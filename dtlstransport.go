// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/fingerprint"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/srtp/v3"
	"github.com/pion/webrtc/v4/internal/detacheddtls"
	"github.com/pion/webrtc/v4/internal/netconn"
	"github.com/pion/webrtc/v4/internal/util"
	"github.com/pion/webrtc/v4/pkg/rtcerr"
)

// DTLSTransport allows an application access to information about the DTLS
// transport over which RTP and RTCP packets are sent and received by
// RTPSender and RTPReceiver, as well other data such as SCTP packets sent
// and received by data channels.
type DTLSTransport struct {
	lock sync.RWMutex

	iceTransport     *ICETransport
	certificates     []Certificate
	remoteParameters DTLSParameters
	// remoteCertificateLock guards remoteCertificate instead of lock: the DTLS
	// handshake stores it while Stop may hold lock and wait for that handshake.
	remoteCertificateLock sync.RWMutex
	remoteCertificate     []byte
	state                 DTLSTransportState
	srtpProtectionProfile srtp.ProtectionProfile
	localCryptexMode      srtp.CryptexMode // outbound (send) Cryptex mode
	remoteCryptexMode     srtp.CryptexMode // inbound (receive) Cryptex mode
	negotiatedVersion     atomic.Uint32    // protocol.Version, 0 until the handshake completes
	sped                  bool             // the handshake runs with SPED (DTLS in STUN)

	onStateChangeHandler   func(DTLSTransportState)
	internalOnCloseHandler func()

	conn     *detacheddtls.Conn
	dtlsConn *dtls.DetachedConn

	srtpSession, srtcpSession   atomic.Value
	srtpEndpoint, srtcpEndpoint *netconn.Conn
	simulcastStreams            []simulcastStreamPair
	srtpReady                   chan struct{}
	srtpStarted                 bool

	// earlySRTP is set for a DTLS server with early SRTP enabled, see
	// SettingEngine.EnableDTLSServerEarlySRTP.
	earlySRTP          atomic.Pointer[earlySRTP]
	onEarlySRTPHandler func()

	dtlsMatcher func([]byte) bool

	api *API
	log logging.LeveledLogger
}

type simulcastStreamPair struct {
	srtp  *srtp.ReadStreamSRTP
	srtcp *srtp.ReadStreamSRTCP
}

type streamsForSSRCResult struct {
	rtpReadStream             *srtp.ReadStreamSRTP
	rtpInterceptor            interceptor.RTPReader
	startRTPReaderImmediately bool
	rtcpReadStream            *srtp.ReadStreamSRTCP
	rtcpInterceptor           interceptor.RTCPReader
}

type srtpRTPReader struct {
	readStream *srtp.ReadStreamSRTP
}

func (r *srtpRTPReader) Read(in []byte, a interceptor.Attributes) (int, interceptor.Attributes, error) {
	n, err := r.readStream.Read(in)

	return n, a, err
}

// NewDTLSTransport creates a new DTLSTransport.
// This constructor is part of the ORTC API. It is not
// meant to be used together with the basic WebRTC API.
func (api *API) NewDTLSTransport(transport *ICETransport, certificates []Certificate) (*DTLSTransport, error) {
	trans := &DTLSTransport{
		iceTransport: transport,
		api:          api,
		state:        DTLSTransportStateNew,
		dtlsMatcher:  matchDTLS,
		srtpReady:    make(chan struct{}),
		log:          api.settingEngine.LoggerFactory.NewLogger("DTLSTransport"),
	}

	if len(certificates) > 0 {
		now := time.Now()
		for _, x509Cert := range certificates {
			if !x509Cert.Expires().IsZero() && now.After(x509Cert.Expires()) {
				return nil, &rtcerr.InvalidAccessError{Err: ErrCertificateExpired}
			}
			trans.certificates = append(trans.certificates, x509Cert)
		}
	} else {
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, &rtcerr.UnknownError{Err: err}
		}
		certificate, err := GenerateCertificate(sk)
		if err != nil {
			return nil, err
		}
		trans.certificates = []Certificate{*certificate}
	}

	return trans, nil
}

// ICETransport returns the currently-configured *ICETransport or nil
// if one has not been configured.
func (t *DTLSTransport) ICETransport() *ICETransport {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.iceTransport
}

// onStateChange requires the caller holds the lock.
func (t *DTLSTransport) onStateChange(state DTLSTransportState) {
	t.state = state
	handler := t.onStateChangeHandler
	if handler != nil {
		handler(state)
	}
}

// OnStateChange sets a handler that is fired when the DTLS
// connection state changes.
func (t *DTLSTransport) OnStateChange(f func(DTLSTransportState)) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.onStateChangeHandler = f
}

// State returns the current dtls transport state.
func (t *DTLSTransport) State() DTLSTransportState {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.state
}

// WriteRTCP sends a user provided RTCP packet to the connected peer. If no peer is connected the
// packet is discarded.
func (t *DTLSTransport) WriteRTCP(pkts []rtcp.Packet) (int, error) {
	raw, err := rtcp.Marshal(pkts)
	if err != nil {
		return 0, err
	}

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return 0, err
	}

	writeStream, err := srtcpSession.OpenWriteStream()
	if err != nil {
		// nolint
		return 0, fmt.Errorf("%w: %v", errPeerConnWriteRTCPOpenWriteStream, err)
	}

	return writeStream.Write(raw)
}

// GetLocalParameters returns the DTLS parameters of the local DTLSTransport upon construction.
func (t *DTLSTransport) GetLocalParameters() (DTLSParameters, error) {
	fingerprints := []DTLSFingerprint{}

	for _, c := range t.certificates {
		prints, err := c.GetFingerprints()
		if err != nil {
			return DTLSParameters{}, err
		}

		fingerprints = append(fingerprints, prints...)
	}

	return DTLSParameters{
		Role:         DTLSRoleAuto, // always returns the default role
		Fingerprints: fingerprints,
	}, nil
}

// NegotiatedVersion returns the DTLS version negotiated with the remote peer:
// protocol.Version1_2 or protocol.Version1_3. It returns false until the
// DTLS handshake has completed.
func (t *DTLSTransport) NegotiatedVersion() (protocol.Version, bool) {
	version := protocol.Version(t.negotiatedVersion.Load()) //nolint:gosec // G115, stored from a protocol.Version

	return version, version != 0
}

// GetRemoteCertificate returns the certificate chain in use by the remote side
// returns an empty list prior to selection of the remote certificate.
func (t *DTLSTransport) GetRemoteCertificate() []byte {
	t.remoteCertificateLock.RLock()
	defer t.remoteCertificateLock.RUnlock()

	return t.remoteCertificate
}

// OnEarlySRTP sets a handler that is fired when a DTLS server starts SRTP
// before the handshake completes, see SettingEngine.EnableDTLSServerEarlySRTP.
func (t *DTLSTransport) OnEarlySRTP(f func()) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.onEarlySRTPHandler = f
}

// EarlySRTPStats reports what the DTLS server did with early SRTP, see
// SettingEngine.EnableDTLSServerEarlySRTP. It does not block.
func (t *DTLSTransport) EarlySRTPStats() EarlySRTPStats {
	if early := t.earlySRTP.Load(); early != nil {
		return early.getStats()
	}

	return EarlySRTPStats{}
}

// serverFinishedSent runs once a DTLS 1.3 server has written its Finished,
// while the DTLS connection processes the datagram that completed the
// ClientHello. Stop holds the lock while it closes that connection, so SRTP
// starts on another goroutine.
func (t *DTLSTransport) serverFinishedSent(early *earlySRTP, sped bool, dtlsConn *dtls.DetachedConn) {
	spedState := t.iceTransport.SPEDState()
	switch {
	case !sped || spedState == ice.SPEDStateOff:
		early.setIneligible(EarlySRTPStateNoSPED)
	case t.iceTransport.directDTLSReceived.Load() != 0:
		// The ClientHello may have come from an on-path attacker, which can
		// derive the keys if it substituted its own key share.
		early.setIneligible(EarlySRTPStateDirectDTLS)
	case spedState != ice.SPEDStateConfirmed:
		early.setIneligible(EarlySRTPStateNoSPED)
	default:
		go t.startEarlySRTP(early, dtlsConn)
	}
}

func (t *DTLSTransport) startEarlySRTP(early *earlySRTP, dtlsConn *dtls.DetachedConn) {
	srtpProtectionProfile, err := srtpProtectionProfileFromDTLSConn(dtlsConn)
	if err != nil {
		// The handshake fails with the same error.
		return
	}

	t.lock.Lock()
	if t.state != DTLSTransportStateConnecting || t.dtlsConn != dtlsConn || !early.start(time.Now()) {
		t.lock.Unlock()

		return
	}
	t.srtpProtectionProfile = srtpProtectionProfile
	t.iceTransport.earlySRTP.Store(early)
	if err = t.startSRTP(); err != nil {
		early.end(EarlySRTPStateFailed, time.Now())
		t.lock.Unlock()
		t.log.Warnf("Failed to start SRTP early: %v", err)

		return
	}
	handler := t.onEarlySRTPHandler
	t.lock.Unlock()

	if handler != nil {
		handler()
	}
}

// endEarlySRTPLocked records that the handshake failed or the transport stopped
// after SRTP started early, and closes the SRTP and SRTCP sessions. It requires
// the caller holds the lock.
func (t *DTLSTransport) endEarlySRTPLocked(state EarlySRTPState) {
	early := t.earlySRTP.Load()
	if early == nil || !early.end(state, time.Now()) {
		return
	}

	// Streams the peer opened are only accepted once the handshake completes, and
	// a session does not close while a new stream waits to be accepted.
	if srtpSession, err := t.getSRTPSession(); err == nil {
		go func() {
			for {
				stream, _, err := srtpSession.AcceptStream()
				if err != nil {
					return
				}
				_ = stream.Close()
			}
		}()
		_ = srtpSession.Close()
	}
	if srtcpSession, err := t.getSRTCPSession(); err == nil {
		go func() {
			for {
				stream, _, err := srtcpSession.AcceptStream()
				if err != nil {
					return
				}
				_ = stream.Close()
			}
		}()
		_ = srtcpSession.Close()
	}
}

// startSRTP requires the caller holds the lock.
func (t *DTLSTransport) startSRTP() error { //nolint:cyclop
	if t.srtpStarted {
		return nil
	}
	srtpConfig := &srtp.Config{
		Profile:       t.srtpProtectionProfile,
		BufferFactory: t.api.settingEngine.BufferFactory,
		LoggerFactory: t.api.settingEngine.LoggerFactory,
	}

	// RFC 9335 Section 4: a=cryptex declares the advertising endpoint's own receive support, so the
	// outbound (local, what we send) and inbound (remote, what we accept receiving) modes may differ
	// when the offer/answer exchange was asymmetric.
	if t.localCryptexMode == srtp.CryptexModeEnabled || t.localCryptexMode == srtp.CryptexModeRequired {
		srtpConfig.LocalOptions = append(srtpConfig.LocalOptions, srtp.Cryptex(t.localCryptexMode))
	}
	if t.remoteCryptexMode == srtp.CryptexModeEnabled || t.remoteCryptexMode == srtp.CryptexModeRequired {
		srtpConfig.RemoteOptions = append(srtpConfig.RemoteOptions, srtp.Cryptex(t.remoteCryptexMode))
	}

	if t.api.settingEngine.replayProtection.SRTP != nil {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPReplayProtection(*t.api.settingEngine.replayProtection.SRTP),
		)
	}

	if t.api.settingEngine.disableSRTPReplayProtection {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPNoReplayProtection(),
		)
	}

	if t.api.settingEngine.replayProtection.SRTCP != nil {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPReplayProtection(*t.api.settingEngine.replayProtection.SRTCP),
		)
	}

	if t.api.settingEngine.disableSRTCPReplayProtection {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPNoReplayProtection(),
		)
	}

	connState, ok := t.dtlsConn.ConnectionState()
	if !ok {
		// nolint
		return fmt.Errorf("%w: Failed to get DTLS ConnectionState", errDtlsKeyExtractionFailed)
	}

	err := srtpConfig.ExtractSessionKeysFromDTLS(&connState, t.role() == DTLSRoleClient)
	if err != nil {
		// nolint
		return fmt.Errorf("%w: %v", errDtlsKeyExtractionFailed, err)
	}

	srtpSession, err := srtp.NewSessionSRTP(t.srtpEndpoint, srtpConfig)
	if err != nil {
		// nolint
		return fmt.Errorf("%w: %v", errFailedToStartSRTP, err)
	}

	srtcpSession, err := srtp.NewSessionSRTCP(t.srtcpEndpoint, srtpConfig)
	if err != nil {
		// nolint
		return fmt.Errorf("%w: %v", errFailedToStartSRTCP, err)
	}

	t.srtpSession.Store(srtpSession)
	t.srtcpSession.Store(srtcpSession)
	t.srtpStarted = true
	close(t.srtpReady)

	return nil
}

func (t *DTLSTransport) getSRTPSession() (*srtp.SessionSRTP, error) {
	if value, ok := t.srtpSession.Load().(*srtp.SessionSRTP); ok {
		return value, nil
	}

	return nil, errDtlsTransportNotStarted
}

func (t *DTLSTransport) getSRTCPSession() (*srtp.SessionSRTCP, error) {
	if value, ok := t.srtcpSession.Load().(*srtp.SessionSRTCP); ok {
		return value, nil
	}

	return nil, errDtlsTransportNotStarted
}

func (t *DTLSTransport) role() DTLSRole {
	// If remote has an explicit role use the inverse
	switch t.remoteParameters.Role {
	case DTLSRoleClient:
		return DTLSRoleServer
	case DTLSRoleServer:
		return DTLSRoleClient
	default:
	}

	// If SettingEngine has an explicit role
	switch t.api.settingEngine.answeringRole(t.sped) {
	case DTLSRoleServer:
		return DTLSRoleServer
	case DTLSRoleClient:
		return DTLSRoleClient
	default:
	}

	// Remote was auto and no explicit role was configured via SettingEngine
	if t.iceTransport.Role() == ICERoleControlling {
		return DTLSRoleServer
	}

	return defaultDtlsRoleAnswer
}

// Start DTLS transport negotiation with the parameters of the remote DTLS transport.
func (t *DTLSTransport) Start(remoteParameters DTLSParameters) error {
	role, certificate, err := t.prepareStart(remoteParameters)
	if err != nil {
		return err
	}

	ctx := context.Background()
	var cancel func()
	if contextMaker := t.api.settingEngine.dtls.connectContextMaker; contextMaker != nil {
		ctx, cancel = contextMaker()
	}
	if cancel != nil {
		defer cancel()
	}

	return t.startPrepared(ctx, role, certificate, nil)
}

// StartContext starts DTLS transport negotiation with the parameters of the remote DTLS
// transport. If the context is canceled before the DTLS handshake is complete, the handshake
// is interrupted and an error is returned.
func (t *DTLSTransport) StartContext(ctx context.Context, remoteParameters DTLSParameters) error {
	role, certificate, err := t.prepareStart(remoteParameters)
	if err != nil {
		return err
	}

	return t.startPrepared(ctx, role, certificate, nil)
}

// startWithSPED starts DTLS with SPED (DTLS in STUN), before the ICE transport:
// it arms SPED on the ICE agent, starts DTLS so that a DTLS client's first
// flight is queued for the first connectivity check, runs startICE, which
// must start the ICE transport with iceRole, and waits for the handshake.
func (t *DTLSTransport) startWithSPED(remoteParameters DTLSParameters, iceRole ICERole, startICE func() error) error {
	if err := t.ensureICEConn(); err != nil {
		return err
	}
	if err := t.iceTransport.enableSPED(iceRole, t.spedICEConnected); err != nil {
		return err
	}
	t.lock.Lock()
	t.sped = true
	t.lock.Unlock()

	role, certificate, err := t.prepareStart(remoteParameters)
	if err != nil {
		return err
	}

	ctx := context.Background()
	var cancel func()
	if contextMaker := t.api.settingEngine.dtls.connectContextMaker; contextMaker != nil {
		ctx, cancel = contextMaker()
	}
	if cancel != nil {
		defer cancel()
	}

	return t.startPrepared(ctx, role, certificate, startICE)
}

// spedICEConnected sets the DTLS retransmission timer from the ICE round-trip
// time when ICE first connects, as libwebrtc's UpdateHandshakeTimeout does.
// Until then SPED keeps DTLS retransmissions off.
func (t *DTLSTransport) spedICEConnected() {
	rtt, ok := t.iceTransport.selectedPairRTT()
	if !ok {
		rtt = spedDefaultRTT
	}
	interval := min(max(2*rtt, spedMinRetransmitInterval), spedMaxRetransmitInterval)

	t.lock.RLock()
	dtlsConn := t.dtlsConn
	isClient := t.role() == DTLSRoleClient
	t.lock.RUnlock()
	if dtlsConn == nil {
		return
	}
	if isClient && t.iceTransport.SPEDState() == ice.SPEDStateOff {
		// The peer does not use SPED, so the pending flight is only sent now.
		interval = interval * 133 / 100
	}
	if err := dtlsConn.SetRetransmitInterval(interval); err != nil {
		t.log.Warnf("Failed to set the DTLS retransmission interval: %v", err)
	}
}

func (t *DTLSTransport) startPrepared( //nolint:cyclop
	ctx context.Context,
	role DTLSRole,
	certificate tls.Certificate,
	startICE func() error,
) error {
	sharedOpts := t.dtlsSharedOptions(certificate)

	dtlsConn, err := t.connectDTLS(role, sharedOpts)
	if err != nil {
		return t.failStart(err)
	}

	var conn *detacheddtls.Conn
	config := detacheddtls.Config{
		DTLSConn:      dtlsConn,
		WriteDatagram: t.iceTransport.write,
		SetDatagramHandler: func(handler func([]byte) error) {
			if handler == nil {
				t.iceTransport.setDTLSHandler(nil, nil)

				return
			}
			t.iceTransport.setDTLSHandler(func(packet []byte) error {
				if t.dtlsMatcher(packet) {
					return handler(packet)
				}

				return nil
			}, func() {
				// The ICE transport is gone, so there is nowhere to flush a close_notify to.
				_ = conn.CloseTransport()
			})
		},
		NetConn: netconn.Config{
			LocalAddr:        t.iceTransport.localAddr,
			RemoteAddr:       t.iceTransport.remoteAddr,
			SetWriteDeadline: t.iceTransport.setWriteDeadline,
		},
		OnClose: t.internalOnCloseHandler,
	}
	spedAgent := t.iceTransport.spedAgent.Load()
	if t.sped {
		config.WriteDatagram = t.iceTransport.writeDTLS
		config.WriteFlight = t.iceTransport.writeDTLSFlight
		config.OnHandshakeDone = spedAgent.SetDTLSHandshakeComplete
		config.OnApplicationData = spedAgent.ApplicationDataReceived
	}
	var early *earlySRTP
	if window := t.api.settingEngine.dtls.earlySRTPWindow; window > 0 && role == DTLSRoleServer {
		early = newEarlySRTP(window)
		sped := t.sped
		config.OnServerFinishedSent = func() { t.serverFinishedSent(early, sped, dtlsConn) }
	}
	conn = detacheddtls.New(config)
	t.lock.Lock()
	if t.state != DTLSTransportStateConnecting {
		state := t.state
		t.lock.Unlock()
		conn.SetOnClose(nil)
		_ = conn.Close()

		return &rtcerr.InvalidStateError{Err: fmt.Errorf("%w: %s", errInvalidDTLSStart, state)}
	}
	t.dtlsConn = dtlsConn
	t.conn = conn
	if early != nil {
		t.earlySRTP.Store(early)
	}
	t.lock.Unlock()

	if err = conn.Start(ctx); err == nil && startICE != nil {
		if err = startICE(); err != nil {
			conn.SetOnClose(nil)
		}
	}
	if err == nil {
		err = conn.Handshake()
	}
	if err != nil {
		t.lock.Lock()
		t.endEarlySRTPLocked(EarlySRTPStateFailed)
		t.lock.Unlock()
		if t.sped {
			spedAgent.SetDTLSFailed()
		}
		// A failed handshake closes the connection like a remote close would.
		_ = conn.Close()
		t.clearConn(conn)

		return t.failStart(err)
	}

	if err = t.completeStart(dtlsConn); err != nil {
		conn.SetOnClose(nil)
		_ = conn.Close()
		t.clearConn(conn)

		return err
	}

	return nil
}

func (t *DTLSTransport) prepareStart(remoteParameters DTLSParameters) (DTLSRole, tls.Certificate, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if err := t.ensureICEConn(); err != nil {
		return DTLSRole(0), tls.Certificate{}, err
	}

	if t.state != DTLSTransportStateNew {
		return DTLSRole(0), tls.Certificate{}, &rtcerr.InvalidStateError{
			Err: fmt.Errorf("%w: %s", errInvalidDTLSStart, t.state),
		}
	}

	t.srtpEndpoint = t.iceTransport.newEndpoint(iceEndpointSRTP)
	t.srtcpEndpoint = t.iceTransport.newEndpoint(iceEndpointSRTCP)
	t.remoteParameters = remoteParameters

	cert := t.certificates[0]
	t.onStateChange(DTLSTransportStateConnecting)

	return t.role(), tls.Certificate{
		Certificate: [][]byte{cert.x509Cert.Raw},
		PrivateKey:  cert.privateKey,
	}, nil
}

func (t *DTLSTransport) dtlsSharedOptions(certificate tls.Certificate) []dtls.Option {
	sharedOpts := []dtls.Option{
		dtls.WithCertificates(certificate),
		dtls.WithSRTPProtectionProfiles(t.srtpProtectionProfiles()...),
		dtls.WithExtendedMasterSecret(t.api.settingEngine.dtls.extendedMasterSecret),
		dtls.WithInsecureSkipVerify(!t.api.settingEngine.dtls.disableInsecureSkipVerify),
		dtls.WithLoggerFactory(t.api.settingEngine.LoggerFactory),
		dtls.WithVerifyPeerCertificate(t.verifyPeerCertificateFunc()),
	}

	if t.api.settingEngine.dtls.customCipherSuites != nil {
		sharedOpts = append(
			sharedOpts,
			dtls.WithCustomCipherSuites(t.api.settingEngine.dtls.customCipherSuites),
		)
	}

	sharedOpts = append(sharedOpts, t.flightOptions()...)

	if t.api.settingEngine.replayProtection.DTLS != nil {
		sharedOpts = append(
			sharedOpts,
			dtls.WithReplayProtectionWindow(int(*t.api.settingEngine.replayProtection.DTLS)), //nolint:gosec // G115
		)
	}

	if t.api.settingEngine.dtls.cipherSuites != nil {
		sharedOpts = append(
			sharedOpts,
			dtls.WithCipherSuites(t.api.settingEngine.dtls.cipherSuites...),
		)
	}

	if len(t.api.settingEngine.dtls.ellipticCurves) > 0 {
		sharedOpts = append(
			sharedOpts,
			dtls.WithEllipticCurves(t.api.settingEngine.dtls.ellipticCurves...),
		)
	}

	if t.api.settingEngine.dtls.rootCAs != nil {
		sharedOpts = append(sharedOpts, dtls.WithRootCAs(t.api.settingEngine.dtls.rootCAs))
	}

	if t.api.settingEngine.dtls.keyLogWriter != nil {
		sharedOpts = append(sharedOpts, dtls.WithKeyLogWriter(t.api.settingEngine.dtls.keyLogWriter))
	}

	if len(t.api.settingEngine.dtls.supportedProtocols) > 0 {
		sharedOpts = append(
			sharedOpts,
			dtls.WithSupportedProtocols(t.api.settingEngine.dtls.supportedProtocols...),
		)
	}

	if t.api.settingEngine.dtls.minVersion != 0 {
		sharedOpts = append(
			sharedOpts,
			dtls.WithMinVersion(t.api.settingEngine.dtls.minVersion),
			dtls.WithMaxVersion(t.api.settingEngine.dtls.maxVersion),
		)
	}

	return sharedOpts
}

// flightOptions returns the options for the MTU and the retransmission of flights.
func (t *DTLSTransport) flightOptions() []dtls.Option {
	if t.sped {
		// Flights ride the connectivity checks, which retransmit them; the timer is
		// set from the ICE round-trip time once ICE connects (spedICEConnected).
		return []dtls.Option{
			dtls.WithFlightInterval(spedDisabledRetransmitInterval),
			dtls.WithMTU(spedDTLSMTU),
		}
	}
	if t.api.settingEngine.dtls.retransmissionInterval > 0 {
		return []dtls.Option{dtls.WithFlightInterval(t.api.settingEngine.dtls.retransmissionInterval)}
	}

	return nil
}

func (t *DTLSTransport) srtpProtectionProfiles() []dtls.SRTPProtectionProfile {
	if len(t.api.settingEngine.srtpProtectionProfiles) > 0 {
		return t.api.settingEngine.srtpProtectionProfiles
	}

	return defaultSrtpProtectionProfiles()
}

func (t *DTLSTransport) verifyPeerCertificateFunc() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errNoRemoteCertificate
		}

		t.remoteCertificateLock.Lock()
		t.remoteCertificate = rawCerts[0]
		t.remoteCertificateLock.Unlock()

		if t.api.settingEngine.disableCertificateFingerprintVerification {
			return nil
		}

		// remoteParameters is set by Start before the handshake begins.
		parsedRemoteCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}

		return t.validateFingerPrint(parsedRemoteCert)
	}
}

func (t *DTLSTransport) connectDTLS(
	role DTLSRole,
	sharedOpts []dtls.Option,
) (*dtls.DetachedConn, error) {
	remoteAddr := t.iceTransport.remoteAddr()
	if remoteAddr == nil {
		// With SPED, DTLS starts before ICE has selected a pair.
		remoteAddr = spedRemoteAddr{}
	}
	if role == DTLSRoleClient {
		clientOpts := t.toDTLSClientOptions(sharedOpts)

		return dtls.DetachedClient(remoteAddr, clientOpts...)
	}

	serverOpts := t.toDTLSServerOptions(sharedOpts)

	return dtls.DetachedServer(remoteAddr, serverOpts...)
}

func (t *DTLSTransport) toDTLSServerOptions(sharedOpts []dtls.Option) []dtls.ServerOption {
	serverOpts := make([]dtls.ServerOption, 0, len(sharedOpts)+5)
	for _, opt := range sharedOpts {
		serverOpts = append(serverOpts, opt)
	}

	clientAuth := dtls.RequireAnyClientCert
	if t.api.settingEngine.dtls.clientAuth != nil {
		clientAuth = *t.api.settingEngine.dtls.clientAuth
	}

	serverOpts = append(serverOpts,
		dtls.WithClientAuth(clientAuth),
		dtls.WithClientCAs(t.api.settingEngine.dtls.clientCAs),
		// With SPED, DTLS only arrives through ICE, whose checks prove the peer's address.
		dtls.WithInsecureSkipVerifyHello(t.api.settingEngine.dtls.insecureSkipHelloVerify || t.sped),
	)

	if t.api.settingEngine.dtls.serverHelloMessageHook != nil {
		serverOpts = append(
			serverOpts,
			dtls.WithServerHelloMessageHook(t.api.settingEngine.dtls.serverHelloMessageHook),
		)
	}

	if t.api.settingEngine.dtls.certificateRequestMessageHook != nil {
		serverOpts = append(
			serverOpts,
			dtls.WithCertificateRequestMessageHook(t.api.settingEngine.dtls.certificateRequestMessageHook),
		)
	}

	return serverOpts
}

func (t *DTLSTransport) toDTLSClientOptions(sharedOpts []dtls.Option) []dtls.ClientOption {
	clientOpts := make([]dtls.ClientOption, 0, len(sharedOpts)+1)
	for _, opt := range sharedOpts {
		clientOpts = append(clientOpts, opt)
	}

	if t.api.settingEngine.dtls.clientHelloMessageHook != nil {
		clientOpts = append(
			clientOpts,
			dtls.WithClientHelloMessageHook(t.api.settingEngine.dtls.clientHelloMessageHook),
		)
	}

	return clientOpts
}

func (t *DTLSTransport) completeStart(dtlsConn *dtls.DetachedConn) error {
	srtpProtectionProfile, err := srtpProtectionProfileFromDTLSConn(dtlsConn)

	t.lock.Lock()
	defer t.lock.Unlock()

	if err != nil {
		t.endEarlySRTPLocked(EarlySRTPStateFailed)
		t.onStateChange(DTLSTransportStateFailed)

		return err
	}

	t.srtpProtectionProfile = srtpProtectionProfile
	if connState, ok := dtlsConn.ConnectionState(); ok {
		t.negotiatedVersion.Store(uint32(connState.NegotiatedVersion()))
	}
	if early := t.earlySRTP.Load(); early != nil {
		if version, _ := t.NegotiatedVersion(); version == protocol.Version1_2 {
			early.setIneligible(EarlySRTPStateDTLS12)
		}
		early.end(EarlySRTPStateVerified, time.Now())
		t.iceTransport.earlySRTP.Store(nil)
	}
	t.onStateChange(DTLSTransportStateConnected)

	return t.startSRTP()
}

func (t *DTLSTransport) clearConn(conn *detacheddtls.Conn) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.conn == conn {
		t.conn = nil
		t.dtlsConn = nil
	}
}

func (t *DTLSTransport) failStart(err error) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.endEarlySRTPLocked(EarlySRTPStateFailed)
	t.onStateChange(DTLSTransportStateFailed)

	return err
}

func srtpProtectionProfileFromDTLSConn(dtlsConn *dtls.DetachedConn) (srtp.ProtectionProfile, error) {
	srtpProfile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok {
		return 0, ErrNoSRTPProtectionProfile
	}

	return srtpProtectionProfileFromDTLS(srtpProfile)
}

func srtpProtectionProfileFromDTLS(srtpProfile dtls.SRTPProtectionProfile) (srtp.ProtectionProfile, error) {
	switch srtpProfile {
	case dtls.SRTP_AEAD_AES_128_GCM:
		return srtp.ProtectionProfileAeadAes128Gcm, nil
	case dtls.SRTP_AEAD_AES_256_GCM:
		return srtp.ProtectionProfileAeadAes256Gcm, nil
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		return srtp.ProtectionProfileAes128CmHmacSha1_80, nil
	case dtls.SRTP_NULL_HMAC_SHA1_80:
		return srtp.ProtectionProfileNullHmacSha1_80, nil
	default:
		return 0, ErrNoSRTPProtectionProfile
	}
}

// Stop stops and closes the DTLSTransport object.
func (t *DTLSTransport) Stop() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Try closing everything and collect the errors
	var closeErrs []error

	t.endEarlySRTPLocked(EarlySRTPStateClosed)
	if srtpSession, err := t.getSRTPSession(); err == nil && srtpSession != nil {
		closeErrs = append(closeErrs, srtpSession.Close())
	}

	if srtcpSession, err := t.getSRTCPSession(); err == nil && srtcpSession != nil {
		closeErrs = append(closeErrs, srtcpSession.Close())
	}

	for i := range t.simulcastStreams {
		closeErrs = append(closeErrs, t.simulcastStreams[i].srtp.Close())
		closeErrs = append(closeErrs, t.simulcastStreams[i].srtcp.Close())
	}

	if t.conn != nil {
		// dtls connection may be closed on sctp close.
		if err := t.conn.Close(); err != nil && !errors.Is(err, dtls.ErrConnClosed) {
			closeErrs = append(closeErrs, err)
		}
	}
	t.onStateChange(DTLSTransportStateClosed)

	return util.FlattenErrs(closeErrs)
}

func (t *DTLSTransport) validateFingerPrint(remoteCert *x509.Certificate) error {
	for _, fp := range t.remoteParameters.Fingerprints {
		hashAlgo, err := fingerprint.HashFromString(fp.Algorithm)
		if err != nil {
			return err
		}

		remoteValue, err := fingerprint.Fingerprint(remoteCert, hashAlgo)
		if err != nil {
			return err
		}

		if strings.EqualFold(remoteValue, fp.Value) {
			return nil
		}
	}

	return errNoMatchingCertificateFingerprint
}

func (t *DTLSTransport) ensureICEConn() error {
	if t.iceTransport == nil {
		return errICEConnectionNotStarted
	}

	return nil
}

func (t *DTLSTransport) storeSimulcastStream(
	srtpReadStream *srtp.ReadStreamSRTP,
	srtcpReadStream *srtp.ReadStreamSRTCP,
) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.simulcastStreams = append(t.simulcastStreams, simulcastStreamPair{srtpReadStream, srtcpReadStream})
}

func (t *DTLSTransport) streamsForSSRC(
	ssrc SSRC,
	streamInfo interceptor.StreamInfo,
) (*streamsForSSRCResult, error) {
	srtpSession, err := t.getSRTPSession()
	if err != nil {
		return nil, err
	}

	rtpReadStream, err := srtpSession.OpenReadStream(uint32(ssrc))
	if err != nil {
		return nil, err
	}

	rtpReader := &srtpRTPReader{readStream: rtpReadStream}
	rtpInterceptor := t.api.interceptor.BindRemoteStream(&streamInfo, rtpReader)

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return nil, err
	}

	rtcpReadStream, err := srtcpSession.OpenReadStream(uint32(ssrc))
	if err != nil {
		return nil, err
	}

	rtcpInterceptor := t.api.interceptor.BindRTCPReader(interceptor.RTCPReaderFunc(
		func(in []byte, a interceptor.Attributes) (n int, attributes interceptor.Attributes, err error) {
			n, err = rtcpReadStream.Read(in)

			return n, a, err
		}),
	)

	return &streamsForSSRCResult{
		rtpReadStream:             rtpReadStream,
		rtpInterceptor:            rtpInterceptor,
		startRTPReaderImmediately: rtpInterceptor != rtpReader && t.api.settingEngine.BufferFactory == nil,
		rtcpReadStream:            rtcpReadStream,
		rtcpInterceptor:           rtcpInterceptor,
	}, nil
}

func (t *DTLSTransport) getLocalCryptexMode() srtp.CryptexMode {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.localCryptexMode
}

func (t *DTLSTransport) setLocalCryptexMode(mode srtp.CryptexMode) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.localCryptexMode = mode
}

func (t *DTLSTransport) getRemoteCryptexMode() srtp.CryptexMode {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.remoteCryptexMode
}

func (t *DTLSTransport) setRemoteCryptexMode(mode srtp.CryptexMode) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.remoteCryptexMode = mode
}

// updateCryptexModes applies localMode/remoteMode to the respective direction of the
// already-started SRTP session, if any, and updates the bookkeeping used by
// getLocalCryptexMode/getRemoteCryptexMode. SRTCP is unaffected by Cryptex mode and is not updated.
func (t *DTLSTransport) updateCryptexModes(localMode, remoteMode srtp.CryptexMode) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	srtpSession, err := t.getSRTPSession()
	sessionStarted := err == nil && srtpSession != nil

	if localMode != t.localCryptexMode {
		if sessionStarted {
			if err := srtpSession.UpdateLocalOptions(srtp.Cryptex(localMode)); err != nil {
				return err
			}
		}
		t.localCryptexMode = localMode
	}

	if remoteMode != t.remoteCryptexMode {
		if sessionStarted {
			if err := srtpSession.UpdateRemoteOptions(srtp.Cryptex(remoteMode)); err != nil {
				return err
			}
		}
		t.remoteCryptexMode = remoteMode
	}

	return nil
}

// rtpHeaderEncryptionNegotiated reports if RFC 9335 RTP Header Extension Encryption ("Cryptex")
// has been negotiated and is enabled for this transceiver.
func (t *DTLSTransport) rtpHeaderEncryptionNegotiated() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.localCryptexMode == srtp.CryptexModeEnabled || t.localCryptexMode == srtp.CryptexModeRequired
}
