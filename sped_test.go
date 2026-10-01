// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/test"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spedPeer configures one PeerConnection of a SPED test.
type spedPeer struct {
	sped   bool
	dtls13 bool
	lite   bool
	// answeringRole and spedAnsweringRole are passed to SetAnsweringDTLSRole and
	// SetAnsweringDTLSRoleWithSPED; answerer only.
	answeringRole, spedAnsweringRole DTLSRole
	skipHelloVerify                  bool
	// curves are passed to SetDTLSEllipticCurves. Without X25519MLKEM768 a
	// DTLS 1.3 ClientHello fits in one datagram.
	curves []elliptic.Curve
	// earlySRTPWindow is passed to EnableDTLSServerEarlySRTP.
	earlySRTPWindow time.Duration
}

var classicalCurves = []elliptic.Curve{elliptic.X25519, elliptic.P256} //nolint:gochecknoglobals

// wirePacket is a UDP datagram the vnet router forwarded or dropped.
type wirePacket struct {
	sent time.Time
	from string // source IP
	raw  []byte
	stun *stun.Message // nil unless raw is a STUN message
}

// embedded returns the DTLS datagram embedded in a STUN message, or nil.
func (p wirePacket) embedded() []byte {
	if p.stun == nil {
		return nil
	}
	data, err := p.stun.Get(stun.AttrDtlsInStun)
	if err != nil {
		return nil
	}

	return data
}

func (p wirePacket) hasSPEDAttributes() bool {
	return p.stun != nil && (p.stun.Contains(stun.AttrDtlsInStun) || p.stun.Contains(stun.AttrDtlsInStunAck))
}

// directDTLS returns the DTLS datagram sent outside STUN, or nil.
func (p wirePacket) directDTLS() []byte {
	if p.stun != nil || !matchDTLS(p.raw) {
		return nil
	}

	return p.raw
}

// dtls returns the DTLS datagram the packet carries, embedded or direct, or nil.
func (p wirePacket) dtls() []byte {
	if data := p.embedded(); data != nil {
		return data
	}

	return p.directDTLS()
}

func (p wirePacket) isBinding(class stun.MessageClass) bool {
	return p.stun != nil && p.stun.Type == stun.NewType(stun.MethodBinding, class)
}

// DTLS handshake message types in a plaintext record.
const (
	dtlsClientHello        = 1
	dtlsServerHello        = 2
	dtlsHelloVerifyRequest = 3
)

// isDTLSHandshake reports whether datagram starts with a plaintext DTLS
// handshake record carrying a message of type msgType.
func isDTLSHandshake(datagram []byte, msgType byte) bool {
	return len(datagram) > 13 && datagram[0] == 22 && datagram[13] == msgType
}

// isHelloRetryRequest reports whether datagram starts with a DTLS 1.3
// HelloRetryRequest: a ServerHello with the RFC 8446 Section 4.1.3 random.
func isHelloRetryRequest(datagram []byte) bool {
	hrrRandom := []byte{
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
	}
	// Record header (13), handshake header (12), legacy_version (2).
	const randomOffset = 13 + 12 + 2

	return isDTLSHandshake(datagram, dtlsServerHello) && len(datagram) >= randomOffset+32 &&
		bytes.Equal(datagram[randomOffset:randomOffset+32], hrrRandom)
}

// spedWire records the datagrams the vnet router forwards, and drops those
// drop selects.
type spedWire struct {
	oneWayDelay time.Duration

	mu      sync.Mutex
	packets []wirePacket
	dropped []wirePacket
	drop    func(wirePacket) bool
}

func (w *spedWire) filter(chunk vnet.Chunk) bool {
	source, _ := chunk.SourceAddr().(*net.UDPAddr)
	packet := wirePacket{
		sent: time.Now().Add(-w.oneWayDelay),
		from: source.IP.String(),
		raw:  bytes.Clone(chunk.UserData()),
	}
	if stun.IsMessage(packet.raw) {
		msg := &stun.Message{Raw: bytes.Clone(packet.raw)}
		if msg.Decode() == nil {
			packet.stun = msg
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.drop != nil && w.drop(packet) {
		w.dropped = append(w.dropped, packet)

		return false
	}
	w.packets = append(w.packets, packet)

	return true
}

func (w *spedWire) setDrop(drop func(wirePacket) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.drop = drop
}

func (w *spedWire) delivered() []wirePacket {
	w.mu.Lock()
	defer w.mu.Unlock()

	return slices.Clone(w.packets)
}

func (w *spedWire) droppedPackets() []wirePacket {
	w.mu.Lock()
	defer w.mu.Unlock()

	return slices.Clone(w.dropped)
}

// spedEnd is one PeerConnection of a spedPair and when it reached each state.
type spedEnd struct {
	pc *PeerConnection
	ip string

	mu                                      sync.Mutex
	iceConnected, dtlsConnected, dtlsFailed time.Time
	// earlySRTP is what EarlySRTPStats returned in the Connected state callback.
	earlySRTP EarlySRTPStats
}

func (e *spedEnd) track() {
	e.pc.OnICEConnectionStateChange(func(state ICEConnectionState) {
		if state == ICEConnectionStateConnected {
			e.mu.Lock()
			if e.iceConnected.IsZero() {
				e.iceConnected = time.Now()
			}
			e.mu.Unlock()
		}
	})
	e.pc.SCTP().Transport().OnStateChange(func(state DTLSTransportState) {
		e.mu.Lock()
		switch state { //nolint:exhaustive
		case DTLSTransportStateConnected:
			e.dtlsConnected = time.Now()
			e.earlySRTP = e.pc.SCTP().Transport().EarlySRTPStats()
		case DTLSTransportStateFailed:
			e.dtlsFailed = time.Now()
		}
		e.mu.Unlock()
	})
}

func (e *spedEnd) times() (iceConnected, dtlsConnected time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.iceConnected, e.dtlsConnected
}

func (e *spedEnd) earlySRTPAtConnected() EarlySRTPStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.earlySRTP
}

func (e *spedEnd) failedAt() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.dtlsFailed
}

func (e *spedEnd) spedState() ice.SPEDState {
	return e.pc.WARPState().SPED
}

// spedPair is an offerer and an answerer on a vnet whose router delays every
// datagram by oneWayDelay.
type spedPair struct {
	offer, answer *spedEnd
	wire          *spedWire
	rtt           time.Duration
}

func newSPEDPair(t *testing.T, oneWayDelay time.Duration, offer, answer spedPeer) *spedPair {
	t.Helper()

	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24",
		MinDelay:      oneWayDelay,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)
	wire := &spedWire{oneWayDelay: oneWayDelay}
	router.AddChunkFilter(wire.filter)

	newEnd := func(ip string, peer spedPeer) *spedEnd {
		vnetNet, netErr := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
		require.NoError(t, netErr)
		require.NoError(t, router.AddNet(vnetNet))

		settings := SettingEngine{}
		settings.SetNet(vnetNet)
		settings.SetICETimeouts(5*time.Second, 10*time.Second, 200*time.Millisecond)
		settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
		settings.SetLite(peer.lite)
		settings.EnableSped(peer.sped)
		settings.SetDTLSInsecureSkipHelloVerify(peer.skipHelloVerify)
		if peer.dtls13 {
			require.NoError(t, settings.SetDTLSVersionRange(protocol.Version1_2, protocol.Version1_3))
		}
		if peer.answeringRole != DTLSRoleUnknown {
			require.NoError(t, settings.SetAnsweringDTLSRole(peer.answeringRole))
		}
		if peer.spedAnsweringRole != DTLSRoleUnknown {
			require.NoError(t, settings.SetAnsweringDTLSRoleWithSPED(peer.spedAnsweringRole))
		}
		if len(peer.curves) > 0 {
			settings.SetDTLSEllipticCurves(peer.curves...)
		}
		settings.EnableDTLSServerEarlySRTP(peer.earlySRTPWindow)
		pc, pcErr := NewAPI(WithSettingEngine(settings)).NewPeerConnection(Configuration{})
		require.NoError(t, pcErr)
		end := &spedEnd{pc: pc, ip: ip}
		end.track()

		return end
	}

	pair := &spedPair{
		offer:  newEnd("1.2.3.4", offer),
		answer: newEnd("1.2.3.5", answer),
		wire:   wire,
		rtt:    2 * oneWayDelay,
	}
	require.NoError(t, router.Start())
	t.Cleanup(func() {
		closePairNow(t, pair.offer.pc, pair.answer.pc)
		assert.NoError(t, router.Stop())
	})

	return pair
}

// signal exchanges the offer and the answer, passing each through its modify
// function, which may be nil.
func (p *spedPair) signal(t *testing.T, modifyOffer, modifyAnswer func(string) string) {
	t.Helper()

	exchange := func(from, to *PeerConnection, create func() (SessionDescription, error), modify func(string) string) {
		desc, err := create()
		require.NoError(t, err)
		gathered := GatheringCompletePromise(from)
		require.NoError(t, from.SetLocalDescription(desc))
		<-gathered
		desc = *from.LocalDescription()
		if modify != nil {
			desc.SDP = modify(desc.SDP)
		}
		require.NoError(t, to.SetRemoteDescription(desc))
	}
	exchange(p.offer.pc, p.answer.pc, func() (SessionDescription, error) { return p.offer.pc.CreateOffer(nil) }, modifyOffer)
	exchange(p.answer.pc, p.offer.pc, func() (SessionDescription, error) { return p.answer.pc.CreateAnswer(nil) }, modifyAnswer)
}

// connectOnly negotiates a data channel and waits until both ends are connected.
func (p *spedPair) connectOnly(t *testing.T, modifyOffer func(string) string) {
	t.Helper()

	_, err := p.offer.pc.CreateDataChannel("sped", nil)
	require.NoError(t, err)
	connected := untilConnectionState(PeerConnectionStateConnected, p.offer.pc, p.answer.pc)
	p.signal(t, modifyOffer, nil)
	<-connected
}

// connect negotiates a data channel and waits until a message crossed it.
func (p *spedPair) connect(t *testing.T, modifyOffer, modifyAnswer func(string) string) {
	t.Helper()

	received := make(chan string, 1)
	p.answer.pc.OnDataChannel(func(dc *DataChannel) {
		dc.OnMessage(func(msg DataChannelMessage) {
			select {
			case received <- string(msg.Data):
			default:
			}
		})
	})
	dc, err := p.offer.pc.CreateDataChannel("sped", nil)
	require.NoError(t, err)
	dc.OnOpen(func() {
		assert.NoError(t, dc.SendText("hello"))
	})

	connected := untilConnectionState(PeerConnectionStateConnected, p.offer.pc, p.answer.pc)
	p.signal(t, modifyOffer, modifyAnswer)
	<-connected

	select {
	case msg := <-received:
		assert.Equal(t, "hello", msg)
	case <-time.After(10 * time.Second):
		require.Fail(t, "data channel message not received")
	}
}

// firstCheck returns the offerer's first Binding request.
func (p *spedPair) firstCheck(t *testing.T) wirePacket {
	t.Helper()

	for _, packet := range append(p.wire.delivered(), p.wire.droppedPackets()...) {
		if packet.from == p.offer.ip && packet.isBinding(stun.ClassRequest) {
			return packet
		}
	}
	require.Fail(t, "no Binding request from the offerer")

	return wirePacket{}
}

// responseTo returns the success response to a Binding request.
func (p *spedPair) responseTo(t *testing.T, request wirePacket) wirePacket {
	t.Helper()

	for _, packet := range p.wire.delivered() {
		if packet.isBinding(stun.ClassSuccessResponse) && packet.stun.TransactionID == request.stun.TransactionID {
			return packet
		}
	}
	require.Fail(t, "the Binding request was not answered")

	return wirePacket{}
}

// requireSPEDAttributesUntilConnected checks that every STUN message sent
// before either end was DTLS connected carries a SPED attribute.
func (p *spedPair) requireSPEDAttributesUntilConnected(t *testing.T) {
	t.Helper()

	_, offerConnected := p.offer.times()
	_, answerConnected := p.answer.times()
	connected := offerConnected
	if answerConnected.Before(connected) {
		connected = answerConnected
	}
	for _, packet := range p.wire.delivered() {
		if packet.stun != nil && packet.sent.Before(connected) {
			require.True(t, packet.hasSPEDAttributes(), "a STUN message from %s without SPED attributes", packet.from)
		}
	}
}

// dtlsClient returns the end that is the DTLS client, and the other one.
func (p *spedPair) dtlsClient() (client, server *spedEnd) {
	transport := p.offer.pc.SCTP().Transport()
	transport.lock.RLock()
	role := transport.role()
	transport.lock.RUnlock()
	if role == DTLSRoleClient {
		return p.offer, p.answer
	}

	return p.answer, p.offer
}

// clientConnectedRTTs returns when the DTLS client connected, in round trips
// after the offerer's first check.
func (p *spedPair) clientConnectedRTTs(t *testing.T) float64 {
	t.Helper()

	client, _ := p.dtlsClient()
	_, connected := client.times()

	return float64(connected.Sub(p.firstCheck(t).sent)) / float64(p.rtt)
}

// withICEOption adds a session-level a=ice-options line to an SDP.
func withICEOption(option string) func(string) string {
	return func(desc string) string {
		return strings.Replace(desc, "t=0 0\r\n", "t=0 0\r\na=ice-options:"+option+"\r\n", 1)
	}
}

func TestSPED_Connects(t *testing.T) {
	for _, tc := range []struct {
		name          string
		offer, answer spedPeer
		version       protocol.Version
	}{
		{name: "DTLS12", offer: spedPeer{sped: true}, answer: spedPeer{sped: true}, version: protocol.Version1_2},
		{
			name:    "DTLS13",
			offer:   spedPeer{sped: true, dtls13: true},
			answer:  spedPeer{sped: true, dtls13: true},
			version: protocol.Version1_3,
		},
		{
			name:    "DTLS12_LitePassiveAnswerer",
			offer:   spedPeer{sped: true},
			answer:  spedPeer{sped: true, lite: true, spedAnsweringRole: DTLSRoleServer},
			version: protocol.Version1_2,
		},
		{
			name:    "DTLS13_LitePassiveAnswerer",
			offer:   spedPeer{sped: true, dtls13: true},
			answer:  spedPeer{sped: true, dtls13: true, lite: true, spedAnsweringRole: DTLSRoleServer},
			version: protocol.Version1_3,
		},
		{
			// The SFU's subscriber PeerConnection: a lite offerer.
			name:    "DTLS13_LiteOfferer",
			offer:   spedPeer{sped: true, dtls13: true, lite: true},
			answer:  spedPeer{sped: true, dtls13: true},
			version: protocol.Version1_3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			pair := newSPEDPair(t, 20*time.Millisecond, tc.offer, tc.answer)
			pair.connect(t, nil, nil)

			for _, end := range []*spedEnd{pair.offer, pair.answer} {
				assert.Equal(t, ice.SPEDStateComplete, end.spedState())
				version, ok := end.pc.SCTP().Transport().NegotiatedVersion()
				assert.True(t, ok)
				assert.Equal(t, tc.version, version)
			}
		})
	}
}

// TestSPED_Media checks SRTP both ways and a data channel with SPED, which also
// completes SPED through the application data it reports.
func TestSPED_Media(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	pair := newSPEDPair(t, 20*time.Millisecond,
		spedPeer{sped: true, dtls13: true},
		spedPeer{sped: true, dtls13: true, lite: true, spedAnsweringRole: DTLSRoleServer},
	)
	exchangeMediaAndData(t, pair.offer.pc, pair.answer.pc)
	assert.Equal(t, ice.SPEDStateComplete, pair.offer.spedState())
	assert.Equal(t, ice.SPEDStateComplete, pair.answer.spedState())
}

func TestSPED_SDP(t *testing.T) {
	iceOptions := func(t *testing.T, desc string) []string {
		t.Helper()

		parsed := &sdp.SessionDescription{}
		require.NoError(t, parsed.UnmarshalString(desc))
		value, ok := parsed.Attribute(sdp.AttrKeyICEOptions)
		if !ok {
			return nil
		}

		return strings.Fields(value)
	}
	newPC := func(t *testing.T, configure func(*SettingEngine)) *PeerConnection {
		t.Helper()

		settings := SettingEngine{}
		configure(&settings)
		pc, err := NewAPI(WithSettingEngine(settings)).NewPeerConnection(Configuration{})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, pc.Close()) })
		_, err = pc.CreateDataChannel("sdp", nil)
		require.NoError(t, err)

		return pc
	}
	offerSDP := func(t *testing.T, sped bool, options *OfferOptions) string {
		t.Helper()

		offer, err := newPC(t, func(s *SettingEngine) { s.EnableSped(sped) }).CreateOffer(options)
		require.NoError(t, err)

		return offer.SDP
	}

	t.Run("Offer", func(t *testing.T) {
		assert.Equal(t, []string{"sped", "googspedv1", "goog-sped-v1"}, iceOptions(t, offerSDP(t, true, nil)))
		assert.Equal(t,
			[]string{"trickle", "sped", "googspedv1", "goog-sped-v1"},
			iceOptions(t, offerSDP(t, true, &OfferOptions{OfferAnswerOptions: OfferAnswerOptions{ICETricklingSupported: true}})),
		)
		assert.Empty(t, iceOptions(t, offerSDP(t, false, nil)))
	})

	t.Run("Answer", func(t *testing.T) {
		mediaLevel := func(option string) func(string) string {
			return func(desc string) string {
				return strings.Replace(desc, "a=mid:0\r\n", "a=mid:0\r\na=ice-options:trickle "+option+"\r\n", 1)
			}
		}
		for _, tc := range []struct {
			name   string
			modify func(string) string
			want   []string
		}{
			{name: "None", modify: func(desc string) string { return desc }},
			{name: "Trickle", modify: withICEOption("trickle")},
			{name: "Sped", modify: withICEOption("sped"), want: []string{"sped"}},
			{name: "GoogSpedV1", modify: withICEOption("googspedv1"), want: []string{"googspedv1"}},
			{name: "GoogSpedV1Dashed", modify: withICEOption("goog-sped-v1"), want: []string{"goog-sped-v1"}},
			{
				name:   "All",
				modify: withICEOption("trickle goog-sped-v1 googspedv1 sped"),
				want:   []string{"sped", "googspedv1", "goog-sped-v1"},
			},
			{name: "MediaLevel", modify: mediaLevel("googspedv1"), want: []string{"googspedv1"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				offer := SessionDescription{Type: SDPTypeOffer, SDP: tc.modify(offerSDP(t, false, nil))}
				for _, sped := range []bool{true, false} {
					answerer := newPC(t, func(s *SettingEngine) { s.EnableSped(sped) })
					require.NoError(t, answerer.SetRemoteDescription(offer))
					answer, err := answerer.CreateAnswer(nil)
					require.NoError(t, err)
					if sped {
						assert.Equal(t, tc.want, iceOptions(t, answer.SDP))
					} else {
						assert.Empty(t, iceOptions(t, answer.SDP))
					}
				}
			})
		}
	})

	t.Run("AnswerDTLSRole", func(t *testing.T) {
		setup := func(t *testing.T, offerOption string, configure func(*SettingEngine)) string {
			t.Helper()

			offer := offerSDP(t, false, nil)
			if offerOption != "" {
				offer = withICEOption(offerOption)(offer)
			}
			answerer := newPC(t, configure)
			require.NoError(t, answerer.SetRemoteDescription(SessionDescription{Type: SDPTypeOffer, SDP: offer}))
			answer, err := answerer.CreateAnswer(nil)
			require.NoError(t, err)

			return dtlsRoleFromSDP(answer.parsed).String()
		}
		passiveWithSPED := func(s *SettingEngine) {
			s.EnableSped(true)
			assert.NoError(t, s.SetAnsweringDTLSRoleWithSPED(DTLSRoleServer))
		}

		// setup:passive (server) only for offers with SPED.
		assert.Equal(t, "server", setup(t, "sped", passiveWithSPED))
		assert.Equal(t, "server", setup(t, "googspedv1", passiveWithSPED))
		assert.Equal(t, "client", setup(t, "", passiveWithSPED))
		assert.Equal(t, "client", setup(t, "trickle", passiveWithSPED))
		// Without SPED enabled, the offer's SPED option changes nothing.
		assert.Equal(t, "client", setup(t, "sped", func(s *SettingEngine) {
			assert.NoError(t, s.SetAnsweringDTLSRoleWithSPED(DTLSRoleServer))
		}))
		// SetAnsweringDTLSRole still applies to offers without SPED.
		assert.Equal(t, "server", setup(t, "", func(s *SettingEngine) {
			passiveWithSPED(s)
			assert.NoError(t, s.SetAnsweringDTLSRole(DTLSRoleServer))
		}))
		assert.Equal(t, "client", setup(t, "sped", func(s *SettingEngine) {
			s.EnableSped(true)
			assert.NoError(t, s.SetAnsweringDTLSRole(DTLSRoleServer))
			assert.NoError(t, s.SetAnsweringDTLSRoleWithSPED(DTLSRoleClient))
		}))

		var settings SettingEngine
		assert.ErrorIs(t, settings.SetAnsweringDTLSRoleWithSPED(DTLSRoleAuto), errSettingEngineSetAnsweringDTLSRole)
	})
}

// TestSPED_FlightsRideChecks checks, with an ICE-lite answerer that is the DTLS
// server (the SFU's publisher PeerConnection), that the ClientHello rides the
// offerer's first check and the server's first flight rides the response to
// the check that completes the ClientHello: the first check, unless the
// post-quantum ClientHello needs two. Every DTLS datagram sent outside STUN is
// dropped until both ends are DTLS connected, so the handshake can only
// complete through STUN. Both ends also send DTLS directly, as libwebrtc does,
// once a pair is usable.
func TestSPED_FlightsRideChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dtls13 bool
		curves []elliptic.Curve
		// serverHelloCheck is the check whose response carries the ServerHello.
		serverHelloCheck int
	}{
		{name: "DTLS12"},
		{name: "DTLS13", dtls13: true, curves: classicalCurves},
		{name: "DTLS13_PostQuantum", dtls13: true, serverHelloCheck: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			pair := newSPEDPair(t, 20*time.Millisecond,
				spedPeer{sped: true, dtls13: tc.dtls13, curves: tc.curves},
				spedPeer{sped: true, dtls13: tc.dtls13, curves: tc.curves, lite: true, spedAnsweringRole: DTLSRoleServer},
			)
			bothDTLSConnected := func() bool {
				_, offerConnected := pair.offer.times()
				_, answerConnected := pair.answer.times()

				return !offerConnected.IsZero() && !answerConnected.IsZero()
			}
			pair.wire.setDrop(func(packet wirePacket) bool {
				return packet.directDTLS() != nil && !bothDTLSConnected()
			})
			pair.connect(t, nil, nil)

			var checks []wirePacket
			for _, packet := range pair.wire.delivered() {
				if packet.from == pair.offer.ip && packet.isBinding(stun.ClassRequest) {
					checks = append(checks, packet)
				}
			}
			require.Greater(t, len(checks), tc.serverHelloCheck)
			assert.True(t, isDTLSHandshake(checks[0].embedded(), dtlsClientHello),
				"the first check does not carry a ClientHello")
			serverHelloCheck := checks[tc.serverHelloCheck]
			assert.True(t, isDTLSHandshake(serverHelloCheck.embedded(), dtlsClientHello),
				"check %d does not carry a ClientHello", tc.serverHelloCheck)
			response := pair.responseTo(t, serverHelloCheck)
			assert.True(t, isDTLSHandshake(response.embedded(), dtlsServerHello),
				"the response to check %d does not carry the ServerHello", tc.serverHelloCheck)

			// SPED was armed before the first check, on both ends: every Binding
			// request and response before either end was DTLS connected
			// carries a SPED attribute (LiveKit's "ICE connected before DTLS
			// installed its callback").
			pair.requireSPEDAttributesUntilConnected(t)

			assert.Equal(t, ice.SPEDStateComplete, pair.offer.spedState())
			assert.Equal(t, ice.SPEDStateComplete, pair.answer.spedState())
			t.Logf("%d DTLS datagrams sent directly before both ends were connected were dropped",
				len(pair.wire.droppedPackets()))
		})
	}
}

// TestSPED_HandshakeRoundTrips measures, over a network with a 200 ms round
// trip, when the DTLS client is connected after the offerer's first check,
// with and without SPED: SPED must save at least about one round trip. Runs
// with SPED leave SetDTLSInsecureSkipHelloVerify off, so a HelloVerifyRequest
// or cookie HelloRetryRequest would cost one more round trip; runs without
// SPED skip it.
func TestSPED_HandshakeRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: runs several handshakes over a delayed virtual network")
	}

	const oneWayDelay = 100 * time.Millisecond

	for _, tc := range []struct {
		name   string
		dtls13 bool
		curves []elliptic.Curve
		lite   bool
		// want is when the DTLS client connects with SPED, in round trips after
		// the offerer's first check.
		want float64
		// minSaving is how much earlier, in round trips, the DTLS client connects
		// with SPED than without; 0 means at least 0.75.
		minSaving float64
	}{
		// The SFU's publisher PeerConnection: a lite answerer that is the DTLS server.
		{name: "DTLS12_LiteServer", lite: true, want: 2},
		{name: "DTLS13_LiteServer", dtls13: true, curves: classicalCurves, lite: true, want: 1},
		// The post-quantum ClientHello takes two datagrams. The first rides the
		// first check, the second goes out directly once the check is answered.
		// The offerer nominates on that first check of a lite peer, so without
		// SPED the ClientHello also leaves after one round trip: SPED saves
		// nothing here.
		{name: "DTLS13_PostQuantum_LiteServer", dtls13: true, lite: true, want: 2, minSaving: -0.25},
		// Default roles: the full answerer is the DTLS client. Its ClientHello
		// rides the response to the offerer's first check.
		{name: "DTLS12_Full", want: 2},
		{name: "DTLS13_Full", dtls13: true, curves: classicalCurves, want: 1},
		{name: "DTLS13_PostQuantum_Full", dtls13: true, want: 1.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(60 * time.Second)
			defer lim.Stop()

			measure := func(sped bool) float64 {
				offer := spedPeer{sped: sped, dtls13: tc.dtls13, curves: tc.curves, skipHelloVerify: !sped}
				answer := offer
				answer.lite = tc.lite
				if tc.lite {
					answer.answeringRole = DTLSRoleServer
					answer.spedAnsweringRole = DTLSRoleServer
				}
				pair := newSPEDPair(t, oneWayDelay, offer, answer)
				pair.connectOnly(t, nil)
				if sped {
					assert.NotEqual(t, ice.SPEDStateOff, pair.offer.spedState())
					assert.NotEqual(t, ice.SPEDStateOff, pair.answer.spedState())
				}

				return pair.clientConnectedRTTs(t)
			}
			without, with := measure(false), measure(true)
			t.Logf("DTLS client connected %.2f RTT after the first check with SPED, %.2f without", with, without)

			assert.Less(t, with, tc.want+0.5, "SPED handshake slower than %.1f RTT", tc.want)
			minSaving := tc.minSaving
			if minSaving == 0 {
				minSaving = 0.75
			}
			assert.GreaterOrEqual(t, without-with, minSaving, "SPED saved less than %.2f RTT", minSaving)
		})
	}
}

// TestSPED_Fallback connects peers where only one side uses SPED, in both
// directions, as offerer and answerer, lite and full: through SDP, where one
// side does not advertise SPED, and in band, where a description advertises
// SPED but that side does not use it.
func TestSPED_Fallback(t *testing.T) {
	sped := spedPeer{sped: true}
	spedLite := spedPeer{sped: true, lite: true}
	for _, tc := range []struct {
		name                      string
		offer, answer             spedPeer
		modifyOffer, modifyAnswer func(string) string
		// wantOffer and wantAnswer are the SPED states each end ends in.
		wantOffer, wantAnswer ice.SPEDState
	}{
		{name: "SPEDOfferer", offer: sped},
		{name: "SPEDOfferer_LiteAnswerer", offer: sped, answer: spedPeer{lite: true}},
		{name: "SPEDAnswerer", answer: sped},
		{name: "SPEDLiteAnswerer", answer: spedLite},
		{name: "SPEDLiteOfferer", offer: spedLite},
		{name: "LiteOfferer_SPEDAnswerer", offer: spedPeer{lite: true}, answer: sped},
		{
			name: "SPEDOfferer_InBand", offer: sped,
			modifyAnswer: withICEOption("sped"), wantOffer: ice.SPEDStateOff,
		},
		{
			name: "SPEDOfferer_LiteAnswerer_InBand", offer: sped, answer: spedPeer{lite: true},
			modifyAnswer: withICEOption("sped"), wantOffer: ice.SPEDStateOff,
		},
		{
			name: "SPEDAnswerer_InBand", answer: sped,
			modifyOffer: withICEOption("sped"), wantAnswer: ice.SPEDStateOff,
		},
		{
			name: "SPEDLiteAnswerer_InBand", answer: spedLite,
			modifyOffer: withICEOption("sped"), wantAnswer: ice.SPEDStateOff,
		},
		{
			name: "SPEDLiteOfferer_InBand", offer: spedLite,
			modifyAnswer: withICEOption("sped"), wantOffer: ice.SPEDStateOff,
		},
	} {
		for _, dtls13 := range []bool{false, true} {
			name := tc.name + "_DTLS12"
			if dtls13 {
				name = tc.name + "_DTLS13"
			}
			t.Run(name, func(t *testing.T) {
				lim := test.TimeOut(30 * time.Second)
				defer lim.Stop()

				offer, answer := tc.offer, tc.answer
				offer.dtls13, answer.dtls13 = dtls13, dtls13
				pair := newSPEDPair(t, 20*time.Millisecond, offer, answer)
				pair.connect(t, tc.modifyOffer, tc.modifyAnswer)

				assert.Equal(t, tc.wantOffer, pair.offer.spedState())
				assert.Equal(t, tc.wantAnswer, pair.answer.spedState())
				// A side that does not use SPED never sends a SPED attribute.
				for _, end := range []*spedEnd{pair.offer, pair.answer} {
					if end.spedState() != ice.SPEDStateDisabled {
						continue
					}
					for _, packet := range pair.wire.delivered() {
						if packet.from == end.ip {
							assert.False(t, packet.hasSPEDAttributes(), "SPED attribute from %s", end.ip)
						}
					}
				}
			})
		}
	}
}

// TestSPED_FallbackNotSlower checks that a peer without SPED connects as fast
// to a peer with SPED as to one without (LiveKit fixed a 95 ms penalty), also
// when an ICE option advertises SPED to the peer with SPED and the fallback is
// in band.
func TestSPED_FallbackNotSlower(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: runs several handshakes over a delayed virtual network")
	}

	const oneWayDelay = 100 * time.Millisecond

	measure := func(t *testing.T, answer spedPeer, modifyOffer func(string) string) float64 {
		t.Helper()

		offer := spedPeer{dtls13: true, skipHelloVerify: true}
		answer.dtls13, answer.lite, answer.skipHelloVerify = true, true, true
		pair := newSPEDPair(t, oneWayDelay, offer, answer)
		pair.connectOnly(t, modifyOffer)

		return pair.clientConnectedRTTs(t)
	}

	for _, tc := range []struct {
		name        string
		answer      spedPeer
		modifyOffer func(string) string
	}{
		{name: "OfferWithoutSPED", answer: spedPeer{sped: true, spedAnsweringRole: DTLSRoleServer}},
		{name: "InBand", answer: spedPeer{sped: true}, modifyOffer: withICEOption("sped")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(60 * time.Second)
			defer lim.Stop()

			baseline := measure(t, spedPeer{}, tc.modifyOffer)
			got := measure(t, tc.answer, tc.modifyOffer)
			t.Logf("DTLS client connected %.2f RTT after the first check, %.2f against a peer without SPED", got, baseline)
			assert.Less(t, got, baseline+0.25)
		})
	}
}

// TestSPED_LostClientHello drops the first check that carries a ClientHello.
// The next check carries the same datagrams again, so the handshake recovers
// without a DTLS retransmission, which SPED keeps off until ICE connects.
func TestSPED_LostClientHello(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dtls13 bool
		curves []elliptic.Curve
		// datagrams is the number of datagrams of the ClientHello.
		datagrams int
	}{
		{name: "DTLS12", datagrams: 1},
		{name: "DTLS13", dtls13: true, curves: classicalCurves, datagrams: 1},
		{name: "DTLS13_PostQuantum", dtls13: true, datagrams: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			pair := newSPEDPair(t, 20*time.Millisecond,
				spedPeer{sped: true, dtls13: tc.dtls13, curves: tc.curves},
				spedPeer{sped: true, dtls13: tc.dtls13, curves: tc.curves, lite: true, spedAnsweringRole: DTLSRoleServer},
			)
			var once sync.Once
			pair.wire.setDrop(func(packet wirePacket) bool {
				dropped := false
				if isDTLSHandshake(packet.embedded(), dtlsClientHello) {
					once.Do(func() { dropped = true })
				}

				return dropped
			})
			pair.connect(t, nil, nil)

			// DTLS produced the ClientHello once: a retransmission would carry
			// new record sequence numbers.
			var clientHellos [][]byte
			for _, packet := range append(pair.wire.delivered(), pair.wire.droppedPackets()...) {
				if datagram := packet.dtls(); isDTLSHandshake(datagram, dtlsClientHello) &&
					!slices.ContainsFunc(clientHellos, func(seen []byte) bool { return bytes.Equal(seen, datagram) }) {
					clientHellos = append(clientHellos, datagram)
				}
			}
			assert.Len(t, clientHellos, tc.datagrams)
			require.Len(t, pair.wire.droppedPackets(), 1)

			client, _ := pair.dtlsClient()
			_, connected := client.times()
			recovery := connected.Sub(pair.wire.droppedPackets()[0].sent)
			t.Logf("DTLS client connected %v after the lost check", recovery)
			// The next scheduled check follows within the 200 ms check interval.
			assert.Less(t, recovery, 500*time.Millisecond)
			assert.Equal(t, ice.SPEDStateComplete, pair.offer.spedState())
			assert.Equal(t, ice.SPEDStateComplete, pair.answer.spedState())
		})
	}
}

// TestSPED_LostFinalFlight drops the first copy, in STUN and direct, of every
// datagram of the DTLS 1.3 client's final flight. The client is connected once
// it sent the flight; SPED keeps it pending until the server acknowledges it,
// so it reaches the server with a later check instead of being stranded
// (LiveKit's premature completion, a 5-15 s stall).
func TestSPED_LostFinalFlight(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	pair := newSPEDPair(t, 20*time.Millisecond,
		spedPeer{sped: true, dtls13: true, curves: classicalCurves},
		spedPeer{sped: true, dtls13: true, curves: classicalCurves, lite: true, spedAnsweringRole: DTLSRoleServer},
	)
	var mu sync.Mutex
	seen := map[bool][][]byte{} // by whether the datagram was embedded
	pair.wire.setDrop(func(packet wirePacket) bool {
		datagram := packet.dtls()
		// The client's final flight is its only data in the handshake epoch (2),
		// which DTLS 1.3 sends with a unified header.
		if packet.from != pair.offer.ip || len(datagram) == 0 || datagram[0]&0xe3 != 0x22 {
			return false
		}
		embedded := packet.stun != nil
		mu.Lock()
		defer mu.Unlock()
		if slices.ContainsFunc(seen[embedded], func(s []byte) bool { return bytes.Equal(s, datagram) }) {
			return false
		}
		seen[embedded] = append(seen[embedded], datagram)

		return true
	})
	pair.connect(t, nil, nil)

	require.NotEmpty(t, pair.wire.droppedPackets())
	_, clientConnected := pair.offer.times()
	_, serverConnected := pair.answer.times()
	t.Logf("DTLS server connected %v after the client", serverConnected.Sub(clientConnected))
	assert.Less(t, serverConnected.Sub(clientConnected), time.Second)
	assert.Equal(t, ice.SPEDStateComplete, pair.offer.spedState())
	assert.Equal(t, ice.SPEDStateComplete, pair.answer.spedState())
}

// TestSPED_DTLSSettings checks the DTLS settings SPED changes, and that they
// do not change without SPED: the 900-byte MTU, and skipping the
// HelloVerifyRequest and the DTLS 1.3 cookie HelloRetryRequest.
func TestSPED_DTLSSettings(t *testing.T) {
	handshake := func(t *testing.T, sped, dtls13 bool) []wirePacket {
		t.Helper()

		pair := newSPEDPair(t, 5*time.Millisecond,
			spedPeer{sped: sped, dtls13: dtls13},
			spedPeer{sped: sped, dtls13: dtls13, lite: true, answeringRole: DTLSRoleServer, spedAnsweringRole: DTLSRoleServer},
		)
		pair.connect(t, nil, nil)
		if sped {
			assert.Equal(t, ice.SPEDStateComplete, pair.offer.spedState())
		}
		client, server := pair.dtlsClient()
		assert.Equal(t, pair.offer, client)
		assert.Equal(t, pair.answer, server)

		return pair.wire.delivered()
	}

	t.Run("MTU", func(t *testing.T) {
		largest := func(packets []wirePacket) (size int) {
			for _, packet := range packets {
				size = max(size, len(packet.dtls()))
			}

			return size
		}
		assert.LessOrEqual(t, largest(handshake(t, true, true)), ice.SPEDDTLSMTU)
		// Without SPED the post-quantum ClientHello fills the default 1200-byte MTU.
		assert.Greater(t, largest(handshake(t, false, true)), ice.SPEDDTLSMTU)
	})

	t.Run("HelloVerify", func(t *testing.T) {
		for _, dtls13 := range []bool{false, true} {
			cookieExchange := func(packets []wirePacket) bool {
				return slices.ContainsFunc(packets, func(packet wirePacket) bool {
					datagram := packet.dtls()

					return isDTLSHandshake(datagram, dtlsHelloVerifyRequest) || isHelloRetryRequest(datagram)
				})
			}
			assert.False(t, cookieExchange(handshake(t, true, dtls13)), "cookie exchange with SPED, DTLS 1.3: %v", dtls13)
			assert.True(t, cookieExchange(handshake(t, false, dtls13)), "no cookie exchange without SPED, DTLS 1.3: %v", dtls13)
		}
	})
}

// TestSPED_RetransmitAfterFallback checks the DTLS timer after an in-band
// fallback: SPED keeps it off while the ClientHello waits for ICE, and sets it
// to about 1.33 times twice the ICE round-trip time when ICE connects, as
// libwebrtc does for a DTLS client whose peer turned SPED down. The copy of the
// ClientHello sent when ICE connects is dropped.
func TestSPED_RetransmitAfterFallback(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	const oneWayDelay = 100 * time.Millisecond
	pair := newSPEDPair(t, oneWayDelay,
		spedPeer{sped: true},
		spedPeer{lite: true, answeringRole: DTLSRoleServer},
	)
	var once sync.Once
	pair.wire.setDrop(func(packet wirePacket) bool {
		dropped := false
		if isDTLSHandshake(packet.directDTLS(), dtlsClientHello) {
			once.Do(func() { dropped = true })
		}

		return dropped
	})
	pair.connect(t, nil, withICEOption("sped"))
	require.Equal(t, ice.SPEDStateOff, pair.offer.spedState())

	var retransmitted time.Time
	for _, packet := range pair.wire.delivered() {
		if isDTLSHandshake(packet.directDTLS(), dtlsClientHello) {
			retransmitted = packet.sent

			break
		}
	}
	require.Len(t, pair.wire.droppedPackets(), 1)
	require.False(t, retransmitted.IsZero())
	iceConnected, _ := pair.offer.times()
	interval := retransmitted.Sub(pair.wire.droppedPackets()[0].sent)
	t.Logf("ClientHello retransmitted %v after the copy sent when ICE connected (%v after ICE connected)",
		interval, retransmitted.Sub(iceConnected))

	// 2 * 200 ms * 1.33 = 532 ms, where the DTLS default is 1 s.
	want := 2 * pair.rtt * 133 / 100
	assert.InDelta(t, float64(want), float64(interval), float64(150*time.Millisecond))
}
