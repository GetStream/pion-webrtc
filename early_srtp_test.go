// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/rtp"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const earlySRTPOneWayDelay = 50 * time.Millisecond

// earlySRTPServer is an ICE-lite DTLS 1.3 offerer with early SRTP, which is the
// DTLS server, like an SFU's subscriber PeerConnection.
func earlySRTPServer(window time.Duration) spedPeer {
	return spedPeer{sped: true, dtls13: true, lite: true, curves: classicalCurves, earlySRTPWindow: window}
}

// earlySRTPClient answers as the DTLS client, which a controlling answerer is
// not by default.
func earlySRTPClient() spedPeer {
	return spedPeer{
		sped: true, dtls13: true, curves: classicalCurves,
		answeringRole: DTLSRoleClient, spedAnsweringRole: DTLSRoleClient,
	}
}

// earlySRTPRun is a spedPair whose offerer sends audio to the answerer, every
// interval from before the offer.
type earlySRTPRun struct {
	*spedPair
	firstRTP chan time.Time
}

func newEarlySRTPRun(t *testing.T, server, client spedPeer, payloadSize int, interval time.Duration) *earlySRTPRun {
	t.Helper()

	pair := newSPEDPair(t, earlySRTPOneWayDelay, server, client)
	track, err := NewTrackLocalStaticRTP(RTPCodecCapability{MimeType: MimeTypeOpus}, "audio", "pion")
	require.NoError(t, err)
	_, err = pair.offer.pc.AddTrack(track)
	require.NoError(t, err)

	run := &earlySRTPRun{spedPair: pair, firstRTP: make(chan time.Time, 1)}
	pair.answer.pc.OnTrack(func(remote *TrackRemote, _ *RTPReceiver) {
		if _, _, readErr := remote.ReadRTP(); readErr != nil {
			return
		}
		run.firstRTP <- time.Now()
		for {
			if _, _, readErr := remote.ReadRTP(); readErr != nil {
				return
			}
		}
	})

	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		packet := &rtp.Packet{Header: rtp.Header{Version: 2}, Payload: make([]byte, payloadSize)}
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			packet.SequenceNumber++
			packet.Timestamp += 960
			_ = track.WriteRTP(packet)
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	return run
}

func (r *earlySRTPRun) connect(t *testing.T) {
	t.Helper()

	connected := untilConnectionState(PeerConnectionStateConnected, r.offer.pc, r.answer.pc)
	r.signal(t, nil, nil)
	<-connected
}

func (r *earlySRTPRun) waitFirstRTP(t *testing.T) time.Time {
	t.Helper()

	select {
	case at := <-r.firstRTP:
		return at
	case <-time.After(10 * time.Second):
		require.Fail(t, "no RTP received")

		return time.Time{}
	}
}

// holdClientFinalFlight drops the client's final flight for hold after its first copy.
func (r *earlySRTPRun) holdClientFinalFlight(hold time.Duration) {
	var mu sync.Mutex
	var firstDrop time.Time
	r.wire.setDrop(func(packet wirePacket) bool {
		datagram := packet.dtls()
		// The client's final flight is its only data in the handshake epoch (2),
		// which DTLS 1.3 sends with a unified header.
		if packet.from != r.answer.ip || len(datagram) == 0 || datagram[0]&0xe3 != 0x22 {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if firstDrop.IsZero() {
			firstDrop = packet.sent
		}

		return packet.sent.Sub(firstDrop) < hold
	})
}

// serverMedia returns the SRTP and SRTCP packets the offerer sent.
func (r *earlySRTPRun) serverMedia() []wirePacket {
	var media []wirePacket
	for _, packet := range r.wire.delivered() {
		if packet.from == r.offer.ip && packet.stun == nil && matchRange(128, 191, packet.raw) {
			media = append(media, packet)
		}
	}

	return media
}

// requireNoMediaBefore checks that the offerer sent no SRTP or SRTCP before at.
func (r *earlySRTPRun) requireNoMediaBefore(t *testing.T, at time.Time) {
	t.Helper()

	for _, packet := range r.serverMedia() {
		require.False(t, packet.sent.Before(at), "media sent %v before", at.Sub(packet.sent))
	}
}

var fingerprintValue = regexp.MustCompile(`a=fingerprint:sha-256 ([0-9A-F:]+)`) //nolint:gochecknoglobals

// withWrongFingerprint replaces the certificate fingerprint of a description.
func withWrongFingerprint(desc string) string {
	match := fingerprintValue.FindStringSubmatch(desc)
	if match == nil {
		return desc
	}
	wrong := "00" + match[1][2:]
	if wrong == match[1] {
		wrong = "11" + match[1][2:]
	}

	return strings.ReplaceAll(desc, match[1], wrong)
}

// TestEarlySRTP_StartsAtServerFinished checks that a DTLS server with early SRTP
// starts it at its Finished. The client nominates only once a check has
// succeeded, so the ICE-lite server has no pair to send on until the
// nomination arrives, together with the client's Finished: against a client
// that does not nominate in its first check, early SRTP saves nothing.
func TestEarlySRTP_StartsAtServerFinished(t *testing.T) {
	for _, tc := range []struct {
		name   string
		curves []elliptic.Curve
		window time.Duration
		// mayBeDirect is set when the ClientHello takes two datagrams: the client
		// may send them directly before the second check carries the second one.
		mayBeDirect bool
	}{
		{name: "Classical", curves: classicalCurves, window: 2 * time.Second},
		{name: "PostQuantum", window: 2 * time.Second, mayBeDirect: true},
		{name: "Off", curves: classicalCurves},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			server, client := earlySRTPServer(tc.window), earlySRTPClient()
			server.curves, client.curves = tc.curves, tc.curves
			run := newEarlySRTPRun(t, server, client, 20, 5*time.Millisecond)
			run.connect(t)
			firstRTP := run.waitFirstRTP(t)

			_, serverConnected := run.offer.times()
			_, clientConnected := run.answer.times()
			stats := run.offer.pc.WARPState().EarlySRTP
			t.Logf("first RTP %v after the client connected, %v before the server; %+v",
				firstRTP.Sub(clientConnected), serverConnected.Sub(firstRTP), stats)
			if tc.window == 0 {
				assert.Equal(t, EarlySRTPStats{}, stats)
				run.requireNoMediaBefore(t, serverConnected)
				assert.GreaterOrEqual(t, firstRTP.Sub(clientConnected), run.rtt*3/4)

				return
			}
			if tc.mayBeDirect && stats.State == EarlySRTPStateDirectDTLS {
				run.requireNoMediaBefore(t, serverConnected)

				return
			}

			assert.Equal(t, EarlySRTPStateVerified, stats.State)
			assert.Equal(t, EarlySRTPStateVerified, run.offer.earlySRTPAtConnected().State)
			assert.Zero(t, stats.PacketsAfterWindow)
			// SRTP started with the server's Finished, a round trip before the
			// client's Finished reached the server.
			assert.GreaterOrEqual(t, serverConnected.Sub(stats.StartedAt), run.rtt*3/4)
			assert.False(t, stats.EndedAt.Before(stats.StartedAt))
			// No media left before the nomination, which arrives with the client's Finished.
			media := run.serverMedia()
			require.NotEmpty(t, media)
			assert.False(t, media[0].sent.Before(serverConnected.Add(-run.rtt/4)))
			assert.GreaterOrEqual(t, firstRTP.Sub(clientConnected), run.rtt*3/4)
		})
	}
}

// TestEarlySRTP_Ineligible checks that SRTP starts when the handshake completes
// unless the server negotiated DTLS 1.3 and SPED and every DTLS datagram before
// its Finished arrived in STUN.
func TestEarlySRTP_Ineligible(t *testing.T) {
	dtls12 := func(peer spedPeer) spedPeer {
		peer.dtls13 = false

		return peer
	}
	noSPED := earlySRTPClient()
	noSPED.sped = false
	dtlsServer := earlySRTPClient()
	dtlsServer.spedAnsweringRole = DTLSRoleServer

	for _, tc := range []struct {
		name           string
		server, client spedPeer
		// directClientHello delivers the ClientHello as if it had arrived
		// outside STUN, and drops the check that carried it.
		directClientHello bool
		want              EarlySRTPState
	}{
		{
			name: "DTLS12", server: dtls12(earlySRTPServer(2 * time.Second)), client: dtls12(earlySRTPClient()),
			want: EarlySRTPStateDTLS12,
		},
		{
			name: "ClientDTLS12", server: earlySRTPServer(2 * time.Second), client: dtls12(earlySRTPClient()),
			want: EarlySRTPStateDTLS12,
		},
		{name: "NoSPED", server: earlySRTPServer(2 * time.Second), client: noSPED, want: EarlySRTPStateNoSPED},
		{
			name: "DirectClientHello", server: earlySRTPServer(2 * time.Second), client: earlySRTPClient(),
			directClientHello: true, want: EarlySRTPStateDirectDTLS,
		},
		{name: "DTLSClient", server: earlySRTPServer(2 * time.Second), client: dtlsServer, want: EarlySRTPStateNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			run := newEarlySRTPRun(t, tc.server, tc.client, 20, 5*time.Millisecond)
			if tc.directClientHello {
				serverICE := run.offer.pc.iceTransport
				var once sync.Once
				run.wire.setDrop(func(packet wirePacket) bool {
					datagram := packet.embedded()
					if packet.from != run.answer.ip || !isDTLSHandshake(datagram, dtlsClientHello) {
						return false
					}
					dropped := false
					once.Do(func() {
						dropped = true
						go serverICE.dispatchPacket(bytes.Clone(datagram))
					})

					return dropped
				})
			}
			run.connect(t)
			run.waitFirstRTP(t)

			stats := run.offer.pc.WARPState().EarlySRTP
			assert.Equal(t, tc.want, stats.State)
			assert.Equal(t, tc.want, run.offer.earlySRTPAtConnected().State)
			assert.Zero(t, stats.PacketsSent)
			assert.True(t, stats.StartedAt.IsZero())
			_, serverConnected := run.offer.times()
			run.requireNoMediaBefore(t, serverConnected)
			if tc.directClientHello {
				require.Len(t, run.wire.droppedPackets(), 1)
			}
		})
	}
}

// TestEarlySRTP_Window holds back the client's final flight for longer than
// the window, and checks that the window expires and media flows when the
// handshake completes. The final flight rides in the nominating check, so the
// server has no pair to send early media on.
func TestEarlySRTP_Window(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	const (
		window = 150 * time.Millisecond
		hold   = 600 * time.Millisecond
	)
	run := newEarlySRTPRun(t, earlySRTPServer(window), earlySRTPClient(), 20, 10*time.Millisecond)
	run.holdClientFinalFlight(hold)
	run.connect(t)
	run.waitFirstRTP(t)

	stats := run.offer.pc.WARPState().EarlySRTP
	t.Logf("%+v", stats)
	assert.Equal(t, EarlySRTPStateVerified, stats.State)
	assert.Zero(t, stats.PacketsSent)
	assert.Positive(t, stats.PacketsAfterWindow)

	_, serverConnected := run.offer.times()
	require.GreaterOrEqual(t, serverConnected.Sub(stats.StartedAt), hold)
	run.requireNoMediaBefore(t, serverConnected.Add(-2*time.Millisecond))
}

// TestEarlySRTP_FailedHandshake checks that a server that started SRTP early
// stops sending media and closes its SRTP sessions when the client's
// certificate does not match its fingerprint.
func TestEarlySRTP_FailedHandshake(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	run := newEarlySRTPRun(t, earlySRTPServer(2*time.Second), earlySRTPClient(), 20, 5*time.Millisecond)
	transport := run.offer.pc.SCTP().Transport()
	run.signal(t, nil, func(desc string) string {
		wrong := withWrongFingerprint(desc)
		require.NotEqual(t, desc, wrong)

		return wrong
	})
	require.Eventually(t, func() bool { return !run.offer.failedAt().IsZero() }, 10*time.Second, 5*time.Millisecond)

	stats := transport.EarlySRTPStats()
	t.Logf("%+v", stats)
	require.Equal(t, EarlySRTPStateFailed, stats.State)
	// The client's final flight rides in the nominating check, so nothing left before it failed.
	assert.Zero(t, stats.PacketsSent)
	assert.False(t, stats.EndedAt.After(run.offer.failedAt()), "SRTP closed after the transport failed")

	// The track keeps writing.
	time.Sleep(300 * time.Millisecond)
	for _, packet := range run.serverMedia() {
		assert.Less(t, packet.sent.Sub(stats.EndedAt), 5*time.Millisecond)
	}
	assert.Equal(t, stats.PacketsSent, transport.EarlySRTPStats().PacketsSent)

	srtpSession, err := transport.getSRTPSession()
	require.NoError(t, err)
	_, _, err = srtpSession.AcceptStream()
	assert.Error(t, err)
	srtcpSession, err := transport.getSRTCPSession()
	require.NoError(t, err)
	_, _, err = srtcpSession.AcceptStream()
	assert.Error(t, err)
}

func TestEarlySRTP_Gate(t *testing.T) {
	allowed := func(e *earlySRTP, n int, received uint64) bool {
		ok, _ := e.allow(n, received)

		return ok
	}
	early := newEarlySRTP(time.Hour)
	assert.False(t, allowed(early, 10, 100), "before start")
	require.True(t, early.start(time.Now()))
	assert.False(t, early.start(time.Now()))
	assert.True(t, allowed(early, 300, 100))
	assert.False(t, allowed(early, 1, 100))
	ok, charged := early.allow(1, 101)
	assert.True(t, ok)
	assert.True(t, charged)
	// A packet that could not be sent gives its budget back.
	early.refund(1)
	assert.True(t, allowed(early, 1, 101))
	require.True(t, early.end(EarlySRTPStateVerified, time.Now()))
	ok, charged = early.allow(1000, 0)
	assert.True(t, ok)
	assert.False(t, charged, "verified packets are not counted")
	stats := early.getStats()
	assert.Equal(t, uint64(2), stats.PacketsSent)
	assert.Equal(t, uint64(301), stats.BytesSent)
	assert.Equal(t, uint64(1), stats.PacketsOverBudget)

	expired := newEarlySRTP(time.Nanosecond)
	require.True(t, expired.start(time.Now().Add(-time.Second)))
	assert.False(t, allowed(expired, 1, 100))
	assert.Equal(t, uint64(1), expired.getStats().PacketsAfterWindow)

	failed := newEarlySRTP(time.Hour)
	require.True(t, failed.start(time.Now()))
	require.True(t, failed.end(EarlySRTPStateFailed, time.Now()))
	assert.False(t, allowed(failed, 1, 100))
	assert.False(t, failed.end(EarlySRTPStateVerified, time.Now()))

	ineligible := newEarlySRTP(time.Hour)
	ineligible.setIneligible(EarlySRTPStateDirectDTLS)
	assert.False(t, ineligible.start(time.Now()))
	ineligible.setIneligible(EarlySRTPStateDTLS12)
	assert.Equal(t, EarlySRTPStateDirectDTLS, ineligible.getStats().State)
}
