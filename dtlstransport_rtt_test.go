// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dtls13ClientWaitsForFinalACK is true while pion/dtls marks a DTLS 1.3 client connected only
// once the server has ACKed the client's final flight, one round trip after the client could
// start sending application data (RFC 9147 Section 5.8). Set it to false once pion/dtls
// completes the client handshake when the final flight is sent.
const dtls13ClientWaitsForFinalACK = true

// dtlsHandshakeTime records when a DTLS transport started its handshake and when it connected.
type dtlsHandshakeTime struct {
	mu                    sync.Mutex
	connecting, connected time.Time
}

func (h *dtlsHandshakeTime) track(dtlsTransport *DTLSTransport) {
	dtlsTransport.OnStateChange(func(state DTLSTransportState) {
		h.mu.Lock()
		defer h.mu.Unlock()
		switch state { //nolint:exhaustive
		case DTLSTransportStateConnecting:
			h.connecting = time.Now()
		case DTLSTransportStateConnected:
			h.connected = time.Now()
		}
	})
}

func (h *dtlsHandshakeTime) duration() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.connected.Sub(h.connecting)
}

// measureDTLSHandshake connects two PeerConnections over a virtual network whose router
// delays every packet by oneWayDelay and returns how long the DTLS client took from
// starting its handshake to being connected.
func measureDTLSHandshake(
	t *testing.T,
	oneWayDelay time.Duration,
	skipHelloVerify bool,
	offer, answer dtlsVersionPeerConfig,
) time.Duration {
	t.Helper()

	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24",
		MinDelay:      oneWayDelay,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)

	newPC := func(ip string, cfg dtlsVersionPeerConfig) *PeerConnection {
		vnetNet, netErr := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
		require.NoError(t, netErr)
		require.NoError(t, wan.AddNet(vnetNet))

		settings := SettingEngine{}
		settings.SetNet(vnetNet)
		settings.SetICETimeouts(5*time.Second, 10*time.Second, 200*time.Millisecond)
		settings.SetDTLSInsecureSkipHelloVerify(skipHelloVerify)
		pc, pcErr := newDTLSVersionAPI(t, cfg, settings).NewPeerConnection(Configuration{})
		require.NoError(t, pcErr)

		return pc
	}
	offerPC := newPC("1.2.3.4", offer)
	answerPC := newPC("1.2.3.5", answer)
	require.NoError(t, wan.Start())
	defer func() { assert.NoError(t, wan.Stop()) }()
	defer closePairNow(t, offerPC, answerPC)

	var offerTime, answerTime dtlsHandshakeTime
	offerTime.track(offerPC.SCTP().Transport())
	answerTime.track(answerPC.SCTP().Transport())

	connected := untilConnectionState(PeerConnectionStateConnected, offerPC, answerPC)
	require.NoError(t, signalPair(offerPC, answerPC))
	<-connected

	clientTime := &answerTime
	if answer.answeringRole == DTLSRoleServer {
		clientTime = &offerTime
	}

	return clientTime.duration()
}

// TestDTLSTransport_HandshakeRoundTrips asserts, over a network with a fixed delay, how many round
// trips the DTLS client needs: one fewer with DTLS 1.3 than with DTLS 1.2 (once
// dtls13ClientWaitsForFinalACK is false), that a DTLS 1.3 peer
// talking to a DTLS 1.2-only peer costs no extra round trip, and that the cookie exchange of both
// versions follows SetDTLSInsecureSkipHelloVerify.
func TestDTLSTransport_HandshakeRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: runs several handshakes over a delayed virtual network")
	}

	const (
		oneWayDelay = 100 * time.Millisecond
		rtt         = 2 * oneWayDelay
	)

	// A DTLS 1.3 client is done after one round trip, a DTLS 1.2 client after two.
	dtls13ClientRTTs := 1
	if dtls13ClientWaitsForFinalACK {
		dtls13ClientRTTs++
	}

	for _, tc := range []struct {
		name            string
		offer, answer   dtlsVersionPeerConfig
		skipHelloVerify bool
		wantRTTs        int
	}{
		{name: "DTLS12", skipHelloVerify: true, wantRTTs: 2},
		{
			name:            "DTLS13",
			offer:           dtlsVersionPeerConfig{enable13: true},
			answer:          dtlsVersionPeerConfig{enable13: true},
			skipHelloVerify: true,
			wantRTTs:        dtls13ClientRTTs,
		},
		{
			name:            "DTLS13Client_DTLS12Server",
			answer:          dtlsVersionPeerConfig{enable13: true},
			skipHelloVerify: true,
			wantRTTs:        2,
		},
		{
			name:            "DTLS12Client_DTLS13Server",
			offer:           dtlsVersionPeerConfig{enable13: true},
			skipHelloVerify: true,
			wantRTTs:        2,
		},
		{
			name:            "DTLS13_AnswererServer",
			offer:           dtlsVersionPeerConfig{enable13: true},
			answer:          dtlsVersionPeerConfig{enable13: true, answeringRole: DTLSRoleServer},
			skipHelloVerify: true,
			wantRTTs:        dtls13ClientRTTs,
		},
		{name: "DTLS12_HelloVerify", wantRTTs: 3},
		{
			// The cookie HelloRetryRequest costs one round trip, like the DTLS 1.2 HelloVerifyRequest.
			name:     "DTLS13_CookieHelloRetry",
			offer:    dtlsVersionPeerConfig{enable13: true},
			answer:   dtlsVersionPeerConfig{enable13: true},
			wantRTTs: dtls13ClientRTTs + 1,
		},
		{
			name:     "DTLS13Client_DTLS12Server_HelloVerify",
			answer:   dtlsVersionPeerConfig{enable13: true},
			wantRTTs: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(60 * time.Second)
			defer lim.Stop()

			report := test.CheckRoutines(t)
			defer report()

			got := measureDTLSHandshake(t, oneWayDelay, tc.skipHelloVerify, tc.offer, tc.answer)
			t.Logf("DTLS client handshake took %v (%.2f RTT)", got, float64(got)/float64(rtt))

			want := time.Duration(tc.wantRTTs) * rtt
			assert.Greater(t, got, want-rtt/2, "handshake faster than %d RTT", tc.wantRTTs)
			assert.Less(t, got, want+rtt/2, "handshake slower than %d RTT", tc.wantRTTs)
		})
	}
}
