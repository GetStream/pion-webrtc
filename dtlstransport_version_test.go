// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/srtp/v3"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dtlsVersionPeerConfig struct {
	enable13      bool
	answeringRole DTLSRole // only used by the answerer; 0 keeps the default
}

func newDTLSVersionAPI(t *testing.T, cfg dtlsVersionPeerConfig, settings SettingEngine) *API {
	t.Helper()

	if cfg.enable13 {
		require.NoError(t, settings.SetDTLSVersionRange(protocol.Version1_2, protocol.Version1_3))
	}
	if cfg.answeringRole != 0 {
		require.NoError(t, settings.SetAnsweringDTLSRole(cfg.answeringRole))
	}

	return NewAPI(WithSettingEngine(settings))
}

// exchangeMediaAndData sends video both ways and a data channel message from the
// offerer to the answerer, and fails the test if either does not arrive.
func exchangeMediaAndData(t *testing.T, offerPC, answerPC *PeerConnection) {
	t.Helper()

	var tracks []*TrackLocalStaticSample
	var tracksReceived sync.WaitGroup
	for _, pc := range []*PeerConnection{offerPC, answerPC} {
		track, err := NewTrackLocalStaticSample(RTPCodecCapability{MimeType: MimeTypeVP8}, "video", "pion")
		require.NoError(t, err)
		_, err = pc.AddTrack(track)
		require.NoError(t, err)
		tracks = append(tracks, track)

		tracksReceived.Add(1)
		var once sync.Once
		pc.OnTrack(func(remote *TrackRemote, _ *RTPReceiver) {
			// Reading an RTP packet proves SRTP was keyed on both ends.
			if _, _, err := remote.ReadRTP(); err == nil {
				once.Do(tracksReceived.Done)
			}
		})
	}

	dataReceived := make(chan string, 1)
	answerPC.OnDataChannel(func(dc *DataChannel) {
		dc.OnMessage(func(msg DataChannelMessage) {
			select {
			case dataReceived <- string(msg.Data):
			default:
			}
		})
	})
	dc, err := offerPC.CreateDataChannel("version", nil)
	require.NoError(t, err)
	dc.OnOpen(func() {
		assert.NoError(t, dc.SendText("hello"))
	})

	connected := untilConnectionState(PeerConnectionStateConnected, offerPC, answerPC)
	require.NoError(t, signalPair(offerPC, answerPC))
	<-connected

	mediaDone := make(chan struct{})
	go func() {
		tracksReceived.Wait()
		close(mediaDone)
	}()
	sendVideoUntilDone(t, mediaDone, tracks)

	select {
	case msg := <-dataReceived:
		assert.Equal(t, "hello", msg)
	case <-time.After(10 * time.Second):
		assert.Fail(t, "data channel message not received")
	}
}

func TestDTLSTransport_VersionNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		offer, answer dtlsVersionPeerConfig
		want          protocol.Version
	}{
		{
			name: "BothDTLS12",
			want: protocol.Version1_2,
		},
		{
			name:   "BothDTLS13_AnswererClient",
			offer:  dtlsVersionPeerConfig{enable13: true},
			answer: dtlsVersionPeerConfig{enable13: true, answeringRole: DTLSRoleClient},
			want:   protocol.Version1_3,
		},
		{
			name:   "BothDTLS13_AnswererServer",
			offer:  dtlsVersionPeerConfig{enable13: true},
			answer: dtlsVersionPeerConfig{enable13: true, answeringRole: DTLSRoleServer},
			want:   protocol.Version1_3,
		},
		{
			name:   "DTLS13Client_DTLS12Server",
			answer: dtlsVersionPeerConfig{enable13: true, answeringRole: DTLSRoleClient},
			want:   protocol.Version1_2,
		},
		{
			name:   "DTLS12Client_DTLS13Server",
			offer:  dtlsVersionPeerConfig{enable13: true},
			answer: dtlsVersionPeerConfig{answeringRole: DTLSRoleClient},
			want:   protocol.Version1_2,
		},
		{
			name:   "DTLS13Server_DTLS12Client",
			answer: dtlsVersionPeerConfig{enable13: true, answeringRole: DTLSRoleServer},
			want:   protocol.Version1_2,
		},
		{
			name:   "DTLS12Server_DTLS13Client",
			offer:  dtlsVersionPeerConfig{enable13: true},
			answer: dtlsVersionPeerConfig{answeringRole: DTLSRoleServer},
			want:   protocol.Version1_2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			report := test.CheckRoutines(t)
			defer report()

			offerPC, err := newDTLSVersionAPI(t, tc.offer, SettingEngine{}).NewPeerConnection(Configuration{})
			require.NoError(t, err)
			answerPC, err := newDTLSVersionAPI(t, tc.answer, SettingEngine{}).NewPeerConnection(Configuration{})
			require.NoError(t, err)
			defer closePairNow(t, offerPC, answerPC)

			for _, pc := range []*PeerConnection{offerPC, answerPC} {
				version, ok := pc.SCTP().Transport().NegotiatedVersion()
				assert.False(t, ok)
				assert.Zero(t, version)
			}

			exchangeMediaAndData(t, offerPC, answerPC)

			for _, pc := range []*PeerConnection{offerPC, answerPC} {
				dtlsTransport := pc.SCTP().Transport()
				version, ok := dtlsTransport.NegotiatedVersion()
				assert.True(t, ok)
				assert.Equal(t, tc.want, version)

				// The SRTP profile does not depend on the DTLS version.
				dtlsTransport.lock.RLock()
				assert.Equal(t, srtp.ProtectionProfileAeadAes256Gcm, dtlsTransport.srtpProtectionProfile)
				dtlsTransport.lock.RUnlock()
			}
		})
	}
}
