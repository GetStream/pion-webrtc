// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/test"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateSPEDGolden = flag.Bool("update-sped-golden", false, "rewrite testdata/sped_off_*.golden") //nolint:gochecknoglobals

// TestSPED_OffWireUnchanged checks that SDP and STUN are byte for byte those
// recorded before SPED support was added (testdata/sped_off_*.golden), when
// SPED is off and when the answerer enables it but the offer has no SPED ICE
// option. Values random by design are masked: the SDP session ID and
// certificate fingerprint, and the STUN transaction ID, tie-breaker,
// MESSAGE-INTEGRITY and FINGERPRINT.
func TestSPED_OffWireUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name       string
		golden     string
		lite       bool
		answerSPED bool
	}{
		{name: "Full", golden: "sped_off_full.golden"},
		{name: "Lite", golden: "sped_off_lite.golden", lite: true},
		{name: "Full_AnswererSPEDEnabled", golden: "sped_off_full.golden", answerSPED: true},
		{name: "Lite_AnswererSPEDEnabled", golden: "sped_off_lite.golden", lite: true, answerSPED: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			got := recordSPEDOffWire(t, tc.lite, tc.answerSPED)
			path := filepath.Join("testdata", tc.golden)
			if *updateSPEDGolden {
				require.NoError(t, os.MkdirAll("testdata", 0o750))
				require.NoError(t, os.WriteFile(path, []byte(got), 0o600))
			}
			want, err := os.ReadFile(path) //nolint:gosec // test data
			require.NoError(t, err)
			assert.Equal(t, string(want), got)
		})
	}
}

// recordSPEDOffWire connects an offerer and an answerer with fixed ICE
// credentials and ports over vnet, exchanges a data channel message, and
// returns both descriptions and every distinct STUN message each side sent.
func recordSPEDOffWire(t *testing.T, lite, answerSPED bool) string {
	t.Helper()

	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24",
		MinDelay:      5 * time.Millisecond,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)

	var mu sync.Mutex
	stunBySender := map[string][]string{}
	router.AddChunkFilter(func(chunk vnet.Chunk) bool {
		raw := chunk.UserData()
		if stun.IsMessage(raw) {
			from := chunk.SourceAddr().(*net.UDPAddr).IP.String() //nolint:forcetypeassert // vnet UDP chunk
			canonical := hex.EncodeToString(maskSTUN(raw))
			mu.Lock()
			if !slices.Contains(stunBySender[from], canonical) {
				stunBySender[from] = append(stunBySender[from], canonical)
			}
			mu.Unlock()
		}

		return true
	})

	newPC := func(ip, ufrag string, port uint16, isLite, sped bool) *PeerConnection {
		vnetNet, netErr := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
		require.NoError(t, netErr)
		require.NoError(t, router.AddNet(vnetNet))

		settings := SettingEngine{}
		settings.SetNet(vnetNet)
		settings.SetICECredentials(ufrag, ufrag+"password0123456789")
		require.NoError(t, settings.SetEphemeralUDPPortRange(port, port))
		settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
		settings.SetLite(isLite)
		settings.EnableSped(sped)
		pc, pcErr := NewAPI(WithSettingEngine(settings)).NewPeerConnection(Configuration{})
		require.NoError(t, pcErr)

		return pc
	}
	offerPC := newPC("1.2.3.4", "offerufrag", 5000, false, false)
	answerPC := newPC("1.2.3.5", "answerufrag", 5001, lite, answerSPED)
	require.NoError(t, router.Start())

	received := make(chan struct{})
	answerPC.OnDataChannel(func(dc *DataChannel) {
		var once sync.Once
		dc.OnMessage(func(DataChannelMessage) { once.Do(func() { close(received) }) })
	})
	dc, err := offerPC.CreateDataChannel("wire", nil)
	require.NoError(t, err)
	dc.OnOpen(func() { assert.NoError(t, dc.SendText("hello")) })

	connected := untilConnectionState(PeerConnectionStateConnected, offerPC, answerPC)
	require.NoError(t, signalPair(offerPC, answerPC))
	<-connected
	<-received

	var out strings.Builder
	out.WriteString("# offer\n" + maskSDP(offerPC.LocalDescription().SDP))
	out.WriteString("# answer\n" + maskSDP(answerPC.LocalDescription().SDP))

	closePairNow(t, offerPC, answerPC)
	require.NoError(t, router.Stop())

	mu.Lock()
	defer mu.Unlock()
	for _, from := range []string{"1.2.3.4", "1.2.3.5"} {
		messages := slices.Clone(stunBySender[from])
		slices.Sort(messages)
		out.WriteString("# STUN from " + from + "\n" + strings.Join(messages, "\n") + "\n")
	}

	return out.String()
}

func maskSDP(sdp string) string {
	sdp = regexp.MustCompile(`(?m)^o=.*$`).ReplaceAllString(sdp, "o=MASKED")
	sdp = regexp.MustCompile(`(?m)^(a=fingerprint:\S+) .*$`).ReplaceAllString(sdp, "$1 MASKED")

	return strings.ReplaceAll(sdp, "\r\n", "\n")
}

// maskSTUN zeroes the transaction ID and the values of the attributes that
// are random or depend on it.
func maskSTUN(raw []byte) []byte {
	masked := slices.Clone(raw)
	clear(masked[8:20])
	for offset := 20; offset+4 <= len(masked); {
		attrType := stun.AttrType(binary.BigEndian.Uint16(masked[offset:]))
		length := int(binary.BigEndian.Uint16(masked[offset+2:]))
		end := min(offset+4+length, len(masked))
		switch attrType { //nolint:exhaustive
		case stun.AttrICEControlling, stun.AttrICEControlled, stun.AttrMessageIntegrity, stun.AttrFingerprint:
			clear(masked[offset+4 : end])
		}
		offset += 4 + (length+3)&^3
	}

	return masked
}
