// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/prf"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/transport/v5/test"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SCTP chunk types (RFC 9260 Section 3.2, RFC 8260) and the DCEP payload protocol identifier
// (RFC 8832 Section 8.1).
const (
	sctpChunkData       = 0
	sctpChunkInit       = 1
	sctpChunkInitAck    = 2
	sctpChunkCookieEcho = 10
	sctpChunkCookieAck  = 11
	sctpChunkIData      = 64
	sctpPPIDDCEP        = 50
)

// sctpWireCount is what a sctpWire saw inside the DTLS records of a call.
type sctpWireCount struct {
	chunks map[byte]int // by chunk type
	dcep   int          // DATA and I-DATA chunks carrying DCEP messages
}

func (c sctpWireCount) handshakeChunks() int {
	return c.chunks[sctpChunkInit] + c.chunks[sctpChunkInitAck] +
		c.chunks[sctpChunkCookieEcho] + c.chunks[sctpChunkCookieAck]
}

// sctpWire records the DTLS 1.2 datagrams a vnet router forwards and the key log of the
// peers, so a test can decrypt the records afterwards and count the SCTP chunks in them.
// It needs TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
type sctpWire struct {
	mu        sync.Mutex
	datagrams [][]byte
	keyLog    bytes.Buffer
}

func (w *sctpWire) filter(c vnet.Chunk) bool {
	data := c.UserData()
	// RFC 7983: DTLS records start with a byte in [20, 63].
	if c.Network() == "udp" && len(data) > 0 && data[0] >= 20 && data[0] <= 63 { //nolint:goconst
		w.mu.Lock()
		w.datagrams = append(w.datagrams, append([]byte{}, data...))
		w.mu.Unlock()
	}

	return true
}

func (w *sctpWire) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.keyLog.Write(p)
}

type dtlsRecord struct {
	contentType protocol.ContentType
	header      []byte
	body        []byte
}

func splitDTLSRecords(datagram []byte) (records []dtlsRecord) {
	const headerLen = 13
	for len(datagram) >= headerLen {
		length := int(binary.BigEndian.Uint16(datagram[11:]))
		if len(datagram) < headerLen+length {
			break
		}
		records = append(records, dtlsRecord{
			contentType: protocol.ContentType(datagram[0]),
			header:      datagram[:headerLen],
			body:        datagram[headerLen : headerLen+length],
		})
		datagram = datagram[headerLen+length:]
	}

	return records
}

// count decrypts the application data records and counts the SCTP chunks they carry.
func (w *sctpWire) count(t *testing.T) sctpWireCount { //nolint:cyclop
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()

	var clientRandom, serverRandom []byte
	for _, datagram := range w.datagrams {
		for _, record := range splitDTLSRecords(datagram) {
			// Handshake header: type(1) length(3) message_seq(2) fragment_offset(3)
			// fragment_length(3), then version(2) and random(32) in both hellos.
			body := record.body
			if record.contentType != protocol.ContentTypeHandshake || len(body) < 12+34 ||
				!bytes.Equal(body[6:9], []byte{0, 0, 0}) || record.header[3] != 0 || record.header[4] != 0 {
				continue
			}
			switch body[0] {
			case 1:
				clientRandom = body[14:46]
			case 2:
				serverRandom = body[14:46]
			}
		}
	}
	require.NotNil(t, clientRandom, "no ClientHello captured")
	require.NotNil(t, serverRandom, "no ServerHello captured")

	var masterSecret []byte
	scanner := bufio.NewScanner(&w.keyLog)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "CLIENT_RANDOM" && fields[1] == hex.EncodeToString(clientRandom) {
			var err error
			masterSecret, err = hex.DecodeString(fields[2])
			require.NoError(t, err)
		}
	}
	require.NotNil(t, masterSecret, "no key logged for the captured ClientHello")

	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, 0, 16, 4, sha256.New)
	require.NoError(t, err)
	newGCM := func(key []byte) cipher.AEAD {
		block, blockErr := aes.NewCipher(key)
		require.NoError(t, blockErr)
		aead, aeadErr := cipher.NewGCM(block)
		require.NoError(t, aeadErr)

		return aead
	}
	directions := []struct {
		aead cipher.AEAD
		iv   []byte
	}{
		{newGCM(keys.ClientWriteKey), keys.ClientWriteIV},
		{newGCM(keys.ServerWriteKey), keys.ServerWriteIV},
	}

	count := sctpWireCount{chunks: map[byte]int{}}
	for _, datagram := range w.datagrams {
		for _, record := range splitDTLSRecords(datagram) {
			if record.contentType != protocol.ContentTypeApplicationData || len(record.body) < 8+16 {
				continue
			}
			// RFC 5288: nonce = salt(4) || explicit nonce(8); additional data = epoch and
			// sequence number(8) || type(1) || version(2) || plaintext length(2).
			explicitNonce, ciphertext := record.body[:8], record.body[8:]
			additionalData := make([]byte, 13)
			copy(additionalData, record.header[3:11])
			copy(additionalData[8:], record.header[:3])
			binary.BigEndian.PutUint16(additionalData[11:], uint16(len(ciphertext)-16)) //nolint:gosec // G115
			var sctpPacket []byte
			for _, d := range directions {
				nonce := append(append([]byte{}, d.iv...), explicitNonce...)
				if plaintext, openErr := d.aead.Open(nil, nonce, ciphertext, additionalData); openErr == nil {
					sctpPacket = plaintext
				}
			}
			require.NotNil(t, sctpPacket, "application data record that neither key decrypts")
			countSCTPChunks(t, sctpPacket, &count)
		}
	}

	return count
}

func countSCTPChunks(t *testing.T, packet []byte, count *sctpWireCount) {
	t.Helper()

	const commonHeaderLen = 12
	require.GreaterOrEqual(t, len(packet), commonHeaderLen)
	for chunks := packet[commonHeaderLen:]; len(chunks) >= 4; {
		length := int(binary.BigEndian.Uint16(chunks[2:]))
		require.GreaterOrEqual(t, length, 4)
		require.LessOrEqual(t, length, len(chunks))
		chunk := chunks[:length]
		count.chunks[chunk[0]]++
		switch {
		case chunk[0] == sctpChunkData && length >= 16:
			if binary.BigEndian.Uint32(chunk[12:]) == sctpPPIDDCEP {
				count.dcep++
			}
		case chunk[0] == sctpChunkIData && length >= 20 && chunk[1]&0x02 != 0: // B bit: first fragment carries the PPID
			if binary.BigEndian.Uint32(chunk[16:]) == sctpPPIDDCEP {
				count.dcep++
			}
		}
		chunks = chunks[min((length+3)&^3, len(chunks)):]
	}
}

// snapPeerConfig configures one side of runSNAPPair.
type snapPeerConfig struct {
	snap   bool
	dtls13 bool
}

// snapPairConfig configures runSNAPPair.
type snapPairConfig struct {
	offer, answer snapPeerConfig
	// negotiatedID, if set, makes both sides create the channel with Negotiated: true and
	// this id. Otherwise the offerer opens it in band.
	negotiatedID *uint16
	// mungeOffer, if set, rewrites the offer before the answerer applies it.
	mungeOffer func(string) string
}

// snapPairResult is what runSNAPPair observed.
type snapPairResult struct {
	offerSDP, answerSDP     string
	offerState, answerState WARPState
	// offerOpenAfterDTLS is how long after its DTLS transport connected the offerer's data
	// channel opened.
	offerOpenAfterDTLS time.Duration
	wire               *sctpWire
}

// runSNAPPair connects two PeerConnections over a virtual network that delays every packet by
// oneWayDelay, opens a data channel, sends a message each way and reports what was
// negotiated.
func runSNAPPair(t *testing.T, oneWayDelay time.Duration, cfg snapPairConfig) snapPairResult { //nolint:cyclop
	t.Helper()

	wire := &sctpWire{}
	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24", //nolint:goconst
		MinDelay:      oneWayDelay,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)
	wan.AddChunkFilter(wire.filter)

	newPC := func(ip string, peer snapPeerConfig) *PeerConnection {
		vnetNet, netErr := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
		require.NoError(t, netErr)
		require.NoError(t, wan.AddNet(vnetNet))

		settings := SettingEngine{}
		settings.SetNet(vnetNet)
		settings.SetICETimeouts(5*time.Second, 10*time.Second, 200*time.Millisecond)
		settings.EnableSctpSnap(peer.snap)
		if peer.dtls13 {
			require.NoError(t, settings.SetDTLSVersionRange(protocol.Version1_2, protocol.Version1_3))
		} else {
			settings.SetDTLSCipherSuites(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
			settings.SetDTLSKeyLogWriter(wire)
		}
		pc, pcErr := NewAPI(WithSettingEngine(settings)).NewPeerConnection(Configuration{})
		require.NoError(t, pcErr)

		return pc
	}
	offerPC := newPC("1.2.3.4", cfg.offer)
	answerPC := newPC("1.2.3.5", cfg.answer)
	require.NoError(t, wan.Start())
	defer func() { assert.NoError(t, wan.Stop()) }()
	defer closePairNow(t, offerPC, answerPC)

	assert.Equal(t, WARPState{}, offerPC.WARPState(), "state before connecting")

	var offerDTLS dtlsHandshakeTime
	offerDTLS.track(offerPC.SCTP().Transport())

	var channelOpened sync.Mutex
	var offerOpened time.Time
	received := make(chan string, 2)
	opened := make(chan struct{}, 2)
	setup := func(dc *DataChannel, isOfferer bool, message string) {
		dc.OnOpen(func() {
			if isOfferer {
				channelOpened.Lock()
				offerOpened = time.Now()
				channelOpened.Unlock()
			}
			assert.NoError(t, dc.SendText(message))
			opened <- struct{}{}
		})
		dc.OnMessage(func(msg DataChannelMessage) { received <- string(msg.Data) })
	}

	init := &DataChannelInit{}
	if cfg.negotiatedID != nil {
		negotiated := true
		init.Negotiated = &negotiated
		init.ID = cfg.negotiatedID
		answerDC, dcErr := answerPC.CreateDataChannel("warp", init)
		require.NoError(t, dcErr)
		setup(answerDC, false, "from answerer")
	} else {
		answerPC.OnDataChannel(func(dc *DataChannel) { setup(dc, false, "from answerer") })
	}
	offerDC, err := offerPC.CreateDataChannel("warp", init)
	require.NoError(t, err)
	setup(offerDC, true, "from offerer")

	opts := []func(*signalPairOptions){withDisableInitialDataChannel(true)}
	if cfg.mungeOffer != nil {
		opts = append(opts, withModificationFunc(cfg.mungeOffer))
	}
	require.NoError(t, signalPairWithOptions(offerPC, answerPC, opts...))

	for range 2 {
		select {
		case <-opened:
		case <-time.After(10 * time.Second):
			require.FailNow(t, "data channel did not open")
		}
	}
	got := map[string]bool{}
	for range 2 {
		select {
		case msg := <-received:
			got[msg] = true
		case <-time.After(10 * time.Second):
			require.FailNow(t, "message not delivered")
		}
	}
	assert.Equal(t, map[string]bool{"from offerer": true, "from answerer": true}, got)

	offerDTLS.mu.Lock()
	dtlsConnected := offerDTLS.connected
	offerDTLS.mu.Unlock()
	channelOpened.Lock()
	openAfterDTLS := offerOpened.Sub(dtlsConnected)
	channelOpened.Unlock()

	return snapPairResult{
		offerSDP:           offerPC.CurrentLocalDescription().SDP,
		answerSDP:          answerPC.CurrentLocalDescription().SDP,
		offerState:         offerPC.WARPState(),
		answerState:        answerPC.WARPState(),
		offerOpenAfterDTLS: openAfterDTLS,
		wire:               wire,
	}
}

// mungeSctpInit rewrites the INIT chunk in the sctp-init attribute of desc.
func mungeSctpInit(t *testing.T, desc string, edit func([]byte)) string {
	t.Helper()

	const prefix = "a=sctp-init:"
	start := strings.Index(desc, prefix)
	require.GreaterOrEqual(t, start, 0, "no sctp-init")
	start += len(prefix)
	end := start + strings.Index(desc[start:], "\r\n")
	init, err := base64.StdEncoding.DecodeString(desc[start:end])
	require.NoError(t, err)
	edit(init)

	return desc[:start] + base64.StdEncoding.EncodeToString(init) + desc[end:]
}

// TestSctpSnap_Wire checks on the wire, in decrypted DTLS records, that a SNAP association
// starts without the SCTP handshake and that a negotiated data channel opens without DCEP,
// and that WARPState reports both.
func TestSctpSnap_Wire(t *testing.T) {
	const (
		oneWayDelay = 50 * time.Millisecond
		rtt         = 2 * oneWayDelay
	)
	negotiatedID := uint16(4)

	for _, tc := range []struct {
		name          string
		cfg           snapPairConfig
		wantSNAP      bool
		wantHandshake bool
		wantDCEP      bool
	}{
		{
			name: "SNAPNegotiatedChannel",
			cfg: snapPairConfig{
				offer: snapPeerConfig{snap: true}, answer: snapPeerConfig{snap: true},
				negotiatedID: &negotiatedID,
			},
			wantSNAP: true,
		},
		{
			name:     "SNAPInBandChannel",
			cfg:      snapPairConfig{offer: snapPeerConfig{snap: true}, answer: snapPeerConfig{snap: true}},
			wantSNAP: true, wantDCEP: true,
		},
		{
			name: "OffererOnlySNAP",
			cfg: snapPairConfig{
				offer: snapPeerConfig{snap: true}, negotiatedID: &negotiatedID,
			},
			wantHandshake: true,
		},
		{
			name:          "NoSNAP",
			cfg:           snapPairConfig{negotiatedID: &negotiatedID},
			wantHandshake: true,
		},
		{
			// A valid base64 value that is not a valid INIT: the answerer leaves sctp-init out of
			// its answer and both sides run the handshake.
			name: "InvalidRemoteInit",
			cfg: snapPairConfig{
				offer: snapPeerConfig{snap: true}, answer: snapPeerConfig{snap: true},
				negotiatedID: &negotiatedID,
				mungeOffer: func(offer string) string {
					return mungeSctpInit(t, offer, func(init []byte) { copy(init[4:8], []byte{0, 0, 0, 0}) })
				},
			},
			wantHandshake: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := test.TimeOut(30 * time.Second)
			defer lim.Stop()

			report := test.CheckRoutines(t)
			defer report()

			res := runSNAPPair(t, oneWayDelay, tc.cfg)
			count := res.wire.count(t)
			t.Logf("chunks by type %v, DCEP messages %d; offerer channel open %v after DTLS",
				count.chunks, count.dcep, res.offerOpenAfterDTLS)

			assert.Equal(t, tc.cfg.offer.snap, strings.Contains(res.offerSDP, "a=sctp-init:"))
			assert.Equal(t, tc.wantSNAP, strings.Contains(res.answerSDP, "a=sctp-init:"))

			// Both messages crossed the wire, so the observer decrypted SCTP traffic.
			assert.Positive(t, count.chunks[sctpChunkData]+count.chunks[sctpChunkIData])
			if tc.wantHandshake {
				assert.Positive(t, count.chunks[sctpChunkInit])
				assert.Positive(t, count.chunks[sctpChunkCookieEcho])
				assert.Positive(t, count.chunks[sctpChunkCookieAck])
			} else {
				assert.Zero(t, count.handshakeChunks(), "SCTP handshake chunks on the wire")
			}
			if tc.wantDCEP {
				assert.Positive(t, count.dcep)
			} else {
				assert.Zero(t, count.dcep, "DCEP messages on the wire")
			}

			if tc.cfg.negotiatedID != nil {
				// Without the handshake the channel opens as soon as DTLS is up; the handshake
				// costs at least one more round trip.
				if tc.wantSNAP {
					assert.Less(t, res.offerOpenAfterDTLS, rtt/2)
				} else {
					assert.Greater(t, res.offerOpenAfterDTLS, rtt)
				}
			}

			want := WARPState{
				DTLSVersion:           protocol.Version1_2,
				SNAP:                  tc.wantSNAP,
				NegotiatedDataChannel: tc.cfg.negotiatedID != nil,
			}
			assert.Equal(t, want, res.offerState)
			assert.Equal(t, want, res.answerState)
		})
	}
}

// TestPeerConnection_WARPState_DTLS13 checks that WARPState reports DTLS 1.3 next to SNAP.
func TestPeerConnection_WARPState_DTLS13(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	negotiatedID := uint16(1)
	res := runSNAPPair(t, 0, snapPairConfig{
		offer:        snapPeerConfig{snap: true, dtls13: true},
		answer:       snapPeerConfig{snap: true, dtls13: true},
		negotiatedID: &negotiatedID,
	})
	want := WARPState{DTLSVersion: protocol.Version1_3, SNAP: true, NegotiatedDataChannel: true}
	assert.Equal(t, want, res.offerState)
	assert.Equal(t, want, res.answerState)
}

// chromeSctpInit2 is the answer example of draft-hancke-tsvwg-snap.
const chromeSctpInit2 = "AQAAHl+zdHQAUAAA/////6Gq3HTAAAAEgAgABoLA"

// invalidSctpInit is Chrome's example with a zero Initiate Tag.
const invalidSctpInit = "AQAAHgAAAAAAUAAA/////+B5ZR3AAAAEgAgABoLA"

// chromeLikeDescription is a description with a data section as Chrome writes it, carrying
// sctpInit unless it is empty.
func chromeLikeDescription(sdpType SDPType, version int, sctpInit string) SessionDescription {
	setup := sdp.ConnectionRoleActpass.String()
	if sdpType == SDPTypeAnswer {
		setup = sdp.ConnectionRoleActive.String()
	}
	desc := "v=0\r\n" +
		"o=- 4611731400430051336 " + strconv.Itoa(version) + " IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"a=msid-semantic: WMS\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=ice-ufrag:rmtu\r\n" +
		"a=ice-pwd:remotepasswordremotepassw\r\n" +
		"a=ice-options:trickle\r\n" +
		"a=fingerprint:sha-256 0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E\r\n" + //nolint:lll
		"a=setup:" + setup + "\r\n" +
		"a=mid:0\r\n" +
		"a=sctp-port:5000\r\n" +
		"a=max-message-size:262144\r\n"
	if sctpInit != "" {
		desc += "a=sctp-init:" + sctpInit + "\r\n"
	}

	return SessionDescription{Type: sdpType, SDP: desc}
}

func newSNAPTestPeerConnection(t *testing.T, snap bool) *PeerConnection {
	t.Helper()

	settings := SettingEngine{}
	settings.EnableSctpSnap(snap)
	settings.SetInterfaceFilter(func(string) bool { return false })
	pc, err := NewAPI(WithSettingEngine(settings)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	return pc
}

func sctpInitOf(t *testing.T, desc string) string {
	t.Helper()

	for line := range strings.SplitSeq(desc, "\r\n") {
		if value, ok := strings.CutPrefix(line, "a=sctp-init:"); ok {
			return value
		}
	}

	return ""
}

func setLocalDescriptionAndGather(t *testing.T, pc *PeerConnection, desc SessionDescription) {
	t.Helper()

	gathered := GatheringCompletePromise(pc)
	require.NoError(t, pc.SetLocalDescription(desc))
	<-gathered
}

// TestSctpSnap_RenegotiationKeepsFirstSctpInit answers Chrome-like offers and re-offers:
// once a data section has been negotiated, the answers keep sctp-init as the first answer
// had it. They never add it and never change it.
func TestSctpSnap_RenegotiationKeepsFirstSctpInit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		snap   bool
		offers []string // sctp-init of each offer, "" for none
		want   []bool   // whether each answer carries our sctp-init
	}{
		{
			name: "RepeatedByChrome", snap: true,
			offers: []string{chromeSctpInit, chromeSctpInit, chromeSctpInit}, want: []bool{true, true, true},
		},
		{
			name: "AddedInReOffer", snap: true,
			offers: []string{"", chromeSctpInit}, want: []bool{false, false},
		},
		{
			name: "ValidAfterInvalid", snap: true,
			offers: []string{invalidSctpInit, chromeSctpInit}, want: []bool{false, false},
		},
		{
			name: "ChangedInReOffer", snap: true,
			offers: []string{chromeSctpInit, chromeSctpInit2}, want: []bool{true, true},
		},
		{
			name: "DroppedThenRepeated", snap: true,
			offers: []string{chromeSctpInit, "", chromeSctpInit}, want: []bool{true, false, false},
		},
		{
			name: "SNAPDisabled", snap: false,
			offers: []string{chromeSctpInit, chromeSctpInit}, want: []bool{false, false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := newSNAPTestPeerConnection(t, tc.snap)

			var first string
			for i, sctpInit := range tc.offers {
				require.NoError(t, pc.SetRemoteDescription(chromeLikeDescription(SDPTypeOffer, i+2, sctpInit)))
				answer, err := pc.CreateAnswer(nil)
				require.NoError(t, err)

				got := sctpInitOf(t, answer.SDP)
				assert.Equal(t, tc.want[i], got != "", "answer %d: %q", i+1, got)
				if i == 0 {
					first = got
				} else if got != "" {
					assert.Equal(t, first, got, "answer %d changed sctp-init", i+1)
				}
				setLocalDescriptionAndGather(t, pc, answer)
			}
		})
	}
}

// TestSctpSnap_RenegotiationAsOfferer checks re-offers, and answers to the remote peer's
// re-offers, after pion offered SNAP: sctp-init stays only if the first answer accepted it.
func TestSctpSnap_RenegotiationAsOfferer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		answer      string // sctp-init of the remote answer
		wantInitial bool
	}{
		{name: "Accepted", answer: chromeSctpInit, wantInitial: true},
		{name: "NotAccepted", answer: ""},
		{name: "InvalidAnswer", answer: invalidSctpInit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := newSNAPTestPeerConnection(t, true)
			_, err := pc.CreateDataChannel("warp", nil)
			require.NoError(t, err)

			offer, err := pc.CreateOffer(nil)
			require.NoError(t, err)
			ours := sctpInitOf(t, offer.SDP)
			require.NotEmpty(t, ours)
			setLocalDescriptionAndGather(t, pc, offer)
			require.NoError(t, pc.SetRemoteDescription(chromeLikeDescription(SDPTypeAnswer, 2, tc.answer)))

			want := ""
			if tc.wantInitial {
				want = ours
			}

			reOffer, err := pc.CreateOffer(nil)
			require.NoError(t, err)
			assert.Equal(t, want, sctpInitOf(t, reOffer.SDP), "re-offer")
			setLocalDescriptionAndGather(t, pc, reOffer)
			require.NoError(t, pc.SetRemoteDescription(chromeLikeDescription(SDPTypeAnswer, 3, tc.answer)))

			// Chrome keeps offering the sctp-init of its current description.
			require.NoError(t, pc.SetRemoteDescription(chromeLikeDescription(SDPTypeOffer, 4, chromeSctpInit)))
			answer, err := pc.CreateAnswer(nil)
			require.NoError(t, err)
			assert.Equal(t, want, sctpInitOf(t, answer.SDP), "answer to the remote re-offer")
		})
	}
}

// TestSctpSnap_EnabledOncePerPeerConnection checks that EnableSctpSnap cannot change after the
// API is created.
func TestSctpSnap_EnabledOncePerPeerConnection(t *testing.T) {
	settings := SettingEngine{}
	settings.EnableSctpSnap(true)
	settings.SetInterfaceFilter(func(string) bool { return false })
	api := NewAPI(WithSettingEngine(settings))
	settings.EnableSctpSnap(false)

	pc, err := api.NewPeerConnection(Configuration{})
	require.NoError(t, err)
	defer func() { assert.NoError(t, pc.Close()) }()

	require.NoError(t, pc.SetRemoteDescription(chromeLikeDescription(SDPTypeOffer, 2, chromeSctpInit)))
	answer, err := pc.CreateAnswer(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, sctpInitOf(t, answer.SDP))
}
