// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/ice/v4"
)

// WARPState reports which of the connection setup optimizations grouped by
// draft-uberti-tsvwg-warp a PeerConnection has used so far. The zero value means none.
type WARPState struct {
	// DTLSVersion is the negotiated DTLS version, protocol.Version1_2 or
	// protocol.Version1_3. It is 0 until the DTLS handshake completes.
	DTLSVersion protocol.Version

	// SPED is the state of DTLS in STUN (draft-hancke-webrtc-sped):
	// ice.SPEDStateDisabled when it was not negotiated, ice.SPEDStateOff after
	// a fallback, ice.SPEDStateComplete once the handshake finished inside STUN.
	SPED ice.SPEDState

	// SNAP is true once the SCTP association was started from the sctp-init
	// attributes of both descriptions (draft-hancke-tsvwg-snap), without the
	// SCTP handshake.
	SNAP bool

	// NegotiatedDataChannel is true once a data channel created with
	// Negotiated: true has opened. Such a channel needs no DCEP exchange.
	NegotiatedDataChannel bool
}

// WARPState returns what the PeerConnection has negotiated so far. It does not
// block, so it is safe to call from any callback.
func (pc *PeerConnection) WARPState() WARPState {
	state := WARPState{
		SPED:                  pc.iceTransport.SPEDState(),
		SNAP:                  pc.sctpTransport.snap.Load(),
		NegotiatedDataChannel: pc.sctpTransport.negotiatedDataChannelOpened.Load(),
	}
	state.DTLSVersion, _ = pc.dtlsTransport.NegotiatedVersion()

	return state
}
