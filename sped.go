// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"slices"
	"strings"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/sdp/v3"
)

// Settings for DTLS while SPED (DTLS in STUN) is used, from libwebrtc's
// p2p/dtls/dtls_transport.cc.
const (
	// spedDTLSMTU keeps DTLS datagrams within the 900 bytes libwebrtc uses with
	// SPED (ice.SPEDDTLSMTU): pion/dtls adds up to 34 bytes of record and
	// handshake headers to the fragments it sizes to the MTU.
	spedDTLSMTU = ice.SPEDDTLSMTU - 34
	// spedDisabledRetransmitInterval turns DTLS retransmissions off until ICE
	// connects: the checks carry the pending flight until it is acknowledged.
	spedDisabledRetransmitInterval = 24 * time.Hour
	// The retransmission interval once ICE connects is twice the ICE round-trip
	// time, spedDefaultRTT without a measurement, within these bounds.
	spedDefaultRTT            = 200 * time.Millisecond
	spedMinRetransmitInterval = 50 * time.Millisecond
	spedMaxRetransmitInterval = 3 * time.Second
)

// ICE options that negotiate SPED, in the order they are added to a description:
// "sped" from the draft, "googspedv1" from libwebrtc M155 and "goog-sped-v1" from
// libwebrtc M149 to M154.
var spedICEOptionList = []string{"sped", "googspedv1", "goog-sped-v1"} //nolint:gochecknoglobals

// spedICEOptions returns the ICE options negotiating SPED that desc carries, at
// session or media level.
func spedICEOptions(desc *sdp.SessionDescription) []string {
	var values []string
	if value, ok := desc.Attribute(sdp.AttrKeyICEOptions); ok {
		values = append(values, strings.Fields(value)...)
	}
	for _, media := range desc.MediaDescriptions {
		if value, ok := media.Attribute(sdp.AttrKeyICEOptions); ok {
			values = append(values, strings.Fields(value)...)
		}
	}

	var options []string
	for _, option := range spedICEOptionList {
		if slices.Contains(values, option) {
			options = append(options, option)
		}
	}

	return options
}

// addSPEDICEOptions adds options to the session-level ICE options of desc.
func addSPEDICEOptions(desc *sdp.SessionDescription, options []string) {
	for _, option := range options {
		if option == "sped" {
			desc.WithICESped()

			continue
		}

		index := slices.IndexFunc(desc.Attributes, func(attribute sdp.Attribute) bool {
			return attribute.Key == sdp.AttrKeyICEOptions
		})
		if index < 0 {
			desc.WithValueAttribute(sdp.AttrKeyICEOptions, option)
		} else {
			desc.Attributes[index].Value += " " + option
		}
	}
}

// spedRemoteAddr is the DTLS remote address while no ICE pair is selected.
// DTLS only uses it to label its datagrams, which the ICE transport sends.
type spedRemoteAddr struct{}

func (spedRemoteAddr) Network() string { return "ice" }
func (spedRemoteAddr) String() string  { return "ice" }
