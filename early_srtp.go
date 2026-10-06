// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"sync"
	"time"
)

// earlySRTPBudgetFactor bounds the SRTP and SRTCP bytes sent before the peer is
// verified to this many times the bytes received, as QUIC bounds 0.5-RTT data
// before address validation (RFC 9000 Section 8.1).
const earlySRTPBudgetFactor = 3

// EarlySRTPState is what a DTLS server did with early SRTP, see
// SettingEngine.EnableDTLSServerEarlySRTP.
type EarlySRTPState int

const (
	// EarlySRTPStateNone means early SRTP is not enabled, the DTLSTransport is
	// not a server, or the handshake has not reached the server's Finished.
	EarlySRTPStateNone EarlySRTPState = iota
	// EarlySRTPStateDTLS12 means DTLS 1.2 was negotiated, so SRTP started when
	// the handshake completed.
	EarlySRTPStateDTLS12
	// EarlySRTPStateNoSPED means the handshake did not run inside STUN, so SRTP
	// starts when it completes.
	EarlySRTPStateNoSPED
	// EarlySRTPStateDirectDTLS means a DTLS datagram arrived outside STUN before
	// the server's Finished, so SRTP starts when the handshake completes.
	EarlySRTPStateDirectDTLS
	// EarlySRTPStateStarted means SRTP started after the server's Finished and
	// the peer is not verified yet.
	EarlySRTPStateStarted
	// EarlySRTPStateVerified means SRTP started early and the handshake completed.
	EarlySRTPStateVerified
	// EarlySRTPStateFailed means SRTP started early and the handshake failed.
	EarlySRTPStateFailed
	// EarlySRTPStateClosed means SRTP started early and the DTLSTransport was
	// stopped before the handshake completed.
	EarlySRTPStateClosed
)

func (s EarlySRTPState) String() string {
	switch s {
	case EarlySRTPStateNone:
		return "none"
	case EarlySRTPStateDTLS12:
		return "dtls12"
	case EarlySRTPStateNoSPED:
		return "no_sped"
	case EarlySRTPStateDirectDTLS:
		return "direct_dtls"
	case EarlySRTPStateStarted:
		return "started"
	case EarlySRTPStateVerified:
		return "verified"
	case EarlySRTPStateFailed:
		return "failed"
	case EarlySRTPStateClosed:
		return "closed"
	default:
		return ErrUnknownType.Error()
	}
}

// EarlySRTPStats reports what a DTLS server did with early SRTP.
type EarlySRTPStats struct {
	State EarlySRTPState
	// StartedAt is when SRTP started early, and EndedAt when the handshake
	// completed or failed or the DTLSTransport was stopped after that.
	StartedAt, EndedAt time.Time
	// PacketsSent and BytesSent count the SRTP and SRTCP packets sent before the
	// handshake completed.
	PacketsSent, BytesSent uint64
	// PacketsOverBudget counts the packets dropped because they would have
	// exceeded three times the bytes received, and PacketsAfterWindow those
	// dropped because the window had elapsed.
	PacketsOverBudget, PacketsAfterWindow uint64
}

// earlySRTP tracks early SRTP on a DTLS server and gates its writes.
type earlySRTP struct {
	window time.Duration

	mu       sync.Mutex
	stats    EarlySRTPStats
	deadline time.Time
}

func newEarlySRTP(window time.Duration) *earlySRTP {
	return &earlySRTP{window: window}
}

// setIneligible records why SRTP does not start early, unless it already did.
func (e *earlySRTP) setIneligible(state EarlySRTPState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stats.State == EarlySRTPStateNone {
		e.stats.State = state
	}
}

// start records that SRTP starts early. It reports false if SRTP must not start
// early anymore.
func (e *earlySRTP) start(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stats.State != EarlySRTPStateNone {
		return false
	}
	e.stats.State = EarlySRTPStateStarted
	e.stats.StartedAt = now
	e.deadline = now.Add(e.window)

	return true
}

// end records the outcome of the handshake after an early start. It reports
// whether SRTP had started early.
func (e *earlySRTP) end(state EarlySRTPState, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stats.State != EarlySRTPStateStarted {
		return false
	}
	e.stats.State = state
	e.stats.EndedAt = now

	return true
}

// allow reports whether to send an SRTP or SRTCP packet of n bytes, given the
// bytes received so far, and counts it. charged reports whether the packet was
// counted against the budget, so that refund can return it if it is not sent.
func (e *earlySRTP) allow(n int, received uint64) (ok, charged bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.stats.State { //nolint:exhaustive
	case EarlySRTPStateVerified:
		return true, false
	case EarlySRTPStateStarted:
	default:
		return false, false
	}
	if !time.Now().Before(e.deadline) {
		e.stats.PacketsAfterWindow++

		return false, false
	}
	size := uint64(n) //nolint:gosec // G115, n is never negative
	if e.stats.BytesSent+size > earlySRTPBudgetFactor*received {
		e.stats.PacketsOverBudget++

		return false, false
	}
	e.stats.BytesSent += size
	e.stats.PacketsSent++

	return true, true
}

// refund returns a charged packet of n bytes that could not be sent, for example
// because the ICE-lite agent has no pair before it is nominated.
func (e *earlySRTP) refund(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.BytesSent -= uint64(n) //nolint:gosec // G115, n is never negative
	e.stats.PacketsSent--
}

func (e *earlySRTP) getStats() EarlySRTPStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.stats
}
