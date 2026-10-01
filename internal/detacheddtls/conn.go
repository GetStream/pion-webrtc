// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

// Package detacheddtls adapts DTLS application-data events to net.Conn while
// leaving DTLS datagram ownership with the caller.
package detacheddtls

import (
	"context"
	"sync"

	"github.com/pion/dtls/v4"
	"github.com/pion/webrtc/v4/internal/netconn"
	"github.com/pion/webrtc/v4/internal/util"
)

// Config contains the transport operations used by a Conn.
type Config struct {
	DTLSConn *dtls.DetachedConn
	// WriteDatagram writes the datagrams of application data written to the
	// Conn, and every other datagram when WriteFlight is nil.
	WriteDatagram func([]byte) (int, error)
	// WriteFlight, if not nil, writes each batch of datagrams DTLS produces on
	// its own: a handshake flight, a retransmission, an acknowledgement or an alert.
	WriteFlight        func([][]byte) error
	SetDatagramHandler func(func([]byte) error)
	// OnHandshakeDone, if not nil, runs when the handshake completes, before
	// Handshake returns.
	OnHandshakeDone func()
	// OnApplicationData, if not nil, runs for every application data record
	// received.
	OnApplicationData func()
	// OnServerFinishedSent, if not nil, runs once when a DTLS 1.3 server has
	// written the flight that ends with its Finished, before it processes any
	// later datagram. It runs while events are processed, so it must not wait
	// for anything that closes this Conn.
	OnServerFinishedSent func()
	NetConn              netconn.Config
	OnClose              func()
}

// Conn pumps a DetachedConn and exposes only its plaintext application data as
// net.Conn for SCTP.
//
// Every call that drives DTLS (Start, HandleDatagram, Write) processes the
// events it causes before it returns, so a flight that answers a datagram has
// been written when HandleDatagram returns. A goroutine processes the events
// of DTLS timers.
type Conn struct {
	*netconn.Conn

	config Config

	driveMu   sync.Mutex
	eventMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}

	// handshakeDone receives the handshake result once, guarded by eventMu.
	handshakeDone     chan error
	handshakeNotified bool

	onCloseMu sync.Mutex
	onClose   func()
}

// New creates a detached DTLS application-data connection.
func New(config Config) *Conn {
	c := &Conn{
		config:        config,
		closed:        make(chan struct{}),
		handshakeDone: make(chan error, 1),
		onClose:       config.OnClose,
	}
	config.NetConn.Write = c.write
	c.Conn = netconn.New(config.NetConn)

	return c
}

// Start starts DTLS, registers its inbound datagram handler and writes its
// first flight, if any. It returns once DTLS waits for the peer; Handshake
// waits for the handshake to complete. Event processing continues after a
// successful handshake.
func (c *Conn) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.driveMu.Lock()
	err := c.config.DTLSConn.Start(ctx)
	c.driveMu.Unlock()
	if err != nil {
		return err
	}

	c.config.SetDatagramHandler(c.HandleDatagram)
	c.processReadyEvents(false)
	go c.processEvents()

	return nil
}

// Handshake waits until the handshake started by Start completes or fails.
func (c *Conn) Handshake() error {
	return <-c.handshakeDone
}

// HandleDatagram supplies one classified inbound DTLS datagram and processes
// the events it causes.
func (c *Conn) HandleDatagram(datagram []byte) error {
	c.driveMu.Lock()
	err := c.config.DTLSConn.HandleDatagram(datagram, c.RemoteAddr())
	c.driveMu.Unlock()
	c.processReadyEvents(false)

	return err
}

func (c *Conn) processEvents() {
	for {
		select {
		case <-c.closed:
			return
		case <-c.config.DTLSConn.EventReady():
		}

		c.processReadyEvents(false)
	}
}

// processReadyEvents processes the pending events. Their datagrams are written
// as application data if userData is true.
func (c *Conn) processReadyEvents(userData bool) {
	c.eventMu.Lock()
	closed := c.processReadyEventsLocked(userData)
	c.eventMu.Unlock()

	if closed {
		_ = c.close(false)
	}
}

func (c *Conn) processReadyEventsLocked(userData bool) bool {
	for {
		event := c.config.DTLSConn.NextEvent()
		if event.Kind == dtls.DetachedNoEvent {
			return false
		}
		if c.processEvent(event, userData) {
			return true
		}
	}
}

func (c *Conn) processEvent(event dtls.DetachedEvent, userData bool) bool { //nolint:cyclop
	var err error
	switch event.Kind {
	case dtls.DetachedNoEvent:
		return false
	case dtls.DetachedWriteDatagrams:
		err = c.writeDatagrams(event.Datagrams, userData)
	case dtls.DetachedApplicationData:
		if c.config.OnApplicationData != nil {
			c.config.OnApplicationData()
		}
		err = c.Push(event.Data)
	case dtls.DetachedHandshakeDone:
		if c.config.OnHandshakeDone != nil {
			c.config.OnHandshakeDone()
		}
		c.notifyHandshakeLocked(nil)

		return false
	case dtls.DetachedServerFinishedSent:
		if c.config.OnServerFinishedSent != nil {
			c.config.OnServerFinishedSent()
		}

		return false
	case dtls.DetachedClosed:
		c.notifyHandshakeLocked(event.Err)

		return true
	}
	if err != nil {
		c.notifyHandshakeLocked(err)
	}

	return err != nil
}

func (c *Conn) notifyHandshakeLocked(err error) {
	if !c.handshakeNotified {
		c.handshakeNotified = true
		c.handshakeDone <- err
	}
}

func (c *Conn) writeDatagrams(datagrams [][]byte, userData bool) error {
	if !userData && c.config.WriteFlight != nil {
		return c.config.WriteFlight(datagrams)
	}
	for _, datagram := range datagrams {
		if _, err := c.config.WriteDatagram(datagram); err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) write(p []byte) (int, error) {
	c.eventMu.Lock()
	c.driveMu.Lock()
	n, err := c.config.DTLSConn.Write(p)
	c.driveMu.Unlock()
	closed := c.processReadyEventsLocked(true)
	c.eventMu.Unlock()

	if closed {
		_ = c.close(false)
	}

	return n, err
}

// Close closes the DTLS connection, flushing any final datagrams such as a
// close_notify alert to the transport.
func (c *Conn) Close() error { return c.close(true) }

// CloseTransport closes the DTLS connection after its datagram transport has
// gone away, without trying to flush final datagrams to it.
func (c *Conn) CloseTransport() error { return c.close(false) }

// SetOnClose replaces the callback run when the connection closes.
func (c *Conn) SetOnClose(onClose func()) {
	c.onCloseMu.Lock()
	defer c.onCloseMu.Unlock()

	c.onClose = onClose
}

func (c *Conn) close(flushEvents bool) error {
	c.closeOnce.Do(func() {
		c.driveMu.Lock()
		dtlsErr := c.config.DTLSConn.Close()
		c.driveMu.Unlock()

		var flushErr error
		if flushEvents {
			flushErr = c.flushDatagrams()
		}
		c.config.SetDatagramHandler(nil)
		c.onCloseMu.Lock()
		onClose := c.onClose
		c.onCloseMu.Unlock()
		if onClose != nil {
			onClose()
		}
		c.closeErr = util.FlattenErrs([]error{dtlsErr, flushErr, c.Conn.Close()})
		c.eventMu.Lock()
		c.notifyHandshakeLocked(dtls.ErrConnClosed)
		c.eventMu.Unlock()
		close(c.closed)
	})

	return c.closeErr
}

func (c *Conn) flushDatagrams() error {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()

	var errs []error
	for event := c.config.DTLSConn.NextEvent(); event.Kind != dtls.DetachedNoEvent; event = c.config.DTLSConn.NextEvent() {
		if event.Kind != dtls.DetachedWriteDatagrams {
			continue
		}
		for _, datagram := range event.Datagrams {
			_, err := c.config.WriteDatagram(datagram)
			errs = append(errs, err)
		}
	}

	return util.FlattenErrs(errs)
}
