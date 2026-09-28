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
	DTLSConn           *dtls.DetachedConn
	WriteDatagram      func([]byte) (int, error)
	SetDatagramHandler func(func([]byte) error)
	NetConn            netconn.Config
	OnClose            func()
}

// Conn pumps a DetachedConn and exposes only its plaintext application data as
// net.Conn for SCTP.
type Conn struct {
	*netconn.Conn

	config Config

	driveMu   sync.Mutex
	eventMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}

	onCloseMu sync.Mutex
	onClose   func()
}

type handshakeNotifier struct {
	done chan<- error
}

func (n *handshakeNotifier) notify(err error) {
	if n.done != nil {
		n.done <- err
		n.done = nil
	}
}

// New creates a detached DTLS application-data connection.
func New(config Config) *Conn {
	c := &Conn{
		config:  config,
		closed:  make(chan struct{}),
		onClose: config.OnClose,
	}
	config.NetConn.Write = c.write
	c.Conn = netconn.New(config.NetConn)

	return c
}

// Start starts DTLS, registers its inbound datagram handler, and processes
// events until the handshake completes or fails. Event processing continues
// after a successful handshake.
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
	handshakeDone := make(chan error, 1)
	go c.processEvents(handshakeDone)

	return <-handshakeDone
}

// HandleDatagram supplies one classified inbound DTLS datagram.
func (c *Conn) HandleDatagram(datagram []byte) error {
	c.driveMu.Lock()
	defer c.driveMu.Unlock()

	return c.config.DTLSConn.HandleDatagram(datagram, c.RemoteAddr())
}

func (c *Conn) processEvents(handshakeDone chan<- error) {
	notifier := handshakeNotifier{done: handshakeDone}

	for {
		select {
		case <-c.closed:
			notifier.notify(dtls.ErrConnClosed)

			return
		case <-c.config.DTLSConn.EventReady():
		}

		if c.processReadyEvents(&notifier) {
			_ = c.close(false)

			return
		}
	}
}

func (c *Conn) processReadyEvents(notifier *handshakeNotifier) bool {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()

	for {
		event := c.config.DTLSConn.NextEvent()
		if event.Kind == dtls.DetachedNoEvent {
			return false
		}
		if c.processEvent(event, notifier) {
			return true
		}
	}
}

func (c *Conn) processEvent(event dtls.DetachedEvent, notifier *handshakeNotifier) bool {
	var err error
	switch event.Kind {
	case dtls.DetachedNoEvent:
		return false
	case dtls.DetachedWriteDatagrams:
		err = c.writeDatagrams(event.Datagrams)
	case dtls.DetachedApplicationData:
		err = c.Push(event.Data)
	case dtls.DetachedHandshakeDone:
		notifier.notify(nil)

		return false
	case dtls.DetachedClosed:
		notifier.notify(event.Err)

		return true
	}
	if err != nil {
		notifier.notify(err)
	}

	return err != nil
}

func (c *Conn) writeDatagrams(datagrams [][]byte) error {
	for _, datagram := range datagrams {
		if _, err := c.config.WriteDatagram(datagram); err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) write(p []byte) (int, error) {
	c.driveMu.Lock()
	defer c.driveMu.Unlock()

	return c.config.DTLSConn.Write(p)
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
