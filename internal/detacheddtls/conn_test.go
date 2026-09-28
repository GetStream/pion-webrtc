// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package detacheddtls

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/transport/v5/test"
	"github.com/pion/webrtc/v4/internal/netconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeEnd delivers datagrams to the peer's handler, like ICETransport does.
type pipeEnd struct {
	mu      sync.Mutex
	handler func([]byte) error
	peer    *pipeEnd
}

func (p *pipeEnd) setHandler(handler func([]byte) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = handler
}

func (p *pipeEnd) write(datagram []byte) (int, error) {
	p.peer.mu.Lock()
	handler := p.peer.handler
	p.peer.mu.Unlock()
	if handler != nil {
		// Deliver asynchronously: the sender's event loop must not run the receiver.
		packet := append([]byte(nil), datagram...)
		go func() { _ = handler(packet) }()
	}

	return len(datagram), nil
}

func newTestConn(t *testing.T, end *pipeEnd, isClient bool, maxVersion protocol.Version) (*Conn, chan struct{}) {
	t.Helper()

	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	opts := []dtls.Option{
		dtls.WithCertificates(cert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMaxVersion(maxVersion),
	}

	var dtlsConn *dtls.DetachedConn
	if isClient {
		clientOpts := make([]dtls.ClientOption, 0, len(opts))
		for _, opt := range opts {
			clientOpts = append(clientOpts, opt)
		}
		dtlsConn, err = dtls.DetachedClient(addr, clientOpts...)
	} else {
		serverOpts := make([]dtls.ServerOption, 0, len(opts)+1)
		for _, opt := range opts {
			serverOpts = append(serverOpts, opt)
		}
		serverOpts = append(serverOpts, dtls.WithClientAuth(dtls.RequireAnyClientCert))
		dtlsConn, err = dtls.DetachedServer(addr, serverOpts...)
	}
	require.NoError(t, err)

	closed := make(chan struct{})
	conn := New(Config{
		DTLSConn:           dtlsConn,
		WriteDatagram:      end.write,
		SetDatagramHandler: end.setHandler,
		NetConn: netconn.Config{
			LocalAddr:        func() net.Addr { return addr },
			RemoteAddr:       func() net.Addr { return addr },
			SetWriteDeadline: func(time.Time) error { return nil },
		},
		OnClose: func() { close(closed) },
	})

	return conn, closed
}

func TestConn(t *testing.T) {
	for name, version := range map[string]protocol.Version{"DTLS1.2": protocol.Version1_2, "DTLS1.3": protocol.Version1_3} {
		t.Run(name, func(t *testing.T) {
			lim := test.TimeOut(10 * time.Second)
			defer lim.Stop()

			report := test.CheckRoutines(t)
			defer report()

			clientEnd, serverEnd := &pipeEnd{}, &pipeEnd{}
			clientEnd.peer, serverEnd.peer = serverEnd, clientEnd

			client, clientClosed := newTestConn(t, clientEnd, true, version)
			server, serverClosed := newTestConn(t, serverEnd, false, version)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, server.Start(ctx))
			require.NoError(t, client.Start(ctx))
			require.NoError(t, client.Handshake())
			require.NoError(t, server.Handshake())

			state, ok := client.config.DTLSConn.ConnectionState()
			require.True(t, ok)
			assert.Equal(t, version, state.NegotiatedVersion())

			_, err := client.Write([]byte("hello"))
			require.NoError(t, err)
			buf := make([]byte, 16)
			require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
			n, err := server.Read(buf)
			require.NoError(t, err)
			assert.Equal(t, "hello", string(buf[:n]))

			// Closing one side sends close_notify, which closes the other.
			require.NoError(t, client.Close())
			<-clientClosed
			<-serverClosed
			assert.NoError(t, server.Close())
		})
	}
}

func TestConn_CloseTransportInterruptsHandshake(t *testing.T) {
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// The peer never answers, so the handshake stays in flight.
	end := &pipeEnd{peer: &pipeEnd{}}
	conn, closed := newTestConn(t, end, true, protocol.Version1_3)
	conn.SetOnClose(nil)

	require.NoError(t, conn.Start(context.Background()))
	end.mu.Lock()
	assert.NotNil(t, end.handler)
	end.mu.Unlock()

	assert.NoError(t, conn.CloseTransport())
	assert.Error(t, conn.Handshake())
	select {
	case <-closed:
		assert.Fail(t, "OnClose must not run after SetOnClose(nil)")
	default:
	}
	// Close after CloseTransport is a no-op.
	assert.NoError(t, conn.Close())
}

// TestConn_EventsProcessedByTheirCaller checks that the datagrams a call makes
// DTLS produce are written before the call returns: a handshake flight through
// WriteFlight, application data written to the Conn through WriteDatagram.
func TestConn_EventsProcessedByTheirCaller(t *testing.T) {
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	client, err := dtls.DetachedClient(addr, dtls.WithInsecureSkipVerify(true))
	require.NoError(t, err)
	server, err := dtls.DetachedServer(addr, dtls.WithCertificates(cert), dtls.WithInsecureSkipVerifyHello(true))
	require.NoError(t, err)

	type end struct {
		conn                  *Conn
		mu                    sync.Mutex
		flights, applications [][]byte
		handshakeDone         bool
	}
	newEnd := func(dtlsConn *dtls.DetachedConn) *end {
		peer := &end{}
		peer.conn = New(Config{
			DTLSConn: dtlsConn,
			WriteDatagram: func(datagram []byte) (int, error) {
				peer.mu.Lock()
				defer peer.mu.Unlock()
				peer.applications = append(peer.applications, append([]byte(nil), datagram...))

				return len(datagram), nil
			},
			WriteFlight: func(flight [][]byte) error {
				peer.mu.Lock()
				defer peer.mu.Unlock()
				for _, datagram := range flight {
					peer.flights = append(peer.flights, append([]byte(nil), datagram...))
				}

				return nil
			},
			SetDatagramHandler: func(func([]byte) error) {},
			OnHandshakeDone: func() {
				peer.mu.Lock()
				defer peer.mu.Unlock()
				peer.handshakeDone = true
			},
			NetConn: netconn.Config{
				LocalAddr:        func() net.Addr { return addr },
				RemoteAddr:       func() net.Addr { return addr },
				SetWriteDeadline: func(time.Time) error { return nil },
			},
		})

		return peer
	}
	clientEnd, serverEnd := newEnd(client), newEnd(server)
	defer func() {
		assert.NoError(t, clientEnd.conn.CloseTransport())
		assert.NoError(t, serverEnd.conn.CloseTransport())
	}()
	// take returns and clears what e wrote, without waiting.
	take := func(e *end) (flights, applications [][]byte) {
		e.mu.Lock()
		defer e.mu.Unlock()
		flights, applications = e.flights, e.applications
		e.flights, e.applications = nil, nil

		return flights, applications
	}

	ctx := context.Background()
	require.NoError(t, serverEnd.conn.Start(ctx))
	require.NoError(t, clientEnd.conn.Start(ctx))
	for exchanged := 0; ; exchanged++ {
		require.Less(t, exchanged, 10, "handshake did not complete")
		clientFlights, _ := take(clientEnd)
		for _, datagram := range clientFlights {
			require.NoError(t, serverEnd.conn.HandleDatagram(datagram))
		}
		serverFlights, _ := take(serverEnd)
		for _, datagram := range serverFlights {
			require.NoError(t, clientEnd.conn.HandleDatagram(datagram))
		}
		if len(clientFlights) == 0 && len(serverFlights) == 0 {
			break
		}
	}
	require.NoError(t, clientEnd.conn.Handshake())
	require.NoError(t, serverEnd.conn.Handshake())
	for _, e := range []*end{clientEnd, serverEnd} {
		e.mu.Lock()
		assert.True(t, e.handshakeDone)
		e.mu.Unlock()
	}

	_, err = clientEnd.conn.Write([]byte("hello"))
	require.NoError(t, err)
	flights, applications := take(clientEnd)
	assert.Empty(t, flights)
	require.Len(t, applications, 1)
	require.NoError(t, serverEnd.conn.HandleDatagram(applications[0]))
	buf := make([]byte, 16)
	require.NoError(t, serverEnd.conn.SetReadDeadline(time.Now().Add(time.Second)))
	n, err := serverEnd.conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
}
