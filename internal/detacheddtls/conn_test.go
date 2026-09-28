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
			started := make(chan error, 1)
			go func() { started <- server.Start(ctx) }()
			require.NoError(t, client.Start(ctx))
			require.NoError(t, <-started)

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

	started := make(chan error, 1)
	go func() { started <- conn.Start(context.Background()) }()
	require.Eventually(t, func() bool {
		end.mu.Lock()
		defer end.mu.Unlock()

		return end.handler != nil
	}, 5*time.Second, time.Millisecond)

	assert.NoError(t, conn.CloseTransport())
	assert.Error(t, <-started)
	select {
	case <-closed:
		assert.Fail(t, "OnClose must not run after SetOnClose(nil)")
	default:
	}
	// Close after CloseTransport is a no-op.
	assert.NoError(t, conn.Close())
}
