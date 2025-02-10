// TINYGO: The following is copied and modified from Go 1.21.4 official implementation.

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS low level connection and record layer

package tls

import (
	"internal/itoa"
	"io"
	"net"
	"strconv"
	"time"
)

// TLSAddr represents the address of a TLS end point.
type TLSAddr struct {
	Host string
	Port int
}

func (a *TLSAddr) Network() string { return "tls" }

func (a *TLSAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	return net.JoinHostPort(a.Host, itoa.Itoa(a.Port))
}

// A TLSConn represents a secured connection.
// It implements the net.Conn interface.
type TLSConn struct {
	fd            int
	net           string
	laddr         *TLSAddr
	raddr         *TLSAddr
	readDeadline  time.Time
	writeDeadline time.Time
}

func DialTLS(addr string) (*TLSConn, error) {

	host, sport, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}

	if port == 0 {
		port = 443
	}

	fd, err := net.DialTLS(host, port)
	if err != nil {
		return nil, err
	}

	return &TLSConn{
		fd:    fd,
		net:   "tls",
		raddr: &TLSAddr{host, port},
	}, nil
}

func (c *TLSConn) Read(b []byte) (int, error) {
	n, err := net.Read(c.fd, c.readDeadline, b)
	// Turn the -1 socket error into 0 and let err speak for error
	if n < 0 {
		n = 0
	}
	if err != nil && err != io.EOF {
		err = &net.OpError{Op: "read", Net: c.net, Source: c.laddr, Addr: c.raddr, Err: err}
	}
	return n, err
}

func (c *TLSConn) Write(b []byte) (int, error) {
	n, err := net.Write(c.fd, c.writeDeadline, b)
	// Turn the -1 socket error into 0 and let err speak for error
	if n < 0 {
		n = 0
	}
	if err != nil {
		err = &net.OpError{Op: "write", Net: c.net, Source: c.laddr, Addr: c.raddr, Err: err}
	}
	return n, err
}

func (c *TLSConn) Close() error {
	return net.Close(c.fd)
}

func (c *TLSConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *TLSConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *TLSConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *TLSConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *TLSConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
//
// Most uses of this package need not call Handshake explicitly: the
// first Read or Write will call it automatically.
//
// For control over canceling or setting a timeout on a handshake, use
// HandshakeContext or the Dialer's DialContext method instead.
func (c *TLSConn) Handshake() error {
	panic("TLSConn.Handshake() not implemented")
	return nil
}

// ConnectionState returns basic TLS details about the connection.
func (c *TLSConn) ConnectionState() ConnectionState {
	panic("TLSConn.ConnectionState() not implemented")
	return ConnectionState{}
}
