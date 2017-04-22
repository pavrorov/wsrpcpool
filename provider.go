package wsrpcpool

// The RPC provider module

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/rpc"
	"time"
)

var (
	// DefaultDelay is the default delay between pool server re-connections. The default value is 100s.
	DefaultDelay = 100 * time.Millisecond
	// DefaultOrigin is the default origin URL for a Provider
	DefaultOrigin string = "http://localhost/"
	// DefaultPingInterval defines the default period of Ping requests -- 5s.
	DefaultPingInterval = 5 * time.Second
	// DefaultMaxPings defines the default value for maximum unanswered Ping requests -- 2
	DefaultMaxPings = 2
)

/*
Provider is intended to connect to a PoolServer and handle RPC calls.
*/
type Provider struct {
	// TLS configuration shared by all pool connections instantiated from this provider
	TlsConfig tls.Config
	// Maximum number of connection attempts. Default is unlimited.
	MaxAttempts int
	// The delay between reconnections. The default is DefaultReconnectDelay (100ms).
	Delay time.Duration
	// Origin URL used for all connections
	Origin string
	// PingInterval defines the period of Ping requests. Set 0 to disable pings.
	PingInterval time.Duration
	// MaxPings defines the value for maximum unanswered Ping requests
	MaxPings int
}

/*
PoolConn represents a signle pool connection that handles
RPC requests coming from a pool server.
*/
type PoolConn struct {
	// Error channel
	Error <-chan error
	// "Connected" signal channel
	Connected <-chan struct{}
	// "Disconnected" signal channel
	Disconnected <-chan struct{}
	// Closed signal channel
	Closed <-chan struct{}
	// Used to close the connection
	stop chan struct{}
}

/*
PoolCallerConn represents a signle connection that is
used to send RPC calls *to* the pool.
*/
type PoolCallerConn struct {
	*PoolConn
	// Call channel
	Calls chan *rpc.Call
}

/*
NewProvider returns a new plain Provider instance with no SSL client-side
certificate authentication. The optional set of root CAs, if any, are used
to validate the pool server certificate when wss:// URL scheme is used.
*/
func NewProvider(rootCAs ...string) (*Provider, error) {
	p := &Provider{
		Origin: DefaultOrigin,
		Delay: DefaultDelay,
		PingInterval: DefaultPingInterval,
		MaxPings: DefaultMaxPings,
	}
	if err := p.AppendRootCAs(rootCAs...); err != nil {
		return nil, err
	}
	return p, nil
}

/*
NewProviderTLS returns a new Provider instance equipped with the given
SSL certificate to authenticate itself with the pool server and an optional
set of root CAs to validate the pool server certificate.
*/
func NewProviderTLSAuth(certfile, keyfile string, rootCAs ...string) (*Provider, error) {
	p, err := NewProvider()
	if err == nil {
		if err := p.AppendCertificate(certfile, keyfile); err != nil {
			return nil, err
		}
		if err := p.AppendRootCAs(rootCAs...); err != nil {
			return nil, err
		}
		return p, nil
	} else {
		return nil, err
	}
}

/*
AppendCertificate appends an SSL certificate to the set of provider
certificates loading it from the pair of public certificate and private
key files.
*/
func (p *Provider) AppendCertificate(certfile, keyfile string) error {
	return appendCertificate(&p.TlsConfig, certfile, keyfile)
}

/*
AppendRootCAs appends the given SSL root CA certificate files to the
set of ones that are used to validate the pool server certificate.
*/
func (p *Provider) AppendRootCAs(rootCAs ...string) error {
	if len(rootCAs) == 0 {
		return nil
	}
	if p.TlsConfig.RootCAs == nil {
		p.TlsConfig.RootCAs = x509.NewCertPool()
	}
	return appendCAs(p.TlsConfig.RootCAs, rootCAs...)
}

/*
ConnectAndServe connects to the pool at the given URL
and asynchronously handles incoming RPC messages with
rpc.ServeConn(). The connection is automatically re-established
when broken until MaxAttempts is exceeded. Don't forget to call
rpc.Register() with your exported objects.
*/
func (p *Provider) ConnectAndServe(url string) (*PoolConn, error) {
	return p.ConnectAndServeWith(url, rpc.ServeConn)
}

/*
ConnectAndServeWith connects to the pool at the given
URL and asynchronously handles incoming RPC messages
with the specified handler. The connection is automatically
re-established when broken until MaxAttempts is exceeded.
Don't forget to call rpc.Register() with your exported objects.
*/
func (p *Provider) ConnectAndServeWith(url string, serveConn func(conn io.ReadWriteCloser)) (*PoolConn, error) {
	return p.connect(url, serveConn, nil, nil)
}

/*
ConnectAndUse connects to the pool at the given URL
to send RPC calls *to* the pool using rpc.NewClient().
The connection is automatically re-established when broken
until MaxAttempts is exceeded. See PoolServer.BindIn()
method for more information.
*/
func (p *Provider) ConnectAndUse(url string) (*PoolCallerConn, error) {
	return p.ConnectAndUseWith(url, rpc.NewClient)
}

/*
ConnectAndUseWith connects to the pool at the given URL
to send RPC calls *to* the pool using the specified client.
The connection is automatically re-established when broken
until MaxAttempts is exceeded. See PoolServer.BindIn()
method for more information.
*/
func (p *Provider) ConnectAndUseWith(url string, newClient func(conn io.ReadWriteCloser) *rpc.Client) (*PoolCallerConn, error) {
	calls := make(chan *rpc.Call)
	if pc, err := p.connect(url, nil, newClient, calls); err != nil {
		return nil, err
	} else {
		return &PoolCallerConn{pc, calls}, nil
	}
}

/*
connect returns the new active pool connection that automatically
re-established when broken until provider's MaxAttempts value is
exceeded.
*/
func (p *Provider) connect(url string, serveConn func(conn io.ReadWriteCloser), newClient func(conn io.ReadWriteCloser) *rpc.Client, callIn <-chan *rpc.Call) (*PoolConn, error) {
	var (
		pc       PoolConn
		attempts int
	)

	pc.stop = make(chan struct{})
	closed := make(chan struct{})
	pc.Closed = closed
	errc := make(chan error, 1)
	pc.Error = errc
	connected := make(chan struct{}, 1)
	pc.Connected = connected
	disconnected := make(chan struct{}, 1)
	pc.Disconnected = disconnected

	if p.MaxAttempts < 0 {
		close(pc.stop)
		errc <- nil
		close(errc)
		return &pc, nil
	}

	origin := p.Origin
	if origin == "" {
		origin = DefaultOrigin
	}
	header := http.Header{"Origin": {origin}}
	dialer := &websocket.Dialer{
		TLSClientConfig: &p.TlsConfig,
	}

	go func() {
		var err error
	loop:
		for {
			var ws *websocket.Conn
			ws, _, err = dialer.Dial(url, header)
			attempts++

			var _break bool
			if err == nil {
				select {
				case connected <- struct{}{}:
				default:
				}
				
				if callIn != nil {
					errOut := make(chan error)
					invoker(newClient, callIn, errOut)(ws)
					if err = <-errOut; err == nil {
						_break = true // callIn is closed
					}
				} else {
					done := make(chan struct{})
					NewPingPong(ws, p.PingInterval, p.MaxPings, nil)
					go func() {
						select {
						case <-done:
						case <-pc.stop:
							ws.Close()
							_break = true
						}
					}()
					serveConn(wrapConn(ws))
					close(done)
				}

				select {
				case disconnected <- struct{}{}:
				default:
				}
			}

			if _break {
				break loop
			}

			if attempts < p.MaxAttempts || p.MaxAttempts == 0 {
				delay := p.Delay
				if delay == 0 {
					delay = DefaultDelay
				}
				if delay > 0 {
					time.Sleep(delay)
				}
			} else {
				break loop
			}
		}

		errc <- err
		close(errc)
		close(closed)
	}()

	return &pc, nil
}

/*
ConnectAndServeMulti asynchronously runs the given number of
simultaneous connections using ConnectAndServe().
*/
func (p *Provider) ConnectAndServeMulti(url string, count int) ([]*PoolConn, error) {
	conns := make([]*PoolConn, count, count)
	for n := 0; n < count; n++ {
		if conn, err := p.ConnectAndServe(url); err != nil {
			return conns, err
		} else {
			conns = append(conns, conn)
		}
	}
	return conns, nil
}

/*
ConnectAndServeMultiWith asynchronously runs the given number of
simultaneous connections using ConnectAndServeWith().
*/
func (p *Provider) ConnectAndServeMultiWith(url string, serveConn func(conn io.ReadWriteCloser), count int) ([]*PoolConn, error) {
	conns := make([]*PoolConn, count, count)
	for n := 0; n < count; n++ {
		if conn, err := p.ConnectAndServeWith(url, serveConn); err != nil {
			return conns, err
		} else {
			conns = append(conns, conn)
		}
	}
	return conns, nil
}

/*
Close closes the connection and returns the last unread error
from pc.Error.
*/
func (pc *PoolConn) Close() error {
	close(pc.stop)
	return <-pc.Error
}

/*
Go invokes the given remote function *on the pool server* asynchronously.
For Go RPC providers the name of the function should be of the form
"Service.Method" -- same as in the package net/rpc. If "done" is nil,
a new channel is allocated and passed in the return value. See net/rpc
package for details.
*/
func (pcc *PoolCallerConn) Go(serviceMethod string, args interface{}, reply interface{}, done chan *rpc.Call) (*rpc.Call, error) {
	call := &rpc.Call{
		ServiceMethod: serviceMethod,
		Args:          args,
		Reply:         reply,
	}
	if done == nil {
		done = make(chan *rpc.Call, 1)
	}
	call.Done = done

	pcc.Calls <- call
	return call, nil
}

/*
Call invokes the given remote function *on the pool server* and waits for
it to complete, returning its error status. For Go RPC providers the name
of the function should be of the form "Service.Method" -- same as in the
package net/rpc.
*/
func (pcc *PoolCallerConn) Call(serviceMethod string, args interface{}, reply interface{}) error {
	if call, err := pcc.Go(serviceMethod, args, reply, nil); err == nil {
		call = <-call.Done
		return call.Error
	} else {
		return err
	}
}

/*
Close closes the caller connection and returns the last unread
error from pcc.Error.
*/
func (pcc *PoolCallerConn) Close() error {
	close(pcc.Calls)
	return pcc.PoolConn.Close()
}
