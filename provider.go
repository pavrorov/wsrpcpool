package wsrpcpool

// The RPC provider module

import (
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/net/websocket"
	"net/rpc"
	"net/rpc/jsonrpc"
	"time"
)

var (
	/* DefaultDelay is the default delay between pool
	server re-connections. The default value is 100s.*/
	DefaultDelay = 100 * time.Millisecond
)

/* Provider is intended to connect to a PoolServer and handle RPC calls. */
type Provider struct {
	Config *websocket.Config
	// Maximum number of connection attempts. Default is unlimited.*/
	MaxAttempts int
	// The delay between reconnections. The default is DefaultReconnectDelay (100ms).
	Delay time.Duration
}

/* PoolConn represents a signle pool connection that handles
RPC requests coming from a pool server. */
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

/* PoolCallerConn represents a signle connection that is
used to send RPC calls *to* the pool. */
type PoolCallerConn struct {
	*PoolConn
	// Call channel
	Calls chan *rpc.Call
}

/* NewProvider returns a new Provider instance tuned to the given pool URL
with no SSL client-side certificate authentication. The optional set of
root CAs, if any, are used to validate the pool server certificate in the
case wss:// URL is used. */
func NewProvider(url string, rootCAs ...string) (*Provider, error) {
	conf, err := websocket.NewConfig(url, "http://localhost/")
	if err != nil {
		return nil, err
	} else {
		p := &Provider{Config: conf}
		if err := p.AppendRootCAs(rootCAs...); err != nil {
			return nil, err
		}
		return p, nil
	}
}

/* NewProviderTLS returns a Provider instance equipped with the given
SSL certificate to authenticate itself with the pool server and an optional
set of root CAs to validate the pool server certificate. */
func NewProviderTLSAuth(url, certfile, keyfile string, rootCAs ...string) (*Provider, error) {
	p, err := NewProvider(url)
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

/* AppendCertificate appends an SSL certificate to the set of provider
certificates loading it from the pair of public certificate and private
key files. */
func (p *Provider) AppendCertificate(certfile, keyfile string) error {
	if p.Config.TlsConfig == nil {
		p.Config.TlsConfig = &tls.Config{}
	}
	return appendCertificate(p.Config.TlsConfig, certfile, keyfile)
}

/* AppendRootCAs appends the given SSL root CA certificate files to the
set of ones that are used to validate the pool server certificate. */
func (p *Provider) AppendRootCAs(rootCAs ...string) error {
	if len(rootCAs) == 0 {
		return nil
	}
	if p.Config.TlsConfig == nil {
		p.Config.TlsConfig = &tls.Config{}
	}
	if p.Config.TlsConfig.RootCAs == nil {
		p.Config.TlsConfig.RootCAs = x509.NewCertPool()
	}
	return appendCAs(p.Config.TlsConfig.RootCAs, rootCAs...)
}

/*
ConnectAndServe connects to the configured server pool URL
and asynchronously handles incoming JSON-RPC messages.
The connection is automatically re-established when broken
until MaxAttempts is exceeded.
Don't forget to call rpc.Register() with your exported objects.
*/
func (p *Provider) ConnectAndServe() *PoolConn {
	return p.connect(nil)
}

/*
ConnectAndUse connects to the configured server pool URL
to send RPC calls *to* the pool with JSON-RPC messages.
The connection is automatically re-established when broken
until MaxAttempts is exceeded. See PoolServer.BindIn()
method for more information.
*/
func (p *Provider) ConnectAndUse() *PoolCallerConn {
	calls := make(chan *rpc.Call)
	pc := p.connect(calls)
	return &PoolCallerConn{pc, calls}
}

func (p *Provider) connect(callIn <-chan *rpc.Call) *PoolConn {
	var (
		ws       *websocket.Conn
		pc       PoolConn
		err      error
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
		return &pc
	}

	go func() {
	loop:
		for {
			ws, err = websocket.DialConfig(p.Config)
			attempts++

			var _break bool
			if err == nil {
				select {
				case connected <- struct{}{}:
				default:
				}
				if callIn != nil {
					errOut := make(chan error)
					invoker(callIn, errOut)(ws)
					if err := <- errOut; err == nil {
						_break = true // callIn is closed
					}
				} else {
					done := make(chan struct{})
					go func() {
						select {
						case <-done:
						case <-pc.stop:
							ws.Close()
						}
					}()
					jsonrpc.ServeConn(ws)
					close(done)
				}
			}

			select {
			case disconnected <- struct{}{}:
			default:
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

	return &pc
}

/* ConnectAndServeMulti asynchronously runs the given number of
simultaneous connections using ConnectAndServe(). */
func (p *Provider) ConnectAndServeMulti(count int) []*PoolConn {
	cons := make([]*PoolConn, count, count)
	for n := 0; n < count; n++ {
		cons = append(cons, p.ConnectAndServe())
	}
	return cons
}

/* Close closes the connection and returns the last unread error
from pc.Error. */
func (pc *PoolConn) Close() error {
	close(pc.stop)
	return <-pc.Error
}

/* Go invokes the given remote function *on the pool server* asynchronously.
The name of the function should be "Service.Method" same, as in the package
net/rpc. If "done" is nil, a new channel is allocated and passed in the return
value. See net/rpc package for details. */
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

/* Call invokes the given remote function *on the pool server* and waits for it to
complete, returning its error status. */
func (pcc *PoolCallerConn) Call(serviceMethod string, args interface{}, reply interface{}) error {
	if call, err := pcc.Go(serviceMethod, args, reply, nil); err == nil {
		call = <-call.Done
		return call.Error
	} else {
		return err
	}
}

/* Close closes the caller connection and returns the last unread
error from pcc.Error. */
func (pcc *PoolCallerConn) Close() error {
	close(pcc.Calls)
	return pcc.PoolConn.Close()
}
