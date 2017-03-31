/* RPC with a pool of providers each connected via a web-socket. */
package wsrpcpool

// The pool server module

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"golang.org/x/net/websocket"
	"io/ioutil"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
)

/* PoolServer is used to listen on a set of web-socket URLs for RPC
providers. */
type PoolServer struct {
	Server http.Server
	// Provider name to call channel map
	PoolMap map[string]chan *rpc.Call
	// Default call channel
	DefaultPool chan *rpc.Call
	// Used to signal the pool is listening for incoming connections
	Listening <-chan struct{}
	// Used to signal the pool is listening for incoming connections (pool side)
	listening chan struct{}
	// Path to call channel map
	pathMap map[string]chan *rpc.Call
}

var (
	// ErrNoDefaultPool signals that provider isn't found and there is no default pool
	ErrNoDefaultPool = errors.New("No default path is bound")
	// ErrNoCertsParsed signals that no SSL certificates were found in the given file
	ErrNoCertsParsed = errors.New("No certificates parsed")
)

/* NewPool returns a plain PoolServer instance. */
func NewPool() *PoolServer {
	listening := make(chan struct{}, 1)
	return &PoolServer{
		Listening: listening,
		listening: listening,
	}
}

/* NewPoolTLS returns a PoolServer instance equipped with the given
SSL certificate. */
func NewPoolTLS(certfile, keyfile string) (*PoolServer, error) {
	pool := NewPool()
	if err := pool.AppendCertificate(certfile, keyfile); err != nil {
		return nil, err
	}
	return pool, nil
}

/* NewPoolTLSAuth returns a PoolServer instance equipped with the given
SSL certificate and a root CA certificates for client authentication. */
func NewPoolTLSAuth(certfile, keyfile string, clientCAs ...string) (*PoolServer, error) {
	pool, err := NewPoolTLS(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	err = pool.AppendClientCAs(clientCAs...)
	if err != nil {
		return nil, err
	}
	return pool, err
}

/* AppendCertificate appends an SSL certificate to the set of server
certificates loading it from the pair of public certificate and private
key files. */
func (pool *PoolServer) AppendCertificate(certfile, keyfile string) error {
	if pool.Server.TLSConfig == nil {
		pool.Server.TLSConfig = &tls.Config{}
	}
	return appendCertificate(pool.Server.TLSConfig, certfile, keyfile)
}

/* appendCertificate appends an SSL certificate to the given tls.Config
loading it from the pair of public certificate and private key files. */
func appendCertificate(tlsConfig *tls.Config, certfile, keyfile string) error {
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return err
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	tlsConfig.BuildNameToCertificate()
	return nil
}

/* AppendClientCAs appends the given SSL root CA certificate files to the
set of client CAs to verify client connections against. */
func (pool *PoolServer) AppendClientCAs(clientCAs ...string) error {
	if len(clientCAs) == 0 {
		return nil
	}
	if pool.Server.TLSConfig == nil {
		pool.Server.TLSConfig = &tls.Config{}
	}
	if pool.Server.TLSConfig.ClientCAs == nil {
		pool.Server.TLSConfig.ClientCAs = x509.NewCertPool()
	}
	err := appendCAs(pool.Server.TLSConfig.ClientCAs, clientCAs...)
	if err == nil {
		pool.Server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return err
}

/* appendCAs appends the given SSL root CA certificate files to the
given CA pool. */
func appendCAs(caPool *x509.CertPool, caCerts ...string) error {
	for _, caFile := range caCerts {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return err
		}
		if !caPool.AppendCertsFromPEM(caCert) {
			return ErrNoCertsParsed
		}
	}
	return nil
}

/* invoke passes the given call to the client. */
func invoke(client *rpc.Client, call *rpc.Call) *rpc.Call {
	return client.Go(call.ServiceMethod, call.Args, call.Reply, call.Done)
}

/* connObserver used to observe I/O errors in a websocket connection */
type connObserver struct {
	*websocket.Conn
	ioError chan error
}

/* reportError sends the given error over the ioError channel
if there is a free slot available and do nothing otherwise
(i.e. non blocking). */
func (conn *connObserver) reportError(err error) {
	select {
	case conn.ioError <- err:
	default:
	}
}

/* Read implements io.Reader. */
func (conn *connObserver) Read(p []byte) (n int, err error) {
	n, err = conn.Conn.Read(p)
	if err != nil {
		conn.reportError(err)
	}
	return
}

/* Write implements io.Writer. */
func (conn *connObserver) Write(p []byte) (n int, err error) {
	n, err = conn.Conn.Write(p)
	if err != nil {
		conn.reportError(err)
	}
	return
}

/* handle returns the websocket.Handler that the passes calls from the
given channel over a websocket connection. In the case of I/O error
it is written to errOut channel if it is provided and the function
returns. The function also returns if callIn channel is closed.
No error is sent in that case. The errOut, if provied, is anyway
closed on return. */
func handle(callIn <-chan *rpc.Call, errOut chan<- error) websocket.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		conn := &connObserver{ws, make(chan error, 10)}
		client := jsonrpc.NewClient(conn)
	loop:
		for {
			select {
			case c, ok := <-callIn:
				if !ok {
					break loop
				}
				invoke(client, c)
			case err := <-conn.ioError:
				if errOut != nil {
					errOut <- err
				}
				break loop
			}
		}
		if errOut != nil {
			close(errOut)
		}
		client.Close()
	})
}

/* assertMux checks for pool.Server.Handler mux and makes
one if it doesn't yet exist. */
func (pool *PoolServer) assertMux() *http.ServeMux {
	if pool.Server.Handler == nil {
		pool.Server.Handler = http.NewServeMux()
	}
	return pool.Server.Handler.(*http.ServeMux)
}

/* Bind associates the given path with the set of remote providers or
makes it the default path if no object provider names given. */
func (pool *PoolServer) Bind(path string, providers ...string) {
	mux := pool.assertMux()
	if pool.pathMap == nil {
		pool.pathMap = make(map[string]chan *rpc.Call)
	}
	callIn := pool.pathMap[path]
	if callIn == nil {
		callIn = make(chan *rpc.Call)
		pool.pathMap[path] = callIn
	}
	if len(providers) > 0 {
		if pool.PoolMap == nil {
			pool.PoolMap = make(map[string]chan *rpc.Call)
		}
		for _, name := range providers {
			pool.PoolMap[name] = callIn
		}
	} else {
		pool.DefaultPool = callIn
	}
	mux.Handle(path, handle(callIn, nil))
}

/* handleIn returns the websocket.Handler that the serves
incoming RPC calls over a websocket connection. */
func handleIn() websocket.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		jsonrpc.ServeConn(ws)
	})
}

/* BindIn handles incoming RPC calls on the given path. */
func (pool *PoolServer) BindIn(path string, providers ...string) {
	mux := pool.assertMux()
	mux.Handle(path, handleIn())
}

/* listen returns the active listener for the current pool config
and an error if any. It also send a signal over the "listening"
channel. */
func (pool *PoolServer) listen(addr string) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	select {
	case pool.listening <- struct{}{}:
	default:
	}
	return l, nil
}

/* use uses the given listener waiting for a signal on
the "stop" channel. */
func (pool *PoolServer) use(l net.Listener) error {
	return pool.Server.Serve(l)
}

/* ListenAndUse listens the given (or configured if "" is given) address
([host]:port) with no SSL encryption. */
func (pool *PoolServer) ListenAndUse(addr string) error {
	if addr == "" {
		addr = pool.Server.Addr
	}
	l, err := pool.listen(addr)
	if err != nil {
		return err
	}
	return pool.use(l)
}

/* ListenAndUseTLS listens the listens the given (or configured if ""
is given) address ([host]:port) with SSL encryption on. */
func (pool *PoolServer) ListenAndUseTLS(addr string) error {
	if addr == "" {
		addr = pool.Server.Addr
	}
	l, err := pool.listen(addr)
	if err != nil {
		return err
	}
	return pool.use(tls.NewListener(l, pool.Server.TLSConfig))
}

/* Close closes the pool listener. */
func (pool *PoolServer) Close() error {
	return pool.Server.Close()
}

/* Go invokes the given remote function asynchronously. The name of the
provider (if given as the first part of serviceMethod, i.e. "Provider.Function")
is first searched in the PoolMap and the DefaultPool is used if it isn't there
(or isn't specified). If "done" is nil, a new channel is allocated and passed in
the return value. See net/rpc package for details. */
func (pool *PoolServer) Go(serviceMethod string, args interface{}, reply interface{}, done chan *rpc.Call) (*rpc.Call, error) {
	var callIn chan *rpc.Call
	if split := strings.SplitN(serviceMethod, ".", 2); len(split) > 1 {
		callIn = pool.PoolMap[split[0]]
	}
	if callIn == nil {
		callIn = pool.DefaultPool
	}
	if callIn == nil {
		return nil, ErrNoDefaultPool
	}

	call := &rpc.Call{
		ServiceMethod: serviceMethod,
		Args:          args,
		Reply:         reply,
	}
	if done == nil {
		done = make(chan *rpc.Call, 1)
	}
	call.Done = done

	callIn <- call
	return call, nil
}

/* Call invokes the given remote function and waits for it to complete,
returning its error status. */
func (pool *PoolServer) Call(serviceMethod string, args interface{}, reply interface{}) error {
	if call, err := pool.Go(serviceMethod, args, reply, nil); err == nil {
		call = <-call.Done
		return call.Error
	} else {
		return err
	}
}
