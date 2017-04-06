/*
RPC with a pool of providers each connected via a web-socket.
*/
package wsrpcpool

// The pool server module

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"golang.org/x/net/websocket"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/rpc"
	"strings"
	"sync"
)

/*
PoolServer is used to listen on a set of web-socket URLs for RPC
providers.
*/
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
	// Closer list used in Close()
	cList []io.Closer
	// Pool mutex
	lock *sync.RWMutex
}

var (
	// ErrNoDefaultPool signals that provider isn't found and there is no default pool
	ErrNoDefaultPool = errors.New("No default path is bound")
	// ErrNoCertsParsed signals that no SSL certificates were found in the given file
	ErrNoCertsParsed = errors.New("No certificates parsed")
)

/*
NewPool returns a plain PoolServer instance.
*/
func NewPool() *PoolServer {
	listening := make(chan struct{}, 1)
	return &PoolServer{
		Listening: listening,
		listening: listening,
		cList:     make([]io.Closer, 0),
		lock:      &sync.RWMutex{},
	}
}

/*
NewPoolTLS returns a PoolServer instance equipped with the given
SSL certificate.
*/
func NewPoolTLS(certfile, keyfile string) (*PoolServer, error) {
	pool := NewPool()
	if err := pool.AppendCertificate(certfile, keyfile); err != nil {
		return nil, err
	}
	return pool, nil
}

/*
NewPoolTLSAuth returns a PoolServer instance equipped with the given
SSL certificate and one ore more root CA certificates for client
authentication.
*/
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

/*
AppendCertificate appends an SSL certificate to the set of server
certificates loading it from the pair of public certificate and private
key files.
*/
func (pool *PoolServer) AppendCertificate(certfile, keyfile string) error {
	if pool.Server.TLSConfig == nil {
		pool.Server.TLSConfig = &tls.Config{}
	}
	return appendCertificate(pool.Server.TLSConfig, certfile, keyfile)
}

/*
appendCertificate appends an SSL certificate to the given tls.Config
loading it from the pair of public certificate and private key files.
*/
func appendCertificate(tlsConfig *tls.Config, certfile, keyfile string) error {
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return err
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	tlsConfig.BuildNameToCertificate()
	return nil
}

/*
AppendClientCAs appends the given SSL root CA certificate files to the
set of client CAs to verify client connections against.
*/
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

/*
appendCAs appends the given SSL root CA certificate files to the
given CA pool.
*/
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

/*
invoke passes the given call to the client.
*/
func invoke(client *rpc.Client, call *rpc.Call) *rpc.Call {
	return client.Go(call.ServiceMethod, call.Args, call.Reply, call.Done)
}

/*
connObserver used to observe I/O errors in a websocket connection.
*/
type connObserver struct {
	*websocket.Conn
	ioError chan error
}

/*
reportError sends the given error over the ioError channel
if there is a free slot available and do nothing otherwise
(i.e. non blocking).
*/
func (conn *connObserver) reportError(err error) {
	select {
	case conn.ioError <- err:
	default:
	}
}

/*
Read implements io.Reader.
*/
func (conn *connObserver) Read(p []byte) (n int, err error) {
	n, err = conn.Conn.Read(p)
	if err != nil {
		conn.reportError(err)
	}
	return
}

/*
Write implements io.Writer.
*/
func (conn *connObserver) Write(p []byte) (n int, err error) {
	n, err = conn.Conn.Write(p)
	if err != nil {
		conn.reportError(err)
	}
	return
}

/*
handle returns and invoker() function casted to the
websocket.Handler type in order to get the necessary websocket
handshake behavior. The invoker function is wrapped call
to addCloser() to register the connection with the pool.
*/
func (pool *PoolServer) handle(newClient func(conn io.ReadWriteCloser) *rpc.Client, callIn <-chan *rpc.Call) websocket.Handler {
	_invoker := invoker(newClient, callIn, nil)
	return websocket.Handler(func(ws *websocket.Conn) {
		pool.addCloser(ws)
		_invoker(ws)
	})
}

/*
addCloser adds the given connection or a listener to the
set of opened objects.
*/
func (pool *PoolServer) addCloser(c io.Closer) {
	pool.lock.Lock()
	pool.cList = append(pool.cList, c)
	pool.lock.Unlock()
}

/*
invoker returns a function that the passes calls from the
given channel over a websocket connection. In the case of I/O error
it is written to errOut channel if it is provided and the function
returns. The function also returns if callIn channel is closed.
No error is sent in that case. The errOut, if provied, is anyway
closed on return.
*/
func invoker(newClient func(conn io.ReadWriteCloser) *rpc.Client, callIn <-chan *rpc.Call, errOut chan<- error) func(ws *websocket.Conn) {
	return func(ws *websocket.Conn) {
		conn := &connObserver{ws, make(chan error, 10)}
		client := newClient(conn)
		defer client.Close()
		defer func() {
			if errOut != nil {
				close(errOut)
			}
		}()
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
	}
}

/*
assertMux checks for pool.Server.Handler mux and makes
one if it doesn't yet exist.
*/
func (pool *PoolServer) assertMux() *http.ServeMux {
	if pool.Server.Handler == nil {
		pool.Server.Handler = http.NewServeMux()
	}
	return pool.Server.Handler.(*http.ServeMux)
}

/*
Bind makes all the connections to the given path to be
considered as the means to make calls to the named providers.
If no providers are specified the connections at the path
are considered the default providers. The expected RPC
protocol is what is used by rpc.NewClient().
*/
func (pool *PoolServer) Bind(path string, providers ...string) {
	pool.BindWith(path, rpc.NewClient, providers...)
}

/*
BindWith associates the given path with the particular RPC protocol
client. If no providers are specified the connections at the path
are considered the default providers.
*/
func (pool *PoolServer) BindWith(path string, newClient func(conn io.ReadWriteCloser) *rpc.Client, providers ...string) {
	pool.lock.Lock()
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
	mux.Handle(path, pool.handle(newClient, callIn))
	pool.lock.Unlock()
}

/*
handleIn returns the websocket.Handler that the serves
incoming RPC calls over a websocket connection using
the given handler.
*/
func (pool *PoolServer) handleIn(serveConn func(conn io.ReadWriteCloser)) websocket.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		pool.addCloser(ws)
		serveConn(ws)
	})
}

/*
BindIn handles incoming RPC calls on the given path.
The expected RPC protocol is what is used by rpc.ServeConn().
*/
func (pool *PoolServer) BindIn(path string) {
	pool.BindInWith(path, rpc.ServeConn)
}

/*
BindInWith handles all connections to the given path with the
given RPC protocol handler.
*/
func (pool *PoolServer) BindInWith(path string, serveConn func(conn io.ReadWriteCloser)) {
	pool.lock.Lock()
	mux := pool.assertMux()
	mux.Handle(path, pool.handleIn(serveConn))
	pool.lock.Unlock()
}

/*
listnObserver wraps a net.Listener providing a special
channel to signal the server pool.Close() was called.
*/
type listnObserver struct {
	net.Listener
	closed chan struct{}
	wg     sync.WaitGroup
}

/*
Close calls Close() on the embedded Listener and aloso closes
the "closed" channel to signal Close() was called on the pool.
*/
func (lo *listnObserver) Close() error {
	close(lo.closed)
	err := lo.Listener.Close()
	lo.wg.Wait()
	return err
}

/*
listen returns the active listener for the current pool config
and an error if any. It also send a signal over the "listening"
channel.
*/
func (pool *PoolServer) listen(addr string, tlsConfig *tls.Config) (*listnObserver, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		l = tls.NewListener(l, tlsConfig)
	}

	lo := &listnObserver{Listener: l, closed: make(chan struct{})}
	pool.addCloser(lo)

	select {
	case pool.listening <- struct{}{}:
	default:
	}

	return lo, nil
}

/*
use uses the given listener waiting for a signal on
the "stop" channel.
*/
func (pool *PoolServer) use(lo *listnObserver) error {
	lo.wg.Add(1)
	err := pool.Server.Serve(lo.Listener)
	lo.wg.Done()
	select {
	case _, opened := <-lo.closed:
		if !opened {
			err = nil // closed by pool.Close()
		}
	default:
	}
	return err
}

/*
ListenAndUse listens the given (or configured if "" is given) address
([host]:port) with no SSL encryption.
*/
func (pool *PoolServer) ListenAndUse(addr string) error {
	if addr == "" {
		addr = pool.Server.Addr
	}
	l, err := pool.listen(addr, nil)
	if err != nil {
		return err
	}
	return pool.use(l)
}

/*
ListenAndUseTLS listens the listens the given (or configured if ""
is given) address ([host]:port) with SSL encryption on.
*/
func (pool *PoolServer) ListenAndUseTLS(addr string) error {
	if addr == "" {
		addr = pool.Server.Addr
	}
	l, err := pool.listen(addr, pool.Server.TLSConfig)
	if err != nil {
		return err
	}
	return pool.use(l)
}

/*
Close closes the pool listener.
*/
func (pool *PoolServer) Close() error {
	var err error

	pool.lock.Lock()
	for i := range pool.cList {
		switch c := pool.cList[i].(type) {
		case *websocket.Conn:
			c.Close() // skip socket error
		default:
			if _err := c.Close(); _err != nil {
				if err == nil {
					err = _err
				}
			}
		}
		pool.cList[i] = nil
	}
	pool.cList = pool.cList[:0]
	pool.lock.Unlock()

	return err
}

/*
Go invokes the given remote function asynchronously. The name of the
provider (if given as the first part of serviceMethod, i.e. "Provider.Function")
is first searched in the PoolMap. If not found (or isn't specified), the
DefaultPool is used. If "done" is nil, a new channel is allocated and passed
in the return value. See net/rpc package for details.
*/
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

/*
Call invokes the given remote function and waits for it to complete,
returning its error status. If an I/O error encountered, then the
function re-queues the call. The name of the provider (if given as the
first part of serviceMethod, i.e. "Provider.Function")
is first searched in the PoolMap. If not found (or isn't specified), the
DefaultPool is used.
*/
func (pool *PoolServer) Call(serviceMethod string, args interface{}, reply interface{}) error {
	for {
		if call, err := pool.Go(serviceMethod, args, reply, nil); err == nil {
			call = <-call.Done
			switch call.Error {
			case rpc.ErrShutdown, io.ErrUnexpectedEOF:
			default:
				return call.Error
			}
		} else {
			return err
		}
	}
}
