/* RPC with a pool of providers each connected via a web-socket. */
package wsrpcpool
// The pool server module

import (
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/net/websocket"
	"io/ioutil"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"sync"
	"errors"
)

/* PoolServer is used to listen on a set of web-socket URLs for RPC
providers. */
type PoolServer struct {
	http.Server
	// Provider name to a call channel map
	PoolMap     map[string]chan *rpc.Call
	// Default call channel
	DefaultPool chan *rpc.Call
}


var (
	// ErrNoDefaultPool signals that provider isn't found and there is no default pool
	ErrNoDefaultPool = errors.New("No default path is bound")
	// ErrNoCertsParsed signals that no SSL certificates were found in the given file
	ErrNoCertsParsed = errors.New("No certificates parsed")
)

/* NewPool returns a plain PoolServer instance. */
func NewPool() *PoolServer {
	return &PoolServer{}
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
	if pool.TLSConfig == nil {
		pool.TLSConfig = &tls.Config{}
	}
	return appendCertificate(pool.TLSConfig, certfile, keyfile)
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
	if pool.TLSConfig == nil {
		pool.TLSConfig = &tls.Config{}
	}
	if pool.TLSConfig.ClientCAs == nil {
		pool.TLSConfig.ClientCAs = x509.NewCertPool()
	}
	err := appendCAs(pool.TLSConfig.ClientCAs, clientCAs...)
	if err == nil {
		pool.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
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

/* Bind associates the given path with the set of remote providers or
makes it the default path if no object provider names given. */
func (pool *PoolServer) Bind(path string, providers ...string) {
	if pool.Handler == nil {
		pool.Handler = http.NewServeMux()
	}

	mux := pool.Handler.(*http.ServeMux)

	if len(providers) > 0 {
		if pool.PoolMap == nil {
			pool.PoolMap = make(map[string]chan *rpc.Call)
		}
		for _, name := range providers {
			if pool.PoolMap[name] == nil {
				pool.PoolMap[name] = make(chan *rpc.Call)
			}
		}
		mux.Handle(path, websocket.Handler(func(ws *websocket.Conn) {
			var wg sync.WaitGroup
			client := jsonrpc.NewClient(ws)
			for _, name := range providers {
				callIn := pool.PoolMap[name]
				go func() {
					defer wg.Done()
					for c := range callIn {
						invoke(client, c)
					}
				}()
			}
			wg.Add(len(providers))
			wg.Wait()
			client.Close()
		}))
	} else {
		if pool.DefaultPool == nil {
			pool.DefaultPool = make(chan *rpc.Call)
		}
		chanIn := pool.DefaultPool
		mux.Handle(path, websocket.Handler(func(ws *websocket.Conn) {
			client := jsonrpc.NewClient(ws)
			for c := range chanIn {
				invoke(client, c)
			}
			client.Close()
		}))
	}
}

/* ListenAndServe listens the given (or configured if "" is given) address
([host]:port) with no SSL encryption. */
func (pool *PoolServer) ListenAndServe(addr string) error {
	if addr != "" {
		pool.Server.Addr = addr
	}
	return pool.Server.ListenAndServe()
}

/* ListenAndServeTLS listens the listens the given (or configured if "" is given) address
([host]:port) with SSL encryption on. */
func (pool *PoolServer) ListenAndServeTLS(addr string) error {
	if addr != "" {
		pool.Server.Addr = addr
	}
	return pool.Server.ListenAndServeTLS("", "")
}

/* Go invokes the given remote function asynchronously. The name of the
provider is first searched in the PoolMap and the DefaultPool is used
if it isn't there. If done is nil, a new channel is allocated and
passed in the return value. See net/rpc package for details. */
func (pool *PoolServer) Go(provider, funcName string, args interface{}, reply interface{}, done chan *rpc.Call) (*rpc.Call, error) {
	callIn := pool.PoolMap[provider]
	if callIn == nil {
		callIn = pool.DefaultPool
	}
	if callIn == nil {
		return nil, ErrNoDefaultPool
	}

	call := &rpc.Call{
		ServiceMethod: provider + "." + funcName,
		Args: args,
		Reply: reply,
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
func (pool *PoolServer) Call(provider, funcName string, args interface{}, reply interface{}) error {
	if call, err := pool.Go(provider, funcName, args, reply, nil); err == nil {
		call = <-call.Done
		return call.Error
	} else {
		return err
	}
}
