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
	PoolMap     map[string]chan *rpc.Call
	DefaultPool chan *rpc.Call
}

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
			return errors.New("No certificates parsed")
		}
	}
	return nil
}

/* invoke passes the given call to the client. */
func invoke(client *rpc.Client, call *rpc.Call) *rpc.Call {
	return client.Go(call.ServiceMethod, call.Args, call.Reply, call.Done)
}

/* BindPath associates the given path with the set of remote objects or
makes it the default path if no object names given. */
func (pool *PoolServer) BindPath(path string, names ...string) {
	if pool.Handler == nil {
		pool.Handler = http.NewServeMux()
	}

	mux := pool.Handler.(*http.ServeMux)

	if len(names) > 0 {
		if pool.PoolMap == nil {
			pool.PoolMap = make(map[string]chan *rpc.Call)
		}
		for _, name := range names {
			if pool.PoolMap[name] == nil {
				pool.PoolMap[name] = make(chan *rpc.Call)
			}
		}
		mux.Handle(path, websocket.Handler(func(ws *websocket.Conn) {
			var wg sync.WaitGroup
			client := jsonrpc.NewClient(ws)
			for _, name := range names {
				callIn := pool.PoolMap[name]
				go func() {
					defer wg.Done()
					for c := range callIn {
						invoke(client, c)
					}
				}()
			}
			wg.Add(len(names))
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

/* ListenAndServe listens the configured address (host and port) with
no SSL encryption. */
func (pool *PoolServer) ListenAndServe() error {
	return pool.Server.ListenAndServe()
}

/* ListenAndServeTLS listens the configured address (host and port)
with SSL encryption on. */
func (pool *PoolServer) ListenAndServeTLS() error {
	return pool.Server.ListenAndServeTLS("", "")
}
