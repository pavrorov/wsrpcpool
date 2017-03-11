/* RPC with a pool of providers each connected via web-socket. */
package wsrpcpool

import (
	"crypto/tls"
	"crypto/x509"
	//"golang.org/x/net/websocket"
	"io/ioutil"
	"net/http"
	//"net/rpc/jsonrpc"
)

/* A Web-socket connection endpoint for RPC provideres. */
type PoolServer struct {
	http.Server
}

/* Plain PoolServer instance. */
func NewPool() *PoolServer {
	return &PoolServer{}
}

/* PoolServer instance equipped with the given SSL certificate. */
func NewPoolTLS(certfile, keyfile string) (*PoolServer, error) {
	pool := NewPool()
	if err := pool.AppendCertificate(certfile, keyfile); err != nil {
		return nil, err
	}
	return pool, nil
}

/* Appends an SSL certificate to the set of server certificates loading
it from the pair of public certificate and private key files. */
func (pool *PoolServer) AppendCertificate(certfile, keyfile string) error {
	if pool.TLSConfig == nil {
		pool.TLSConfig = &tls.Config{}
	}

	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return err
	}

	pool.TLSConfig.Certificates = append(pool.TLSConfig.Certificates, cert)
	pool.TLSConfig.BuildNameToCertificate()

	return nil
}

/* Appends the given SSL root CA certificate files to the set of client
CAs to verify client connections against. */
func (pool *PoolServer) AppendClientCAs(clientCAs ...string) error {
	if pool.TLSConfig == nil {
		pool.TLSConfig = &tls.Config{}
	}
	if pool.TLSConfig.ClientCAs == nil {
		pool.TLSConfig.ClientCAs = x509.NewCertPool()
	}

	for _, caFile := range clientCAs {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return err
		}
		pool.TLSConfig.ClientCAs.AppendCertsFromPEM(caCert)
	}

	pool.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	return nil
}

/* PoolServer instance equipped with the given SSL certificate
and a root CA certificates for client authentication. */
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
