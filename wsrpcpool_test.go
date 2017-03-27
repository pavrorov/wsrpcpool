/* RPC with a pool of providers each connected via a web-socket. */
package wsrpcpool

// Main testing module

import (
	"testing"
)

/* TestNewPool tests the NewPool works as expected. */
func TestNewPool(t *testing.T) {
	pool := NewPool()
	if pool == nil {
		t.Fail()
	}
}

/* TestNewPoolTLS tests the NewPoolTLS works as expected. */
func TestNewPoolTLS(t *testing.T) {
	pool, err := NewPoolTLS("testfiles/server.crt", "testfiles/server.key")
	if err != nil {
		t.Error(err)
	}
	if pool == nil {
		t.Fatal("Pool is nil")
	}
	checkPoolCerts(t, pool, 1, 0)
}

/* TestNewPoolTLSAuth tests the NewPoolTLSAuth works as expected. */
func TestNewPoolTLSAuth(t *testing.T) {
	pool, err := NewPoolTLSAuth("testfiles/server.crt", "testfiles/server.key", "testfiles/rootCA.crt")
	if err != nil {
		t.Error(err)
	}
	if pool == nil {
		t.Fatal("Pool is nil")
	}
	checkPoolCerts(t, pool, 1, 1)
}

/* checkPoolCerts checks that a specified number of server and root CA
certificates (for client verification) are loaded into the TLSConfig of
the pool server. */
func checkPoolCerts(t *testing.T, pool *PoolServer, certs, clientCAs int) {
	if pool.Server.TLSConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	csLen := len(pool.Server.TLSConfig.Certificates)
	if csLen != certs {
		t.Errorf("Expected %d certificate, got %d\n", certs, csLen)
	}
	if pool.Server.TLSConfig.ClientCAs == nil {
		if clientCAs > 0 {
			t.Fatal("Client CA pool is nil")
		}
	} else {
		subjs := pool.Server.TLSConfig.ClientCAs.Subjects()
		if len(subjs) != clientCAs {
			t.Errorf("Expected %d certificate in the client CA pool, got %d\n", clientCAs, len(subjs))
		}
	}
}

/* TestBindDefault tests Bind("/") works on a plain pool. */
func TestBindDefault(t *testing.T) {
	pool := NewPool()
	if pool == nil {
		t.Fatal("Unable to instantiate a plain pool")
	}
	pool.Bind("/")
	if pool.DefaultPool == nil {
		t.Fatal("DefaultPool is nil")
	}
}

/* TestBindName tests Bind("/") works on a plain pool for a named provider. */
func TestBindName(t *testing.T) {
	pool := NewPool()
	if pool == nil {
		t.Fatal("Unable to instantiate a plain pool")
	}
	pool.Bind("/", "Test")
	if pool.DefaultPool != nil {
		t.Fatal("DefaultPool is not nil")
	}
	if pool.PoolMap == nil {
		t.Fatal("PoolMap[\"Test\"] is nil")
	}
}

/* closeConnection closes the given pool and provider connections. */
func closeConnection(t *testing.T, pool *PoolServer, pc *PoolConnection) {
	if pc != nil {
		if err := pc.Close(); err != nil {
			t.Error(err)
		}
	}
	if pool != nil {
		if err := pool.Close(); err != nil {
			t.Error(err)
		}
	}
}

/* tryConnect tries to connect the given provider making a given number of
attempts at most. Returns the new connection and the connected flag. */
func tryConnect(p *Provider, maxattempts int) (*PoolConnection, bool) {
	p.MaxAttempts = maxattempts
	pc := p.ConnectAndServe()

	var connected bool
	select {
	case <-pc.Connected:
		connected = true
	case <-pc.Closed:
	}

	return pc, connected
}

/* testConnection tests for a successful provider to pool server connection
using the given callback functions. */
func testConnection(t *testing.T, getpool func() (*PoolServer, error), listen func(pool *PoolServer) error, getprovider func() (*Provider, error), connect func(p *Provider, pool *PoolServer) (*PoolConnection, error)) {
	pool, err := getpool()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("Unable to instantiate a plain pool")
	}
	pool.Bind("/")

	go func() {
		if err := listen(pool); err != nil {
			t.Error(err)
		}
	}()
	<-pool.Listening

	p, err := getprovider()
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Error("Unable to instantiate the provider")
	}

	pc, err := connect(p, pool)
	if err != nil {
		t.Error(err)
	}

	closeConnection(t, pool, pc)
}

/* TestConnection tests for a successful provider to pool server connection
over an unencrypted channel. */
func TestConnection(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPool(), nil
		},
		func(pool *PoolServer) error {
			return pool.ListenAndUse("localhost:8080")
		},
		func() (*Provider, error) {
			return NewProvider("ws://localhost:8080/")
		},
		func(p *Provider, pool *PoolServer) (*PoolConnection, error) {
			pc, connected := tryConnect(p, 1)
			if !connected {
				t.Error("Not connected")
			}
			return pc, nil
		})
}

/* TestConnectionTLS tests for a successful provider to pool server connection
over an encrypted channel. */
func TestConnectionTLS(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLS("testfiles/server.crt", "testfiles/server.key")
		},
		func(pool *PoolServer) error {
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() (*Provider, error) {
			return NewProvider("wss://localhost:8443/", "testfiles/rootCA.crt")
		},
		func(p *Provider, pool *PoolServer) (*PoolConnection, error) {
			pc, connected := tryConnect(p, 1)
			if !connected {
				t.Error("Not connected")
			}
			return pc, nil
		})
}

/* TestConnectionTLSAuth tests for a successful provider to pool server connection
over an encrypted channel with client-side certificate authentication. */
func TestConnectionTLSAuth(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLSAuth("testfiles/server.crt", "testfiles/server.key", "testfiles/rootCA.crt")
		},
		func(pool *PoolServer) error {
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() (*Provider, error) {
			return NewProviderTLSAuth("wss://localhost:8443/", "testfiles/client.crt", "testfiles/client.key", "testfiles/rootCA.crt")
		},
		func(p *Provider, pool *PoolServer) (*PoolConnection, error) {
			pc, connected := tryConnect(p, 1)
			if !connected {
				t.Error("Not connected")
			}
			return pc, nil
		})
}

/* TestConnectionTLSAuthFail tests for a *unsuccessful* provider to pool server
connection over an encrypted channel without the expected client-side certificate
authentication. */
func TestConnectionTLSAuthFail(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLSAuth("testfiles/server.crt", "testfiles/server.key", "testfiles/rootCA.crt")
		},
		func(pool *PoolServer) error {
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() (*Provider, error) {
			return NewProvider("wss://localhost:8443/", "testfiles/rootCA.crt")
		},
		func(p *Provider, pool *PoolServer) (*PoolConnection, error) {
			pc, connected := tryConnect(p, 1)
			if connected {
				t.Error("Unexpected connection")
			}
			pc.Close()
			return nil, nil
		})
}
