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

/* connectAndClose tests the given provider and pool server for a
successful connection and then close them. */

func connectAndClose(t *testing.T, pool *PoolServer, p *Provider) {
	p.MaxAttempts = 1
	pc := p.ConnectAndServe()

	var connected bool
	select {
	case <-pc.Connected:
		connected = true
	case <-pc.Closed:
	}

	if err := pc.Close(); err != nil {
		t.Error(err)
	} else {
		if !connected {
			t.Error("Not connected")
		}
	}
	if err := pool.Close(); err != nil {
		t.Error(err)
	}
}

/* TestConnection tests for a successful provider to pool server connection
over an unencrypted channel. */
func TestConnection(t *testing.T) {
	pool := NewPool()
	if pool == nil {
		t.Fatal("Unable to instantiate a plain pool")
	}
	pool.Bind("/")

	go func() {
		if err := pool.ListenAndUse("localhost:8080"); err != nil {
			t.Error(err)
		}
	}()
	<-pool.Listening

	p, err := NewProvider("ws://localhost:8080/")
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Error("Unable to instantiate the provider")
	}

	connectAndClose(t, pool, p)
}


/* TestConnectionTLS tests for a successful provider to pool server connection
over an encrypted channel. */
func TestConnectionTLS(t *testing.T) {
	pool, err := NewPoolTLS("testfiles/server.crt", "testfiles/server.key")
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("Unable to instantiate a TLS pool")
	}
	pool.Bind("/")

	go func() {
		if err := pool.ListenAndUseTLS("localhost:8443"); err != nil {
			t.Error(err)
		}
	}()
	<-pool.Listening

	p, err := NewProvider("wss://localhost:8443/", "testfiles/rootCA.crt")
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Error("Unable to instantiate the provider")
	}

	connectAndClose(t, pool, p)
}
