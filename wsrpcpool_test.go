/* RPC with a pool of providers each connected via a web-socket. */
package wsrpcpool
// Pool server testing module

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
	if pool.Server.TLSConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	csLen := len(pool.Server.TLSConfig.Certificates)
	if csLen != 1 {
		t.Errorf("Expected 1 certificate, got %d\n", csLen)
	}
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
	if pool.Server.TLSConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	csLen := len(pool.Server.TLSConfig.Certificates)
	if csLen != 1 {
		t.Errorf("Expected 1 certificate, got %d\n", csLen)
	}
	if pool.Server.TLSConfig.ClientCAs == nil {
		t.Fatal("Client CA pool is nil")
	}
	subjs := pool.Server.TLSConfig.ClientCAs.Subjects();
	if len(subjs) != 1 {
		t.Errorf("Expected 1 certificate in the client CA pool, got %d\n", len(subjs))
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
