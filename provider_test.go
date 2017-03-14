/* RPC with a pool of providers each connected via a web-socket. */
package wsrpcpool
// Provider testing module

import (
	"testing"
)

/* TestNewProvider tests the NewProvider works as expected. */
func TestNewProvider(t *testing.T) {
	p, err := NewProvider("ws://localhost:8000/")
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Fail()
	}
}

/* TestNewProviderTLSAuth tests the NewProviderTLSAuth works as expected. */
func TestNewProviderTLSAuth(t *testing.T) {
	p, err := NewProviderTLSAuth("wss://localhost:8001/", "testfiles/client.crt", "testfiles/client.key")
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Fatal()
	}
	if p.Config.TlsConfig == nil {
		t.Fatal("TlsConfig is nil")
	}
	csLen := len(p.Config.TlsConfig.Certificates)
	if csLen != 1 {
		t.Errorf("Expected 1 certificate, got %d\n", csLen)
	}
}

/* TestNewProviderCustomCA tests the NewProvider works as expected with a custom root CA cert. */
func TestNewProviderCustomCA(t *testing.T) {
	p, err := NewProvider("wss://localhost:8001/", "testfiles/rootCA.crt")
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Fatal()
	}
	if p.Config.TlsConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	csLen := len(p.Config.TlsConfig.Certificates)
	if csLen != 0 {
		t.Errorf("Expected 0 certificates, got %d\n", csLen)
	}
	if p.Config.TlsConfig.RootCAs == nil {
		t.Fatal("Root CA pool is nil")
	}
	subjs := p.Config.TlsConfig.RootCAs.Subjects();
	if len(subjs) != 1 {
		t.Errorf("Expected 1 certificate in the root CA pool, got %d\n", len(subjs))
	}
}

/* TestNewProviderTLSAuthCustomCA tests the NewProviderTLSAuth works as expected with a custom root CA cert. */
func TestNewProviderTLSAuthCustomCA(t *testing.T) {
	p, err := NewProviderTLSAuth("wss://localhost:8001/", "testfiles/client.crt", "testfiles/client.key", "testfiles/rootCA.crt")
	if err != nil {
		t.Error(err)
	}
	if p == nil {
		t.Fatal()
	}
	if p.Config.TlsConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	csLen := len(p.Config.TlsConfig.Certificates)
	if csLen != 1 {
		t.Errorf("Expected 0 certificates, got %d\n", csLen)
	}
	if p.Config.TlsConfig.RootCAs == nil {
		t.Fatal("Root CA pool is nil")
	}
	subjs := p.Config.TlsConfig.RootCAs.Subjects();
	if len(subjs) != 1 {
		t.Errorf("Expected 1 certificate in the root CA pool, got %d\n", len(subjs))
	}
}
