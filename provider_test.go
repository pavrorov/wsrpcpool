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
	checkProviderCerts(t, p, 1, 0)
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
	checkProviderCerts(t, p, 0, 1)
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
	checkProviderCerts(t, p, 1, 1)
}

/* checkProviderCerts checks that a specified number of auth and root CA
certificates are loaded into the TlsConfig of the provider. */
func checkProviderCerts(t *testing.T, p *Provider, certs, rootCAs int) {
	if p.Config.TlsConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	csLen := len(p.Config.TlsConfig.Certificates)
	if csLen != certs {
		t.Errorf("Expected %d certificates, got %d\n", certs, csLen)
	}
	if p.Config.TlsConfig.RootCAs == nil {
		if rootCAs > 0 {
			t.Fatal("Root CA pool is nil")
		}
	} else {
		subjs := p.Config.TlsConfig.RootCAs.Subjects();
		if len(subjs) != rootCAs {
			t.Errorf("Expected %d certificate in the root CA pool, got %d\n", rootCAs, len(subjs))
		}
	}
}
