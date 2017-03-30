/* RPC with a pool of providers each connected via a web-socket. */
package wsrpcpool

// Main testing module

import (
	"errors"
	"io"
	"net/rpc"
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

/* closeConn closes the given pool and provider connections. */
func closeConn(t *testing.T, pool, pc io.Closer) {
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

/* waitConnected waits for the given connection to either connect
or be closed. Returns the connected flag value. */
func waitConnected(pc *PoolConn) bool {
	var connected bool
	select {
	case <-pc.Connected:
		connected = true
	case <-pc.Closed:
	}
	return connected
}

/* tryConnect tries to connect the given provider making a given number of
attempts at most. Returns the new connection and the connected flag. */
func tryConnect(p *Provider, maxattempts int) (*PoolConn, bool) {
	p.MaxAttempts = maxattempts
	pc := p.ConnectAndServe()
	connected := waitConnected(pc)
	return pc, connected
}

/* tryConnectCaller tries to connect the given provider as a caller
making a given number of attempts at most. Returns the new caller connection
and the connected flag. */
func tryConnectCaller(p *Provider, maxattempts int) (*PoolCallerConn, bool) {
	p.MaxAttempts = maxattempts
	pc := p.ConnectAndUse()
	connected := waitConnected(pc.PoolConn)
	return pc, connected
}

/* testConnection tests for a successful provider to pool server connection
using the given callback functions. */
func testConnection(t *testing.T, getpool func() (*PoolServer, error), listen func(pool *PoolServer) error, getprovider func() (*Provider, error), connect func(p *Provider, pool *PoolServer) (io.Closer, error)) {
	pool, err := getpool()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("Unable to instantiate a plain pool")
	}

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

	closeConn(t, pool, pc)
}

/* TestConnection tests for a successful provider to pool server connection
over an unencrypted channel. */
func TestConnection(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPool(), nil
		},
		func(pool *PoolServer) error {
			pool.Bind("/")
			return pool.ListenAndUse("localhost:8080")
		},
		func() (*Provider, error) {
			return NewProvider("ws://localhost:8080/")
		},
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
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
			pool.Bind("/")
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() (*Provider, error) {
			return NewProvider("wss://localhost:8443/", "testfiles/rootCA.crt")
		},
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
			pc, connected := tryConnect(p, 1)
			if !connected {
				t.Error("Not connected")
			}
			return pc, nil
		})
}

/* TestConnectionTLS expects unsuccessful provider to pool server connection
over an encrypted channel due to unknown server certificate. */
func TestConnectionTLSFail(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLS("testfiles/server.crt", "testfiles/server.key")
		},
		func(pool *PoolServer) error {
			pool.Bind("/")
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() (*Provider, error) {
			return NewProvider("wss://localhost:8443/")
		},
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
			pc, connected := tryConnect(p, 1)
			if connected {
				t.Error("Unexpected connection")
			}
			pc.Close()
			return nil, nil
		})
}

/* testConnectionTLSAuth tests for a successful provider to pool server connection
over an encrypted channel with client-side certificate authentication
using the provided test function and optional hooks. */
func testConnectionTLSAuth(t *testing.T, setupPool func(pool *PoolServer), getprovider func() (*Provider, error), connect func(p *Provider, pool *PoolServer) (io.Closer, error)) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLSAuth("testfiles/server.crt", "testfiles/server.key", "testfiles/rootCA.crt")
		},
		func(pool *PoolServer) error {
			if setupPool != nil {
				setupPool(pool)
			} else {
				pool.Bind("/")
			}
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() (*Provider, error) {
			if getprovider != nil {
				return getprovider()
			} else {
				return NewProviderTLSAuth("wss://localhost:8443/", "testfiles/client.crt", "testfiles/client.key", "testfiles/rootCA.crt")
			}
		},
		connect)
}

/* TestConnectionTLSAuth tests for a successful provider to pool server connection
over an encrypted channel with client-side certificate authentication. */
func TestConnectionTLSAuth(t *testing.T) {
	testConnectionTLSAuth(t, nil, nil,
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
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
	testConnectionTLSAuth(t, nil,
		func() (*Provider, error) {
			return NewProvider("wss://localhost:8443/", "testfiles/rootCA.crt")
		},
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
			pc, connected := tryConnect(p, 1)
			if connected {
				t.Error("Unexpected connection")
			}
			pc.Close()
			return nil, nil
		})
}

/* Test is used as the exported function provider for remote calls. */
type Test struct {
}

/* TestFunc sets its return argument to the value of its first argument. */
func (t *Test) TestFunc(arg int, reply *int) error {
	*reply = arg
	return nil
}

/* TestError returns the error value with the given text. It also sets
its return value to the same string if the pointer is not nil. */
func (t *Test) TestError(text string, reply *string) error {
	if reply != nil {
		*reply = text
	}
	return errors.New(text)
}

/* rpcClient provides Go and Call methods. */
type rpcClient interface {
	Go(serviceMethod string, args interface{}, reply interface{}, done chan *rpc.Call) (*rpc.Call, error)
	Call(serviceMethod string, args interface{}, reply interface{}) error
}

/* testCalls perform the series of remote calls using the Test type. */
func testCalls(t *testing.T, client rpcClient) {
	rpc.Register(&Test{})

	var testval int = 1
	var reply int
	if err := client.Call("Test.TestFunc", testval, &reply); err != nil {
		t.Error(err)
	}
	if reply != testval {
		t.Error("Unexpected result")
	}

	var errtext = "Error text"
	if err := client.Call("Test.TestError", errtext, nil); err == nil {
		t.Error("Expected error")
	} else {
		if err.Error() != errtext {
			t.Error(err)
		}
	}
}

/* TestCallTLSAuth tests for a successful method call over
an encrypted channel with client-side certificate authentication. */
func TestCallTLSAuth(t *testing.T) {
	testConnectionTLSAuth(t, nil, nil,
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
			pc, connected := tryConnect(p, 1)
			if !connected {
				t.Error("Not connected")
			} else {
				testCalls(t, pool)
			}
			return pc, nil
		})
}

/* TestInCallTLSAuth tests for a successful incoming method call over
an encrypted channel with client-side certificate authentication. */
func TestInCallTLSAuth(t *testing.T) {
	testConnectionTLSAuth(t,
		func(pool *PoolServer) {
			pool.BindIn("/")
		},
		nil,
		func(p *Provider, pool *PoolServer) (io.Closer, error) {
			pc, connected := tryConnectCaller(p, 1)
			if !connected {
				t.Error("Not connected")
			} else {
				testCalls(t, pc)
			}
			return pc, nil
		})
}
