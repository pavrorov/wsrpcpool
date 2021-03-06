package wsrpcpool

// Main testing module

import (
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/rpc"
	"sync"
	"testing"
	"time"
)

/*
TestNewPool tests the NewPool works as expected.
*/
func TestNewPool(t *testing.T) {
	pool := NewPool()
	if pool == nil {
		t.Fail()
	}
}

/*
TestNewPoolTLS tests the NewPoolTLS works as expected.
*/
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

/*
TestNewPoolTLSAuth tests the NewPoolTLSAuth works as expected.
*/
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

/*
checkPoolCerts checks that a specified number of server and root CA
certificates (for client verification) are loaded into the TLSConfig of
the pool server.
*/
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

/*
TestBindDefault tests Bind("/") works on a plain pool.
*/
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

/*
TestBindName tests Bind("/") works on a plain pool for a named provider.
*/
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

/*
waitConnected waits for the given connection to either connect
or be closed. Returns the connected flag value.
*/
func waitConnected(pc *PoolConn) bool {
	var connected bool
	select {
	case <-pc.Connected:
		connected = true
	case <-pc.Closed:
	}
	return connected
}

/*
tryConnect tries to connect the given provider making a given number of
attempts at most. Returns the new connection and the connected flag.
*/
func tryConnect(url string, p *Provider, maxattempts int) (*PoolConn, error, bool) {
	p.MaxAttempts = maxattempts
	pc, err := p.ConnectAndServe(url)
	if err == nil {
		connected := waitConnected(pc)
		return pc, nil, connected
	} else {
		return nil, err, false
	}
}

/*
tryConnectCaller tries to connect the given provider as a caller
making a given number of attempts at most. Returns the new caller connection
and the connected flag.
*/
func tryConnectCaller(url string, p *Provider, maxattempts int) (*PoolCallerConn, error, bool) {
	p.MaxAttempts = maxattempts
	pc, err := p.ConnectAndUse(url)
	if err == nil {
		connected := waitConnected(pc.PoolConn)
		return pc, nil, connected
	} else {
		return nil, err, false
	}
}

/*
testConnection tests for a successful provider to pool server connection
using the given callback functions.
*/
func testConnection(t *testing.T, getpool func() (*PoolServer, error), listen func(pool *PoolServer) error, getproviders func() ([]*Provider, error), connect func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error)) {
	pool, err := getpool()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("Unable to instantiate a plain pool")
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Error(err)
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := listen(pool); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-pool.Listening:
	case <-done:
		t.Fatal("Pool closed unexpectedly")
	}

	ps, err := getproviders()
	if err != nil {
		t.Error(err)
	}
	if len(ps) == 0 {
		t.Error("Unable to instantiate the provider")
	}

	conns, err := connect(pool, ps...)
	if err != nil {
		t.Error(err)
	}

	for _, c := range conns {
		if c != nil {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}
	}
}

/*
TestConnection tests for a successful provider to pool server connection
over an unencrypted channel.
*/
func TestConnection(t *testing.T) {
	testConnectionPlain(t, nil, nil,
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("ws://localhost:8080/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			}
			return []io.Closer{pc}, nil
		})
}

/*
TestConnectionTLS tests for a successful provider to pool server connection
over an encrypted channel.
*/
func TestConnectionTLS(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLS("testfiles/server.crt", "testfiles/server.key")
		},
		func(pool *PoolServer) error {
			pool.Bind("/")
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() ([]*Provider, error) {
			p, err := NewProvider("testfiles/rootCA.crt")
			return []*Provider{p}, err
		},
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			}
			return []io.Closer{pc}, nil
		})
}

/*
TestConnectionTLS expects unsuccessful provider to pool server connection
over an encrypted channel due to unknown server certificate.
*/
func TestConnectionTLSFail(t *testing.T) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPoolTLS("testfiles/server.crt", "testfiles/server.key")
		},
		func(pool *PoolServer) error {
			pool.Bind("/")
			return pool.ListenAndUseTLS("localhost:8443")
		},
		func() ([]*Provider, error) {
			p, err := NewProvider()
			return []*Provider{p}, err
		},
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if connected {
				t.Error("Unexpected connection")
			}
			pc.Close()
			return nil, nil
		})
}

/*
newTLSAuthProvider return a new provider with root and client
certificates configured.
*/
func newTLSAuthProvider() (*Provider, error) {
	return NewProviderTLSAuth("testfiles/client.crt", "testfiles/client.key", "testfiles/rootCA.crt")
}

/*
testConnectionPlain tests for a successful provider to pool server connection
over an unencrypted channel using the provided test function and optional
hooks.
*/
func testConnectionPlain(t *testing.T, setupPool func(pool *PoolServer), getproviders func() ([]*Provider, error), connect func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error)) {
	testConnection(t,
		func() (*PoolServer, error) {
			return NewPool(), nil
		},
		func(pool *PoolServer) error {
			if setupPool != nil {
				setupPool(pool)
			} else {
				pool.Bind("/")
			}
			return pool.ListenAndUse("localhost:8080")
		},
		func() ([]*Provider, error) {
			if getproviders != nil {
				return getproviders()
			} else {
				p, err := NewProvider()
				return []*Provider{p}, err
			}
		},
		connect)
}

/*
testConnectionTLSAuth tests for a successful provider to pool server connection
over an encrypted channel with client-side certificate authentication
using the provided test function and optional hooks.
*/
func testConnectionTLSAuth(t *testing.T, setupPool func(pool *PoolServer), getproviders func() ([]*Provider, error), connect func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error)) {
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
		func() ([]*Provider, error) {
			if getproviders != nil {
				return getproviders()
			} else {
				p, err := newTLSAuthProvider()
				return []*Provider{p}, err
			}
		},
		connect)
}

/*
TestConnectionTLSAuth tests for a successful provider to pool server connection
over an encrypted channel with client-side certificate authentication.
*/
func TestConnectionTLSAuth(t *testing.T) {
	testConnectionTLSAuth(t, nil, nil,
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			}
			return []io.Closer{pc}, nil
		})
}

/*
TestConnectionTLSAuthFail tests for a *unsuccessful* provider to pool
server connection over an encrypted channel without the expected
client-side certificate authentication.
*/
func TestConnectionTLSAuthFail(t *testing.T) {
	testConnectionTLSAuth(t, nil,
		func() ([]*Provider, error) {
			p, err := NewProvider("testfiles/rootCA.crt")
			return []*Provider{p}, err
		},
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if connected {
				t.Error("Unexpected connection")
			}
			pc.Close()
			return nil, nil
		})
}

/*
Test is used as the exported function provider for remote calls.
*/
type Test struct {
}

/*
TestFunc sets its return argument to the value of its first argument.
*/
func (t *Test) TestFunc(arg int, reply *int) error {
	*reply = arg
	return nil
}

/*
TestError returns the error value with the given text. It also sets
its return value to the same string if the pointer is not nil.
*/
func (t *Test) TestError(text string, reply *string) error {
	if reply != nil {
		*reply = text
	}
	return errors.New(text)
}

/*
rpcClient provides Go and Call methods.
*/
type rpcClient interface {
	Go(serviceMethod string, args interface{}, reply interface{}, done chan *rpc.Call) (*rpc.Call, error)
	Call(serviceMethod string, args interface{}, reply interface{}) error
}

/*
testCalls perform the series of remote calls using the Test type.
*/
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

/*
TestCallPlain tests for a successful method call over
an unencrypted channel.
*/
func TestCallPlain(t *testing.T) {
	testConnectionPlain(t, nil, nil,
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("ws://localhost:8080/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			} else {
				testCalls(t, pool)
			}
			return []io.Closer{pc}, nil
		})
}

/*
TestCallTLSAuth tests for a successful method call over
an encrypted channel with client-side certificate authentication.
*/
func TestCallTLSAuth(t *testing.T) {
	testConnectionTLSAuth(t, nil, nil,
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			} else {
				testCalls(t, pool)
			}
			return []io.Closer{pc}, nil
		})
}

/*
TestInCallTLSAuth tests for a successful incoming method call over
an encrypted channel with client-side certificate authentication.
*/
func TestInCallTLSAuth(t *testing.T) {
	testConnectionTLSAuth(t,
		func(pool *PoolServer) {
			pool.BindIn("/")
		},
		nil,
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnectCaller("wss://localhost:8443/", ps[0], 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			} else {
				testCalls(t, pc)
			}
			return []io.Closer{pc}, nil
		})
}

/*
testTLSAuthMulti runs given tests on the pool server and a set of
providers with multiple connections established over an encrypted
channel with client-side certificate authentication.
*/
func testTLSAuthMulti(t *testing.T, providerCount, connsPerProvider int, connect func(p *Provider) (io.Closer, error), poolTest func(pool *PoolServer, cls []io.Closer) error) {
	testConnectionTLSAuth(t, nil,
		func() ([]*Provider, error) {
			ps := make([]*Provider, 0, providerCount)
			for i := 0; i < providerCount; i++ {
				if p, err := newTLSAuthProvider(); err == nil {
					ps = append(ps, p)
				} else {
					return nil, err
				}
			}
			return ps, nil
		},
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			wg := sync.WaitGroup{}
			pcs := make(chan io.Closer, len(ps)*connsPerProvider)
			for _, p := range ps {
				for i := 0; i < connsPerProvider; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						pc, err := connect(p)
						if err != nil {
							t.Error(err)
						}
						pcs <- pc
					}()
				}
			}
			wg.Wait()
			close(pcs)

			cls := make([]io.Closer, 0, len(ps)*connsPerProvider)
			for pc := range pcs {
				cls = append(cls, pc)
			}

			var err error
			if poolTest != nil {
				err = poolTest(pool, cls)
			}
			return cls, err
		})
}

/*
TestConnectionTLSAuthMulti tests for a successful connection between the pool
server and the set of providers over an encrypted channel with client-side
certificate authentication.
*/
func TestConnectionTLSAuthMulti(t *testing.T) {
	testTLSAuthMulti(t, 5, 5,
		func(p *Provider) (io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", p, 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			}
			return pc, nil
		}, nil)
}

/*
TestCallTLSAuthMulti tests for a successful calls on a series of connections
between the pool server and the set of providers over an encrypted channel
with client-side certificate authentication.
*/
func TestCallTLSAuthMulti(t *testing.T) {
	testTLSAuthMulti(t, 5, 5,
		func(p *Provider) (io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", p, 1)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			}
			return pc, nil
		},
		func(pool *PoolServer, cls []io.Closer) error {
			for i := range cls {
				testCalls(t, pool)
				if err := cls[i].Close(); err != nil {
					t.Error(err)
				}
				cls[i] = nil
			}
			return nil
		})
}

/*
testReconnectTLSAuth tests the ability of a authenticated encrypted connection
to automatically re-connect if broken using the stop / resume hooks.
*/
func testReconnectTLSAuth(t *testing.T, setupPool func(pool *PoolServer), setupProvider func(p *Provider), stop func(pool *PoolServer) error, resume func(pool *PoolServer) error) {
	testConnectionTLSAuth(t, setupPool,
		func() ([]*Provider, error) {
			p, err := newTLSAuthProvider()
			if setupProvider != nil {
				setupProvider(p)
			}
			return []*Provider{p}, err
		},
		func(pool *PoolServer, ps ...*Provider) ([]io.Closer, error) {
			pc, err, connected := tryConnect("wss://localhost:8443/", ps[0], 20)
			if err != nil {
				return nil, err
			}
			if !connected {
				t.Error("Not connected")
			} else {
			loop:
				for i := 1; i <= ps[0].MaxAttempts; i++ {
					testCalls(t, pool)
					if t.Failed() {
						break loop
					}
					if i < ps[0].MaxAttempts {
						if err := stop(pool); err != nil {
							t.Error(err)
							break loop
						}
						select {
						case <-pc.Disconnected:
						case <-pc.Closed:
							t.Errorf("Connection closed unexpectedly (%d)", i)
							break loop
						}
						if err := resume(pool); err != nil {
							t.Error(err)
							break loop
						}
						if connected = waitConnected(pc); !connected {
							t.Errorf("Reconnect %d failed", i)
							break loop
						}
					}
				}
			}
			return []io.Closer{pc}, nil
		})
}

/*
TestReconnectTLSAuth tests the ability of a authenticated encrypted connection
to automatically re-connect if broken (pool is closed).
*/
func TestReconnectTLSAuth(t *testing.T) {
	testReconnectTLSAuth(t, nil, nil,
		func(pool *PoolServer) error {
			return pool.Close()
		},
		func(pool *PoolServer) error {
			var err error
			done := make(chan struct{})
			go func() {
				defer close(done)
				err = pool.ListenAndUseTLS("localhost:8443")
			}()
			select {
			case <-pool.Listening:
			case <-done:
				err = errors.New("Pool closed unexpectedly")
			}
			return err
		})
}

/*
TestReconnectPingTLSAuth tests the ability of a authenticated encrypted
connection to automatically re-connect if broken (by Ping/Pong timeout).
*/
func TestReconnectPingTLSAuth(t *testing.T) {
	var (
		m    sync.Mutex
		mute bool
		j    int
	)
	testReconnectTLSAuth(t,
		func(pool *PoolServer) {
			pool.OnConn = func(ws *websocket.Conn, rq *http.Request) error {
				h := ws.PingHandler()
				ws.SetPingHandler(func(appData string) error {
					m.Lock()
					_mute := mute
					if !_mute {
						j = j + 1
					}
					m.Unlock()
					if !_mute {
						h(appData)
					}
					return nil
				})
				return nil
			}
			pool.Bind("/")
		},
		func(p *Provider) {
			p.PingInterval = 100 * time.Millisecond
		},
		func(pool *PoolServer) error {
			m.Lock()
			for j < 3 {
				m.Unlock()
				testCalls(t, pool)
				m.Lock()
			}
			mute = true
			j = 0
			m.Unlock()
			return nil
		},
		func(pool *PoolServer) error {
			m.Lock()
			mute = false
			m.Unlock()
			return nil
		})
}
