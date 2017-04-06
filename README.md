# wsrpcpool

**RPC with a pool of providers each connected via a web-socket.
Written in Go.**

The library provides an implementation of a rather *inside-out*
client-server RPC architecture. Multiple *backend* clients connect to
a (pool) server which then invokes backend methods via an RPC protocol.
Basic call load-balancing and call-backs included.

The architecture is intended for a public service with a number of
private providers (dynamic IPs, NAT).


## Basic example

```go
// Public part
pool := NewPool()
pool.Bind("/pool")
pool.ListenAndUse(":8080")

var ret string
err := pool.Call("Backend.Get", "object_id-1", &ret)
```

```go
// Private part
rpc.Register(&Backend{})
p, err := NewProvider()
pc, err := p.ConnectAndServe("ws://pool.my:8080/pool")
```

## HTTPS/WSS encryption

```go
pool, err := NewPoolTLS("server.crt", "server.key")
go pool.ListenAndUseTLS(":8443")
```

```go
// Specify one or more custom CA certs to verify the pool cert if necessary
p, err := NewProvider("rootCA.crt")
pc, err := p.ConnectAndServe("wss://pool.my:8443/pool")
```

## Client certificate authentication

```go
// Add one or more custom CA certs to verify a client cert if necessary
pool, err := NewPoolTLSAuth("server.crt", "server.key", "rootCA.crt")
go pool.ListenAndUseTLS(":8443")
```

```go
// Add one or more custom CA certs to verify the pool cert if necessary
p, err := NewProviderTLSAuth("client.crt", "client.key", "rootCA.crt")
pc, err := p.ConnectAndServe("wss://pool.my:8443/pool")
```

## Call-backs

```go
// Pool side
rpc.Register(&PoolSide{})
pool.BindIn("/cb")
```

```go
pc, err := p.ConnectAndUse("wss://pool.my:8443/cb")

var ret string
err := pc.Call("PoolSide.Notify", "event_id-1", &ret)
```

## Use different URLs for different providers

```go
pool.Bind("/") // the default path
pool.Bind("/db", "Database")
pool.Bind("/files", "Filesystem")
go pool.ListenAndUseTLS(":8443")

var ret string
pool.Call("Database.Select", "object_id-1", &ret) // goes to providers on /db
pool.Call("Filesystem.Open", "file_id-1", &ret) // goes to providers on /files
```

```go
rpc.Register(&Database{})
p.ConnectAdServe("wss://pool.my:8443/db")
```

```go
rpc.Register(&Filesystem{})
p.ConnectAdServe("wss://pool.my:8443/files")
```

## Signals

```go
go pool.ListenAndUseTLS(":8443")
<-pool.Listening
// Now the pool server is listening for incoming connections
```

```go
pc, err := p.ConnectAndServe("wss://pool.my:8443/pool")

select {
case <-pc.Connected:
    // now connected or re-connected
case <-pc.Disconnected:
    // disconnected
case <-pc.Closed:
    // closed by pc.Close() or MaxAttempts is exceeded
}

err := pc.Close()
```

## JSON-RPC

```go
pool.BindWith("/pool", jsonrpc.NewClient)
pool.BindInWith("/cb", jsonrpc.ServeConn)
```

```go
pc.ConnectAndServeWith("wss://pool.my:8443/pool", jsonrpc.NewClient)
pc.ConnectAndUseWith("wss://pool.my:8443/pool", jsonrpc.ServeConn)
```
