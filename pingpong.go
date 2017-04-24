package wsrpcpool

// The Ping/Pong module

import (
	"github.com/gorilla/websocket"
	"sync"
	"time"
)

/*
PingPong is a mutex-protected ping/pong request/response counter
for a Web socket.
*/
type PingPong struct {
	stop chan struct{}
}

/*
NewPingPong returns new PingPong instance adding the Pong
handler function that resets the ping counter to 0.
The event handler is called when the ping counter exceeds
the given max limit or when sending the Ping control frame
fails. The default action is to close the connection and to
stop the PingPong itself.
*/
func NewPingPong(ws *websocket.Conn, interval time.Duration, max int, event func(count int, err error)) *PingPong {
	pp := &PingPong{make(chan struct{})}
	if interval <= 0 {
		return pp
	}

	var (
		i int
		m sync.Mutex
	)
	go func() {
		t := time.NewTimer(interval)
		defer t.Stop()
		h := ws.PongHandler()
		defer func() {
			ws.SetPongHandler(h)
		}()
		ws.SetPongHandler(func(appData string) error {
			m.Lock()
			i = 0
			m.Unlock()
			if h == nil {
				return nil
			} else {
				return h(appData)
			}
		})
		if event == nil {
			event = func(count int, err error) {
				ws.Close()
				pp.Stop()
			}
		}
	loop:
		for {
			select {
			case <-pp.stop:
				break loop
			case <-t.C:
				m.Lock()
				_i := i
				m.Unlock()
				if _i < max {
					if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(interval)); err == nil {
						m.Lock()
						i = i + 1
						m.Unlock()
					} else {
						event(i, err)
					}
				} else {
					event(_i, nil)
				}
				select {
				case <-pp.stop:
					break loop // stopped
				default:
					// not stopped
					t.Reset(interval)
				}
			}
		}
	}()

	return pp
}

/*
Stop stops the PingPong from doing more Ping requests.
*/
func (pp *PingPong) Stop() {
	close(pp.stop)
}
