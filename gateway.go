package infrared

import (
	"context"
	"errors"
	"fmt"
	"github.com/cloudflare/tableflip"
	"github.com/haveachin/infrared/protocol"
	"github.com/haveachin/infrared/protocol/handshaking"
	"github.com/haveachin/infrared/protocol/login"
	"github.com/haveachin/infrared/protocol/status"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	handshakeCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "infrared_handshakes",
		Help: "The total number of handshakes made to each proxy by type",
	}, []string{"type", "host"})
	underAttackStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "infrared_underAttack",
		Help: "Is the proxy under attack",
	})
	usedBandwith = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "infrared_used_bandwith",
		Help: "The total number of used bytes of bandwith per proxy",
	}, []string{"host"})
	ctx = context.Background()
	Upg *tableflip.Upgrader
)

type Gateway struct {
	listeners            sync.Map
	Proxies              sync.Map
	closed               chan bool
	wg                   sync.WaitGroup
	conngroup            sync.WaitGroup
	ReceiveProxyProtocol bool
	underAttack          bool
	connections          uint64
}

type Session struct {
	username        string
	loginPacket     protocol.Packet
	handshakePacket protocol.Packet
	ip              string
	serverAddress   string
	connRemoteAddr  net.Addr
	ProtocolVersion protocol.VarInt
	config          *ProxyConfig
}

func (gateway *Gateway) ListenAndServe(proxies []*Proxy) error {
	if len(proxies) <= 0 {
		return errors.New("no proxies in gateway")
	}

	if Config.UnderAttack {
		log.Println("Enabled permanent underAttack mode")
		gateway.underAttack = true
		underAttackStatus.Set(1)
	}

	gateway.closed = make(chan bool, len(proxies))

	for _, proxy := range proxies {
		if err := gateway.RegisterProxy(proxy); err != nil {
			gateway.Close()
			return err
		}
	}

	log.Println("All proxies are online")
	return nil
}

func (gateway *Gateway) EnablePrometheus(bind string) error {
	gateway.wg.Add(1)

	go func() {
		defer gateway.wg.Done()

		http.Handle("/metrics", promhttp.Handler())

		if Config.Tableflip.Enabled {
			var listen net.Listener
			var err error
			listen, err = net.Listen("tcp", bind)
			if err != nil {
				if strings.Contains(err.Error(), "bind: address already in use") {
					log.Printf("Starting secondary prometheus listener on %s", Config.Prometheus.Bind2)
					listen, err = net.Listen("tcp", Config.Prometheus.Bind2)
					if err != nil {
						log.Printf("Failed to open secondary prometheus listener: %s", err)
						return
					}
				} else {
					log.Printf("Failed to open new prometheus listener: %s", err)
					return
				}
			}
			http.Serve(listen, nil)
		} else {
			http.ListenAndServe(bind, nil)
		}
	}()

	log.Println("Enabling Prometheus metrics endpoint on", bind)
	return nil
}

func (gateway *Gateway) KeepProcessActive() {
	gateway.wg.Wait()
}

func (gateway *Gateway) WaitConnGroup() {
	gateway.conngroup.Wait()
}

// Close closes all listeners
func (gateway *Gateway) Close() {
	gateway.listeners.Range(func(k, v interface{}) bool {
		gateway.closed <- true
		_ = v.(Listener).Close()
		return false
	})
}

func (gateway *Gateway) CloseProxy(proxyUID string) {
	log.Println("Closing config with UID", proxyUID)
	v, ok := gateway.Proxies.Load(proxyUID)
	if !ok {
		return
	}
	proxy := v.(*Proxy)

	uids := proxy.UIDs()
	for _, uid := range uids {
		log.Println("Closing proxy with UID", uid)
		gateway.Proxies.Delete(uid)
	}

	playersConnected.DeleteLabelValues(proxy.DomainName())

	closeListener := true
	gateway.Proxies.Range(func(k, v interface{}) bool {
		otherProxy := v.(*Proxy)
		if proxy.ListenTo() == otherProxy.ListenTo() {
			closeListener = false
			return false
		}
		return true
	})

	if !closeListener {
		return
	}

	v, ok = gateway.listeners.Load(proxy.ListenTo())
	if !ok {
		return
	}
	v.(Listener).Close()
}

func (gateway *Gateway) RegisterProxy(proxy *Proxy) error {
	// Register new Proxy
	uids := proxy.UIDs()
	for _, uid := range uids {
		log.Println("Registering proxy with UID", uid)
		gateway.Proxies.Store(uid, proxy)
	}
	proxyUID := proxy.UID()

	proxy.Config.removeCallback = func() {
		gateway.CloseProxy(proxyUID)
	}

	proxy.Config.changeCallback = func() {
		gateway.CloseProxy(proxyUID)
		if err := gateway.RegisterProxy(proxy); err != nil {
			log.Println(err)
		}
	}

	playersConnected.WithLabelValues(proxy.DomainName())

	if Config.TrackBandwidth {
		usedBandwith.WithLabelValues(proxy.DomainName())
	}

	// Check if a gate is already listening to the Proxy address
	addr := proxy.ListenTo()
	if _, ok := gateway.listeners.Load(addr); ok {
		return nil
	}

	log.Println("Creating listener on", addr)
	listener, err := Listen(addr)
	if err != nil {
		return err
	}
	gateway.listeners.Store(addr, listener)

	gateway.wg.Add(1)
	go func() {
		if err := gateway.listenAndServe(listener, addr); err != nil {
			log.Printf("Failed to listen on %s; error: %s", proxy.ListenTo(), err)
		}
	}()
	return nil
}

func (gateway *Gateway) listenAndServe(listener Listener, addr string) error {
	defer gateway.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Closing listener on", addr)
				gateway.listeners.Delete(addr)
				return nil
			}

			continue
		}

		go func() {
			gateway.conngroup.Add(1)
			if Config.Debug {
				log.Printf("[>] Incoming %s on listener %s", conn.RemoteAddr(), addr)
			}
			if gateway.underAttack {
				defer conn.CloseForce()
			} else {
				defer conn.Close()
			}

			realip := conn.RemoteAddr()
			if gateway.ReceiveProxyProtocol {
				header, err := proxyproto.Read(conn.Reader())
				if err != nil {
					if Config.Debug {
						log.Printf("[e] failed to parse proxyproto for %s: %s", conn.RemoteAddr(), err)
					}
					return
				}
				realip = header.SourceAddr
			}

			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := gateway.serve(conn, addr, realip); err != nil {
				if errors.Is(err, protocol.ErrInvalidPacketID) || errors.Is(err, protocol.ErrInvalidPacketLength) {
					handshakeCount.With(prometheus.Labels{"type": "cancelled_invalid", "host": ""}).Inc()
				}

				if Config.Debug {
					log.Printf("[x] %s closed connection with %s; error: %s", realip, addr, err)
				}
				gateway.conngroup.Done()
				return
			}
			_ = conn.SetDeadline(time.Time{})
			if Config.Debug {
				log.Printf("[x] %s closed connection with %s", realip, addr)
			}
			gateway.conngroup.Done()
		}()
	}
}

func (gateway *Gateway) serve(conn Conn, addr string, realip net.Addr) (rerr error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				rerr = errors.New(x)
			case error:
				rerr = x
			default:
				rerr = errors.New("unknown panic in client handler")
			}
		}
	}()

	atomic.AddUint64(&gateway.connections, 1)

	session := Session{}

	session.connRemoteAddr = realip

	err := error(nil)
	session.handshakePacket, err = conn.ReadPacket(true)
	if err != nil {
		return err
	}

	hs, err := handshaking.UnmarshalServerBoundHandshake(session.handshakePacket)
	if err != nil {
		return err
	}
	session.ProtocolVersion = hs.ProtocolVersion

	session.serverAddress = strings.ToLower(hs.ParseServerAddress())

	proxyUID := proxyUID(session.serverAddress, addr)
	if Config.Debug {
		log.Printf("[i] %s requests proxy with UID %s", session.connRemoteAddr, proxyUID)
	}

	session.ip, _, _ = net.SplitHostPort(session.connRemoteAddr.String())

	v, ok := gateway.Proxies.Load(proxyUID)
	if !ok {
		if hs.IsLoginRequest() {
			err := gateway.handleUnknown(conn, session, true)
			if err != nil {
				return err
			}
		}
		err := gateway.handleUnknown(conn, session, false)
		if err != nil {
			return err
		}
	}
	proxy := v.(*Proxy)
	session.config = proxy.Config

	if hs.IsLoginRequest() {
		session.loginPacket, err = conn.ReadPacket(true)
		if err != nil {
			return err
		}

		loginStart, err := login.UnmarshalServerBoundLoginStart(session.loginPacket)
		if err != nil {
			return err
		}

		session.username = string(loginStart.Name)

		handshakeCount.With(prometheus.Labels{"type": "login", "host": session.serverAddress}).Inc()
		_ = conn.SetDeadline(time.Time{})
		if err := proxy.handleLoginConnection(conn, session); err != nil {
			return err
		}
	}

	if hs.IsStatusRequest() {
		handshakeCount.With(prometheus.Labels{"type": "status", "host": session.serverAddress}).Inc()
		if err := proxy.handleStatusConnection(conn, session); err != nil {
			return err
		}
	}
	return nil
}

func (gateway *Gateway) handleUnknown(conn Conn, session Session, isLogin bool) error {
	if gateway.underAttack {
		return errors.New("blocked connection because underAttack")
	}

	if !isLogin {
		_, err := conn.ReadPacket(true)
		if err != nil {
			return err
		}

		err = conn.WritePacket(DefaultStatusResponse())
		if err != nil {
			return err
		}

		pingPacket, err := conn.ReadPacket(true)
		if err != nil {
			return err
		}

		ping, err := status.UnmarshalServerBoundPing(pingPacket)
		if err != nil {
			return err
		}

		err = conn.WritePacket(status.ClientBoundPong{
			Payload: ping.Payload,
		}.Marshal())
		if err != nil {
			return err
		}

		handshakeCount.With(prometheus.Labels{"type": "status", "host": session.serverAddress}).Inc()
		return errors.New("no proxy with domain " + session.serverAddress)
	}

	// Client send an invalid address/port; we don't have a v for that address
	err := conn.WritePacket(login.ClientBoundDisconnect{
		Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", Config.GenericJoinResponse)),
	}.Marshal())
	if err != nil {
		log.Println(err)
	}
	handshakeCount.With(prometheus.Labels{"type": "login", "host": session.serverAddress}).Inc()

	return errors.New("no proxy with domain " + session.serverAddress)
}

func (gateway *Gateway) ClearCps() {
	if gateway.connections >= Config.ConnectionThreshold {
		gateway.underAttack = true
		underAttackStatus.Set(1)
		log.Printf("[i] Reached connections treshold: %d", gateway.connections)
		time.Sleep(time.Minute)
	} else {
		if gateway.underAttack {
			log.Printf("[i] Disabled connections treshold: %d", gateway.connections)
			gateway.underAttack = false
			underAttackStatus.Set(0)
		}
	}
	gateway.connections = 0
	time.Sleep(time.Second)
}

func (gateway *Gateway) TrackBandwith() {
	gateway.Proxies.Range(func(k, v interface{}) bool {
		proxy := v.(*Proxy)
		name := proxy.DomainName()
		proxy.mu.Lock()
		usedBandwith.WithLabelValues(name).Add(float64(proxy.usedBandwith))
		proxy.usedBandwith = 0
		proxy.mu.Unlock()
		return false
	})
	time.Sleep(5 * time.Second)
}