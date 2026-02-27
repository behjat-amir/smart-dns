package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ======================== Globals ========================

var (
	// Reusable buffer to reduce allocations in io.Copy and reads
	BufferPool = sync.Pool{
		New: func() interface{} {
			// 16KB tends to work well for TLS/DNS framing
			return make([]byte, 16*1024)
		},
	}

	config    *Config
	limiter   *rate.Limiter
	dohURL    = "https://1.1.1.1/dns-query"
	dohClient = &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			TLSHandshakeTimeout: 3 * time.Second,
		},
	}
	defaultTTL uint32 = 3600
)

// ======================== Config ========================

type Config struct {
	Host    string            `json:"host"`
	Domains map[string]string `json:"domains"` // pattern -> IP (supports exact or "*.example.com")
}

func LoadConfig(filename string) (*Config, error) {
	var c Config
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ======================== Utilities ========================

func isIPv4(ip net.IP) bool { return ip.To4() != nil }

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func countDots(s string) int { return strings.Count(s, ".") }

// Domain matcher with wildcard support: "*.example.com"
func matches(host, pattern string) bool {
	h := strings.ToLower(trimDot(host))
	p := strings.ToLower(trimDot(pattern))
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "*.") {
		suf := p[1:] // ".example.com"
		// require suffix match and at least as many labels as the pattern
		return strings.HasSuffix(h, suf) && countDots(h) >= countDots(p)
	}
	return h == p
}

func findValueByPattern(m map[string]string, host string) (string, bool) {
	for k, v := range m {
		if matches(host, k) {
			return v, true
		}
	}
	return "", false
}

// ======================== DNS Handling ========================

func buildLocalDNSResponse(req *dns.Msg, ipStr string) ([]byte, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Compress = true

	q := req.Question[0]
	name := q.Name

	// Answer only if the type matches the IP version.
	switch q.Qtype {
	case dns.TypeA:
		if ip4 := ip.To4(); ip4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    defaultTTL,
				},
				A: ip4,
			})
		}
	case dns.TypeAAAA:
		if ip16 := ip.To16(); ip16 != nil && ip.To4() == nil {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    defaultTTL,
				},
				AAAA: ip16,
			})
		}
	case dns.TypeANY:
		// Return whichever record matches the IP family
		if ip4 := ip.To4(); ip4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    defaultTTL,
				},
				A: ip4,
			})
		} else if ip16 := ip.To16(); ip16 != nil {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    defaultTTL,
				},
				AAAA: ip16,
			})
		}
	default:
		// NOERROR / NODATA for other types
	}

	return resp.Pack()
}

func processDNSQuery(query []byte) ([]byte, error) {
	var req dns.Msg
	if err := req.Unpack(query); err != nil {
		return nil, err
	}
	if len(req.Question) == 0 {
		return nil, errors.New("no DNS question")
	}

	qName := trimDot(req.Question[0].Name)
	if ip, ok := findValueByPattern(config.Domains, qName); ok {
		return buildLocalDNSResponse(&req, ip)
	}

	// Forward to DoH (POST application/dns-message)
	httpReq, err := http.NewRequest("POST", dohURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "smartSNI/1.0")

	resp, err := dohClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("doh upstream status %d: %s", resp.StatusCode, string(slurp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// ======================== DoT Server ========================

func handleDoTConnection(conn net.Conn) {
	defer conn.Close()

	if !limiter.Allow() {
		log.Println("DoT: rate limit exceeded")
		return
	}

	// DoT framing: 2-byte length + DNS payload (RFC 7858 uses TCP DNS framing)
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Println("DoT read len:", err)
		return
	}

	dnsLen := binary.BigEndian.Uint16(header)
	// Basic sanity limit to avoid huge allocations
	if dnsLen == 0 || dnsLen > 8192 {
		log.Println("DoT invalid length:", dnsLen)
		return
	}

	buf := make([]byte, int(dnsLen))
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Println("DoT read body:", err)
		return
	}

	resp, err := processDNSQuery(buf)
	if err != nil {
		log.Println("DoT process:", err)
		return
	}

	outLen := make([]byte, 2)
	binary.BigEndian.PutUint16(outLen, uint16(len(resp)))
	if _, err := conn.Write(outLen); err != nil {
		log.Println("DoT write len:", err)
		return
	}
	if _, err := conn.Write(resp); err != nil {
		log.Println("DoT write body:", err)
		return
	}
}

func startDoTServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	certDir := filepath.Join("/etc/letsencrypt/live", config.Host)
	cer, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "fullchain.pem"),
		filepath.Join(certDir, "privkey.pem"),
	)
	if err != nil {
		log.Fatal("DoT: load cert:", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", ":853", tlsCfg)
	if err != nil {
		log.Fatal("DoT: listen:", err)
	}
	log.Println("DoT listening on :853")

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("DoT accept:", err)
			continue
		}
		go handleDoTConnection(c)
	}
}

// ======================== TLS SNI Peek ========================

type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c readOnlyConn) Write(_ []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                     { return nil }
func (c readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// Perform a TLS handshake only to capture ClientHello (SNI), then abort
func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	helloCh := make(chan *tls.ClientHelloInfo, 1)

	cfg := &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case helloCh <- chi:
			default:
			}
			// Returning nil causes handshake to fail fast; we only need the Hello
			return nil, nil
		},
	}

	t := tls.Server(readOnlyConn{r: reader}, cfg)
	_ = t.Handshake() // expected to error; we just want ClientHello

	select {
	case h := <-helloCh:
		return h, nil
	default:
		return nil, errors.New("failed to capture ClientHello")
	}
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekBuf := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekBuf))
	if err != nil {
		return nil, nil, err
	}
	return hello, peekBuf, nil
}

// ======================== TCP Proxy (SNI) ========================

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func copyWithPool(dst, src net.Conn) {
	buf := BufferPool.Get().([]byte)
	defer BufferPool.Put(buf)
	_, _ = io.CopyBuffer(dst, src, buf)
	closeWrite(dst)
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Deadline only for initial ClientHello capture
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	clientHello, clientHelloBytes, err := peekClientHello(clientConn)
	if err != nil {
		log.Println("SNI peek:", err)
		return
	}
	_ = clientConn.SetReadDeadline(time.Time{}) // clear deadline

	sni := strings.TrimSpace(strings.ToLower(clientHello.ServerName))
	if sni == "" {
		// Meaningful HTTP error for non-TLS/empty SNI traffic
		resp := "HTTP/1.1 421 Misdirected Request\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 12\r\n\r\nSNI required"
		_, _ = clientConn.Write([]byte(resp))
		return
	}

	target := sni
	if config.Host != "" && target == strings.ToLower(config.Host) {
		target = "127.0.0.1:8443"
	} else {
		target = net.JoinHostPort(target, "443")
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	backendConn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Println("backend dial:", err)
		return
	}
	defer backendConn.Close()

	// Replay the captured ClientHello to the backend first
	if _, err := io.Copy(backendConn, clientHelloBytes); err != nil {
		log.Println("write clienthello:", err)
		return
	}

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyWithPool(clientConn, backendConn) // backend -> client
	}()
	go func() {
		defer wg.Done()
		copyWithPool(backendConn, clientConn) // client -> backend
	}()

	wg.Wait()
}

func serveSniProxy(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal("SNI: listen:", err)
	}
	log.Println("SNI proxy listening on :443")

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("SNI accept:", err)
			continue
		}
		go handleConnection(c)
	}
}

// ======================== DoH Server (fasthttp) ========================

func handleDoHRequest(ctx *fasthttp.RequestCtx) {
	if !limiter.Allow() {
		ctx.Error("Rate limit exceeded", fasthttp.StatusTooManyRequests)
		return
	}

	var body []byte
	switch string(ctx.Method()) {
	case "GET":
		raw := ctx.QueryArgs().Peek("dns")
		if raw == nil {
			ctx.Error("Missing 'dns' query parameter", fasthttp.StatusBadRequest)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
		if err != nil {
			ctx.Error("Invalid 'dns' query parameter", fasthttp.StatusBadRequest)
			return
		}
		body = decoded
	case "POST":
		body = ctx.PostBody()
		if len(body) == 0 {
			ctx.Error("Empty request body", fasthttp.StatusBadRequest)
			return
		}
	default:
		ctx.Error("Only GET and POST methods are allowed", fasthttp.StatusMethodNotAllowed)
		return
	}

	resp, err := processDNSQuery(body)
	if err != nil {
		ctx.Error("Failed to process DNS query", fasthttp.StatusBadRequest)
		return
	}

	ctx.SetContentType("application/dns-message")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_, _ = ctx.Write(resp)
}

func runDOHServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	server := &fasthttp.Server{
		Handler: func(c *fasthttp.RequestCtx) {
			switch string(c.Path()) {
			case "/dns-query":
				handleDoHRequest(c)
			default:
				c.Error("Unsupported path", fasthttp.StatusNotFound)
			}
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = server.Shutdown()
	}()

	log.Println("DoH listening on 127.0.0.1:8080")
	if err := server.ListenAndServe("127.0.0.1:8080"); err != nil {
		if ctx.Err() == nil {
			log.Fatalf("DoH server error: %v", err)
		}
	}
}

// ======================== Classic DNS (port 53 – system DNS) ========================

// dnsHandler53 handles plain DNS (UDP/TCP) for use as system DNS (like shecan.ir).
func dnsHandler53(w dns.ResponseWriter, r *dns.Msg) {
	if !limiter.Allow() {
		log.Println("DNS53: rate limit exceeded")
		return
	}
	queryBytes, err := r.Pack()
	if err != nil {
		log.Println("DNS53 pack:", err)
		return
	}
	respBytes, err := processDNSQuery(queryBytes)
	if err != nil {
		log.Println("DNS53 process:", err)
		return
	}
	// UDP: if response > 512 bytes, set TC and trim so client retries over TCP
	if u, ok := w.RemoteAddr().(*net.UDPAddr); ok && u != nil && len(respBytes) > 512 {
		var truncated dns.Msg
		if err := truncated.Unpack(respBytes); err == nil {
			truncated.Truncated = true
			truncated.Answer = nil
			if b, err := truncated.Pack(); err == nil {
				respBytes = b
			}
		}
	}
	if _, err := w.Write(respBytes); err != nil {
		log.Println("DNS53 write:", err)
	}
}

func runClassicDNSServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	handler := dns.HandlerFunc(dnsHandler53)

	// UDP :53
	udpAddr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		log.Fatal("DNS53 UDP resolve:", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("DNS53 UDP listen: %v (on Linux use: sudo or setcap 'cap_net_bind_service=+ep' binary)", err)
	}
	defer udpConn.Close()

	// TCP :53
	tcpLn, err := net.Listen("tcp", ":53")
	if err != nil {
		log.Fatalf("DNS53 TCP listen: %v (on Linux use: sudo or setcap 'cap_net_bind_service=+ep' binary)", err)
	}
	defer tcpLn.Close()

	log.Println("Classic DNS (system DNS) listening on :53 (UDP/TCP)")

	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpLn, Handler: handler}

	go func() {
		<-ctx.Done()
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}()

	var runWg sync.WaitGroup
	runWg.Add(2)
	go func() {
		defer runWg.Done()
		_ = udpServer.ActivateAndServe()
	}()
	go func() {
		defer runWg.Done()
		_ = tcpServer.ActivateAndServe()
	}()
	runWg.Wait()
}

// ======================== main ========================

func main() {
	// Effective GC tuning at runtime (unlike setting env var)
	debug.SetGCPercent(50)

	// Optional override for DoH upstream via env
	if v := os.Getenv("DOH_UPSTREAM"); v != "" {
		dohURL = v
	}

	cfg, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	config = cfg

	// Shared rate limiter for DoH/DoT (50 req/s, burst 100)
	limiter = rate.NewLimiter(rate.Limit(50), 100)

	useDoHDoT := config.Host != ""
	if useDoHDoT {
		log.Println("Starting smartSNI on :53 (DNS), :443 (SNI), :853 (DoT), 127.0.0.1:8080 (DoH)")
	} else {
		log.Println("Starting smartSNI on :53 (DNS), :443 (SNI) — no DoH/DoT (host not set)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2) // Classic DNS + SNI proxy always
	go runClassicDNSServer(ctx, &wg)
	go serveSniProxy(ctx, &wg)
	if useDoHDoT {
		wg.Add(2)
		go runDOHServer(ctx, &wg)
		go startDoTServer(ctx, &wg)
	}

	wg.Wait()
	log.Println("Shutdown complete")
}
