package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
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

	configMu   sync.RWMutex
	configPath string
	startTime  time.Time
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

// ======================== Admin ========================

const adminPort = "8081"
const sessionCookie = "admin_session"
const sessionDuration = 24 * time.Hour

type AdminCreds struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

var (
	adminPath   string
	adminCreds  *AdminCreds
	sessionMap  = make(map[string]sessionEntry)
	sessionMu   sync.RWMutex
)

type sessionEntry struct {
	username string
	expires  time.Time
}

func loadAdminCreds(path string) (*AdminCreds, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c AdminCreds
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Username == "" || c.PasswordHash == "" {
		return nil, errors.New("invalid admin file")
	}
	return &c, nil
}

func ensureDefaultAdmin(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	creds := AdminCreds{Username: "admin", PasswordHash: string(hash)}
	b, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(path, b, 0600); err != nil {
		return err
	}
	log.Println("Admin: created default admin user (admin / admin). Change password after first login.")
	return nil
}

func adminCheckPassword(username, password string) bool {
	if adminCreds == nil {
		return false
	}
	if !strings.EqualFold(adminCreds.Username, username) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(adminCreds.PasswordHash), []byte(password)) == nil
}

func adminNewSession(username string) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	sessionMu.Lock()
	sessionMap[token] = sessionEntry{username: username, expires: time.Now().Add(sessionDuration)}
	sessionMu.Unlock()
	return token
}

func adminGetSession(token string) (username string, ok bool) {
	sessionMu.RLock()
	e, ok := sessionMap[token]
	sessionMu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.username, true
}

func adminRequireAuth(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return false
	}
	if _, ok := adminGetSession(c.Value); !ok {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/admin", http.StatusFound)
		return false
	}
	return true
}

func saveConfigDomains(domains map[string]string) error {
	configMu.Lock()
	defer configMu.Unlock()
	newCfg := &Config{Host: config.Host, Domains: domains}
	b, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, b, 0644); err != nil {
		return err
	}
	config = newCfg
	return nil
}

// getServerIP returns the server's primary IPv4 (first non-loopback). Used when adding domains.
func getServerIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}
			return ipNet.IP.String()
		}
	}
	return ""
}

func adminLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" && r.URL.Path != "/admin/" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		c, _ := r.Cookie(sessionCookie)
		if c != nil && c.Value != "" {
			if _, ok := adminGetSession(c.Value); ok {
				http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Error bool }{Error: r.URL.Query().Get("error") != ""}
	tpl := template.Must(template.New("login").Parse(string(adminLoginHTML)))
	tpl.Execute(w, data)
}

func adminLoginPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/admin/login" {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin?error=1", http.StatusFound)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	if user == "" || pass == "" {
		http.Redirect(w, r, "/admin?error=1", http.StatusFound)
		return
	}
	if !adminCheckPassword(user, pass) {
		http.Redirect(w, r, "/admin?error=1", http.StatusFound)
		return
	}
	token := adminNewSession(user)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionDuration.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func adminDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/dashboard" {
		http.NotFound(w, r)
		return
	}
	if !adminRequireAuth(w, r) {
		return
	}
	configMu.RLock()
	domains := make(map[string]string)
	for k, v := range config.Domains {
		domains[k] = v
	}
	configMu.RUnlock()
	tpl := template.Must(template.New("dashboard").Parse(adminDashboardHTML))
	data := struct {
		Domains     []struct{ Domain, IP string }
		DomainCount int
	}{DomainCount: len(domains)}
	for d, ip := range domains {
		data.Domains = append(data.Domains, struct{ Domain, IP string }{d, ip})
	}
	for i := 0; i < len(data.Domains); i++ {
		for j := i + 1; j < len(data.Domains); j++ {
			if data.Domains[j].Domain < data.Domains[i].Domain {
				data.Domains[i], data.Domains[j] = data.Domains[j], data.Domains[i]
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.Execute(w, data); err != nil {
		log.Println("admin template:", err)
	}
}

func adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/logout" {
		http.NotFound(w, r)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		sessionMu.Lock()
		delete(sessionMap, c.Value)
		sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func adminAPIDomains(w http.ResponseWriter, r *http.Request) {
	if !adminRequireAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	configMu.RLock()
	domains := make(map[string]string)
	for k, v := range config.Domains {
		domains[k] = v
	}
	configMu.RUnlock()
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(domains)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"ok":false,"error":"bad form"}`, http.StatusBadRequest)
			return
		}
		domain := strings.TrimSpace(strings.ToLower(r.FormValue("domain")))
		if domain == "" {
			http.Error(w, `{"ok":false,"error":"domain required"}`, http.StatusBadRequest)
			return
		}
		ip := getServerIP()
		if ip == "" {
			http.Error(w, `{"ok":false,"error":"could not determine server IP"}`, http.StatusInternalServerError)
			return
		}
		configMu.RLock()
		newDomains := make(map[string]string)
		for k, v := range config.Domains {
			newDomains[k] = v
		}
		configMu.RUnlock()
		newDomains[domain] = ip
		if err := saveConfigDomains(newDomains); err != nil {
			http.Error(w, `{"ok":false,"error":"save failed"}`, http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	case http.MethodDelete:
		domain := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("domain")))
		if domain == "" {
			http.Error(w, `{"ok":false,"error":"domain required"}`, http.StatusBadRequest)
			return
		}
		configMu.RLock()
		newDomains := make(map[string]string)
		for k, v := range config.Domains {
			newDomains[k] = v
		}
		configMu.RUnlock()
		delete(newDomains, domain)
		if err := saveConfigDomains(newDomains); err != nil {
			http.Error(w, `{"ok":false,"error":"save failed"}`, http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, "", http.StatusMethodNotAllowed)
	}
}

func adminAPIStatus(w http.ResponseWriter, r *http.Request) {
	if !adminRequireAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true,"service":"smartSNI"}`))
}

// usageStats holds server usage for the admin dashboard.
type usageStats struct {
	RAMUsedMB   uint64  `json:"ram_used_mb"`
	RAMTotalMB  uint64  `json:"ram_total_mb"`
	RAMPercent  float64 `json:"ram_percent"`
	CPUPercent  float64 `json:"cpu_percent"`
	Goroutines  int     `json:"goroutines"`
	UptimeSec   int64   `json:"uptime_sec"`
	ProcessMB   uint64  `json:"process_mb"`
}

func readUsageStats() usageStats {
	var u usageStats
	u.Goroutines = runtime.NumGoroutine()
	u.UptimeSec = int64(time.Since(startTime).Seconds())
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	u.ProcessMB = mem.Alloc / (1024 * 1024)
	// Linux: /proc/meminfo and /proc/stat
	totalKB, availKB := readProcMeminfo()
	if totalKB > 0 {
		u.RAMTotalMB = totalKB / 1024
		usedKB := totalKB - availKB
		if usedKB > totalKB {
			usedKB = totalKB
		}
		u.RAMUsedMB = usedKB / 1024
		u.RAMPercent = 100 * float64(usedKB) / float64(totalKB)
	}
	u.CPUPercent = readProcCPUPercent()
	return u
}

func readProcMeminfo() (totalKB, availKB uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(strings.TrimSuffix(fields[1], " kB"), 10, 64)
		switch fields[0] {
		case "MemTotal:":
			totalKB = val
		case "MemAvailable:":
			availKB = val
		case "MemFree:":
			if availKB == 0 {
				availKB = val
			}
		}
	}
	return totalKB, availKB
}

func readProcCPUPercent() float64 {
	parseCPU := func(data []byte) (total, idle uint64) {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0
			}
			for i := 1; i < len(fields); i++ {
				v, _ := strconv.ParseUint(fields[i], 10, 64)
				total += v
			}
			idle, _ = strconv.ParseUint(fields[4], 10, 64)
			return total, idle
		}
		return 0, 0
	}
	b0, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	total0, idle0 := parseCPU(b0)
	time.Sleep(300 * time.Millisecond)
	b1, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	total1, idle1 := parseCPU(b1)
	dtotal := total1 - total0
	didle := idle1 - idle0
	if dtotal == 0 {
		return 0
	}
	return 100 * (1 - float64(didle)/float64(dtotal))
}

func adminAPIUsage(w http.ResponseWriter, r *http.Request) {
	if !adminRequireAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(readUsageStats())
}

func runAdminServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", adminLoginPage)
	mux.HandleFunc("/admin/", adminLoginPage)
	mux.HandleFunc("/admin/login", adminLoginPost)
	mux.HandleFunc("/admin/dashboard", adminDashboard)
	mux.HandleFunc("/admin/logout", adminLogout)
	mux.HandleFunc("/admin/api/domains", adminAPIDomains)
	mux.HandleFunc("/admin/api/status", adminAPIStatus)
	mux.HandleFunc("/admin/api/usage", adminAPIUsage)
	srv := &http.Server{Addr: ":" + adminPort, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
	log.Println("Admin panel listening on http://127.0.0.1:" + adminPort + "/admin")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Println("Admin server:", err)
	}
}

var adminLoginHTML = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login – Smart SNI</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center min-vh-100">
  <div class="container">
    <div class="row justify-content-center">
      <div class="col-md-4">
        <div class="card shadow">
          <div class="card-body p-4">
            <h5 class="card-title mb-4">Smart SNI – Admin</h5>
            {{if .Error}}<div class="alert alert-danger py-2">Invalid username or password.</div>{{end}}
            <form method="post" action="/admin/login">
              <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" name="username" class="form-control" required autofocus>
              </div>
              <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required>
              </div>
              <button type="submit" class="btn btn-primary w-100">Sign in</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`)

var adminDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard – Smart SNI Admin</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container-fluid">
      <a class="navbar-brand" href="/admin/dashboard">Smart SNI</a>
      <div class="navbar-nav ms-auto">
        <a class="nav-link text-white" href="/admin/logout">Logout</a>
      </div>
    </div>
  </nav>
  <div class="container py-4">
    <h4 class="mb-4">Domains</h4>
    <p class="text-muted">Added domains use this server's IP. Subdomains resolve automatically.</p>
    <div class="row mb-4">
      <div class="col-12">
        <div class="card">
          <div class="card-header">Server usage</div>
          <div class="card-body">
            <div class="row g-3" id="usageRow">
              <div class="col-md-3"><div class="border rounded p-2"><strong>RAM</strong><br><span id="ram">—</span></div></div>
              <div class="col-md-3"><div class="border rounded p-2"><strong>CPU</strong><br><span id="cpu">—</span></div></div>
              <div class="col-md-2"><div class="border rounded p-2"><strong>Goroutines</strong><br><span id="goroutines">—</span></div></div>
              <div class="col-md-2"><div class="border rounded p-2"><strong>Process</strong><br><span id="process">—</span></div></div>
              <div class="col-md-2"><div class="border rounded p-2"><strong>Uptime</strong><br><span id="uptime">—</span></div></div>
            </div>
            <small class="text-muted">Refreshes every 5s</small>
          </div>
        </div>
      </div>
    </div>
    <div class="card mb-4">
      <div class="card-header">Add domain</div>
      <div class="card-body">
        <form id="addForm" class="row g-2">
          <div class="col-md-9">
            <input type="text" name="domain" class="form-control" placeholder="Domain (e.g. example.com)" required>
          </div>
          <div class="col-md-3">
            <button type="submit" class="btn btn-success w-100">Add</button>
          </div>
        </form>
        <div id="addMsg" class="mt-2 small"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Current domains</span>
        <span class="badge bg-secondary">{{.DomainCount}}</span>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover mb-0">
            <thead><tr><th>Domain</th><th>IP</th><th></th></tr></thead>
            <tbody>
              {{range .Domains}}
              <tr>
                <td><code>{{.Domain}}</code></td>
                <td>{{.IP}}</td>
                <td><button type="button" class="btn btn-sm btn-outline-danger remove-btn" data-domain="{{.Domain}}">Remove</button></td>
              </tr>
              {{end}}
              {{if not .Domains}}<tr><td colspan="3" class="text-muted">No domains yet. Add one above.</td></tr>{{end}}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    function fmtUptime(sec) {
      if (sec < 60) return sec + 's';
      if (sec < 3600) return Math.floor(sec/60) + 'm';
      if (sec < 86400) return Math.floor(sec/3600) + 'h ' + Math.floor((sec%3600)/60) + 'm';
      return Math.floor(sec/86400) + 'd ' + Math.floor((sec%86400)/3600) + 'h';
    }
    function loadUsage() {
      fetch('/admin/api/usage').then(function(r) { return r.json(); }).then(function(d) {
        document.getElementById('ram').textContent = (d.ram_total_mb ? (d.ram_used_mb + ' / ' + d.ram_total_mb + ' MB (' + (d.ram_percent || 0).toFixed(1) + '%)') : '—');
        document.getElementById('cpu').textContent = (typeof d.cpu_percent === 'number' ? d.cpu_percent.toFixed(1) : '—') + '%';
        document.getElementById('goroutines').textContent = d.goroutines != null ? d.goroutines : '—';
        document.getElementById('process').textContent = (d.process_mb || 0) + ' MB';
        document.getElementById('uptime').textContent = fmtUptime(d.uptime_sec || 0);
      }).catch(function() {});
    }
    loadUsage();
    setInterval(loadUsage, 5000);
    document.getElementById('addForm').onsubmit = function(e) {
      e.preventDefault();
      var fd = new FormData(this);
      var msg = document.getElementById('addMsg');
      fetch('/admin/api/domains', { method: 'POST', body: fd }).then(function(r) {
        if (r.ok) { msg.className = 'mt-2 small text-success'; msg.textContent = 'Added.'; location.reload(); }
        else { msg.className = 'mt-2 small text-danger'; msg.textContent = 'Failed.'; }
      });
    };
    document.querySelectorAll('.remove-btn').forEach(function(btn) {
      btn.onclick = function() {
        if (!confirm('Remove ' + this.dataset.domain + '?')) return;
        var domain = encodeURIComponent(this.dataset.domain);
        fetch('/admin/api/domains?domain=' + domain, { method: 'DELETE' }).then(function(r) {
          if (r.ok) location.reload(); else alert('Failed.');
        });
      };
    });
  </script>
</body>
</html>`

func isIPv4(ip net.IP) bool { return ip.To4() != nil }

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func countDots(s string) int { return strings.Count(s, ".") }

// parentDomains returns parent domain names for a host, e.g. "api.cdn.example.com" -> ["cdn.example.com", "example.com"]
func parentDomains(host string) []string {
	h := strings.ToLower(trimDot(host))
	if h == "" {
		return nil
	}
	var out []string
	for {
		idx := strings.Index(h, ".")
		if idx < 0 {
			break
		}
		parent := h[idx+1:]
		if parent != "" {
			out = append(out, parent)
		}
		h = parent
	}
	return out
}

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
	// 1) Exact or wildcard match (existing behavior)
	for k, v := range m {
		if matches(host, k) {
			return v, true
		}
	}
	// 2) Auto subdomain: if host is a subdomain of a configured domain, use that domain's IP
	for _, parent := range parentDomains(host) {
		if v, ok := m[parent]; ok {
			// Only use exact key (no wildcard) so we don't double-apply *.example.com
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
	configMu.RLock()
	domains := config.Domains
	configMu.RUnlock()
	if ip, ok := findValueByPattern(domains, qName); ok {
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
	configMu.RLock()
	hostCfg := config.Host
	configMu.RUnlock()
	if hostCfg != "" && target == strings.ToLower(hostCfg) {
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

func runSetAdminPassword() {
	wd, _ := os.Getwd()
	path := filepath.Join(wd, "admin.json")
	fmt.Print("Admin username [admin]: ")
	reader := bufio.NewReader(os.Stdin)
	user, _ := reader.ReadString('\n')
	user = strings.TrimSpace(user)
	if user == "" {
		user = "admin"
	}
	fmt.Print("Admin password: ")
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)
	if pass == "" {
		log.Fatal("Password cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	creds := AdminCreds{Username: user, PasswordHash: string(hash)}
	b, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Admin credentials saved to", path)
}

func main() {
	// -set-admin-password: create/update admin.json and exit
	if len(os.Args) >= 2 && (os.Args[1] == "-set-admin-password" || os.Args[1] == "--set-admin-password") {
		runSetAdminPassword()
		return
	}

	// Effective GC tuning at runtime (unlike setting env var)
	debug.SetGCPercent(50)

	// Optional override for DoH upstream via env
	if v := os.Getenv("DOH_UPSTREAM"); v != "" {
		dohURL = v
	}

	cfgPath, err := filepath.Abs("config.json")
	if err != nil {
		cfgPath = "config.json"
	}
	configPath = cfgPath
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	config = cfg
	startTime = time.Now()

	// Admin: ensure admin.json exists (default admin/admin), then load
	adminPath = filepath.Join(filepath.Dir(configPath), "admin.json")
	if err := ensureDefaultAdmin(adminPath); err != nil {
		log.Printf("Admin: could not ensure default admin: %v", err)
	} else {
		adminCreds, err = loadAdminCreds(adminPath)
		if err != nil {
			log.Printf("Admin: could not load credentials: %v", err)
		}
	}

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
	if adminCreds != nil {
		wg.Add(1)
		go runAdminServer(ctx, &wg)
	}

	wg.Wait()
	log.Println("Shutdown complete")
}
