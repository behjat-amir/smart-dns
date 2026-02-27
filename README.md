# Smart SNI and DNS Proxy Server

Go-based server: **plain DNS (port 53)** and **SNI proxy (443)**. Optionally DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT). Use like **shecan.ir**: set the server IP as system DNS.

## Features

- **Classic DNS (port 53):** Set this server's IP as **system DNS** (Windows, Linux, Mac, router). No browser config.
- **SNI Proxy (443):** Proxies HTTPS by SNI for the domains you list.
- **DoH / DoT:** Optional; only if `host` is set in config and nginx/certs are configured.
- **Rate limiting** and configurable domain list via `config.json`.

## Project structure

```
smart-dns/
├── main.go              # Application entry and all services
├── go.mod / go.sum      # Go modules
├── config.example.json  # Example config (copy to config.json)
├── nginx.conf           # Used only when DoH is enabled (host set)
├── install.sh           # Install menu (clone, build, systemd, smart-dns command)
└── README.md
```

## Configuration

Copy the example and set your server IP:

```bash
cp config.example.json config.json
```

Edit `config.json`:

- **`host`:** Leave `""` for **system DNS + SNI only** (no DoH/DoT). Set to your domain only if you want DoH/DoT and will configure nginx + certbot.
- **`domains`:** List of domains to proxy; value is your server’s public IP.

Example (DNS + SNI only):

```json
{
  "host": "",
  "domains": {
    "example.com": "1.2.3.4",
    "pub.dev": "1.2.3.4"
  }
}
```

Replace `1.2.3.4` with your server’s public IP.

**Using as system DNS:** After the server is running, set your **server’s IP** as DNS in the OS (Windows: adapter DNS, Linux: resolv.conf or NetworkManager).

## Auto install

One-liner (run once):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/behjat-amir/smart-dns/main/install.sh)
```

- Choose **1) Install**. You only enter **website names** (e.g. `pub.dev,youtube.com`). No domain needed for DNS + SNI.
- After install you can install the **`smart-dns`** command so you don’t need curl again.

Next time on the server, run:

```bash
smart-dns
```

Menu options: Install, Uninstall, Show/Add/Remove sites, Fix port 53, **Upgrade** (git pull + rebuild + restart).

## Manual setup

1. Install: `nginx`, `certbot`, `go` (and optionally `python3-certbot-nginx` if using DoH).
2. Clone the repo, then:
   ```bash
   cp config.example.json config.json
   # Edit config.json: set your server IP in "domains", leave "host" as "" for DNS+SNI only
   go mod download && go mod tidy && go build -o smartSNI .
   ```
3. On Linux, port 53 usually needs: `sudo setcap 'cap_net_bind_service=+ep' ./smartSNI` or run as root.
4. Run: `./smartSNI` (or run via systemd; see `install.sh` for an example unit).

If you set `host` and want DoH: configure nginx with SSL for that host and proxy `/dns-query` to `127.0.0.1:8080`. DoT uses certs under `/etc/letsencrypt/live/<host>/`.

## Rate limiting

The server uses `golang.org/x/time/rate` (e.g. 50 req/s, burst 100). Adjust in `main.go` if needed.

## License

[MIT License](LICENSE).
