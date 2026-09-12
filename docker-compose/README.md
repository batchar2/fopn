# FPTN VPN Server — Installation Guide

FPTN is a VPN technology built from the ground up to provide secure, censorship- and block-resistant connections that can bypass censorship and network filtering.

- Website: https://fptn.org
- GitHub: https://github.com/batchar2/fptn
- Telegram chat: https://t.me/fptn_project

---

## Key features

- **Full IP‑level tunneling (L3 VPN)**  
  FPTN creates a true Layer‑3 tunnel using a TUN interface. All IPv4 and IPv6 traffic is supported and routed transparently. On the client side, traffic can be selectively routed through the tunnel using split‑tunneling based on DNS resolution.
- **Custom transport protocol over HTTPS**  
  Raw IP packets are serialized into protobuf messages and transported through a secure WebSocket connection. This forms a lightweight, fully controllable transport layer independent of classic VPN protocols.
- **TLS stack based on BoringSSL**  
  TLS is built on top of BoringSSL, the same library used by Chrome.
- **Stealth client identification**  
  Legitimate clients are recognized directly at the TLS level using a modified `session_id` field. This allows the server to authenticate clients without exposing a visible VPN protocol or additional negotiation phase.
- **Advanced traffic camouflage**  
  The client supports SNI spoofing, TLS handshake obfuscation, and a “reality mode” where the connection initially behaves like a real HTTPS session before switching to the VPN tunnel. This significantly complicates DPI classification.
- **Indistinguishable server behavior**  
  If an incoming connection does not match the expected TLS fingerprint, the server transparently proxies traffic to the SNI domain. Externally, the server behaves like a normal HTTPS website and does not reveal that a VPN service is running.
- **Traffic shaping and access control**  
  Per‑user bandwidth limits and policies are enforced on the server using a Leaky Bucket–based traffic shaper. This prevents individual clients from exhausting shared resources.
- **Unwanted traffic filtering**  
  Built‑in packet inspection detects BitTorrent signatures and blocks such traffic to comply with hosting policies and reduce abuse.
- **Management, clustering, and monitoring**  
  The server exposes a REST API protected by JWT for user and system management. Distributed master/slave architecture is supported. Operational metrics are exported to Prometheus and can be visualized in Grafana. A Telegram bot is available for basic integration and notifications.

---


## 1. Create Working Directory

Create a folder to store all server files and configurations. This keeps your setup organized.

```bash
mkdir fptn-server && cd fptn-server
```




## 2. Create docker-compose.yml


```yaml
services:
  fptn-server:
    restart: unless-stopped
    image: fptnvpn/fptn-vpn-server:0.4.4
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
      - NET_RAW
      - SYS_ADMIN
      - SYS_RESOURCE
    sysctls:
      net.ipv4.ip_local_port_range: "6890 65535"
      net.ipv4.tcp_congestion_control: "bbr"
      net.ipv4.tcp_rmem: "4096 131072 33554432"
      net.ipv4.tcp_wmem: "4096 65536 33554432"
    ulimits:
      nproc:
        soft: 524288
        hard: 524288
      nofile:
        soft: 524288
        hard: 524288
      memlock:
        soft: 524288
        hard: 524288
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "${FPTN_PORT}:443/tcp"
    volumes:
      - ./fptn-server-data:/etc/fptn
    environment:
      - ENABLE_DETECT_PROBING=${ENABLE_DETECT_PROBING}
      - ALLOWED_SNI_LIST=${ALLOWED_SNI_LIST}
      - ENABLE_DOMAIN_BLACKLIST_FILTER=${ENABLE_DOMAIN_BLACKLIST_FILTER:-true}
      - DOMAIN_BLACKLIST_URLS=${DOMAIN_BLACKLIST_URLS:-}
      - ENABLE_ADS_FILTER=${ENABLE_ADS_FILTER:-true}
      - ADS_BLOCKLIST_URLS=${ADS_BLOCKLIST_URLS:-}
      - DATA_DIR=${DATA_DIR:-/etc/fptn/data}
      - ENABLE_TORRENT_FILTER=${ENABLE_TORRENT_FILTER}
      - ENABLE_SPAM_FILTER=${ENABLE_SPAM_FILTER}
      - PROMETHEUS_SECRET_ACCESS_KEY=${PROMETHEUS_SECRET_ACCESS_KEY}
      - USE_REMOTE_SERVER_AUTH=${USE_REMOTE_SERVER_AUTH}
      - REMOTE_SERVER_AUTH_HOST=${REMOTE_SERVER_AUTH_HOST}
      - REMOTE_SERVER_AUTH_PORT=${REMOTE_SERVER_AUTH_PORT}
      - MAX_ACTIVE_SESSIONS_PER_USER=${MAX_ACTIVE_SESSIONS_PER_USER}
      - SERVER_EXTERNAL_IPS=${SERVER_EXTERNAL_IPS}
      - MTU_SIZE=${MTU_SIZE:-1400}
      - USING_DNS_SERVER=unbound
      - DNS_IPV6_ENABLE=${DNS_IPV6_ENABLE:-false}
      - DNS_IPV4_PRIMARY=${DNS_IPV4_PRIMARY:-8.8.8.8}
      - DNS_IPV4_SECONDARY=${DNS_IPV4_SECONDARY:-8.8.4.4}
      - DNS_IPV6_PRIMARY=${DNS_IPV6_PRIMARY:-2001:4860:4860::8888}
      - DNS_IPV6_SECONDARY=${DNS_IPV6_SECONDARY:-2001:4860:4860::8844}
    healthcheck:
      test: ["CMD", "sh", "-c", "pgrep fptn-server"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fptn-network
networks:
  fptn-network:
    driver: bridge
    enable_ipv6: true
    ipam:
      config:
        - subnet: dead:beef:cafe::/48
          gateway: dead:beef:cafe::1
        - subnet: 192.168.200.0/24
          gateway: 192.168.200.1
```

## 3. Create `.env` file and configure server options.


```bash
# ============================================
# FPTN SERVER
# ============================================
FPTN_PORT=443

# Server's public IPv4/IPv6 addresses, comma-separated.
# Set ALL of them to prevent proxy loops when the server reaches itself.
# Example: SERVER_EXTERNAL_IPS=1.2.3.4,5.6.7.8
SERVER_EXTERNAL_IPS=

# Detect non-FPTN clients / probing during the TLS handshake. (true/false)
ENABLE_DETECT_PROBING=true

# Decoy domains for non-VPN (scanner) traffic. Such a client is proxied to a
# real site, so the server looks like an ordinary HTTPS host.
#   - SNI is in the list     -> proxy to that SNI
#   - SNI is not in the list -> proxy to the first reachable domain in the list
#   - list is empty          -> built-in default domain
# Subdomains match too: "example.com" also covers www / api / any.sub.example.com.
# Pick always-reachable TLS 1.3 sites and verify each is live FROM THIS server.
ALLOWED_SNI_LIST=dashboard.cdnvideo.ru,gosuslugi.ru,sber.ru,id.sber.ru,tbank.ru,cdn.tbank.ru,alfabank.ru,mos.ru,vk.com,wildberries.ru,ozon.ru,2gis.ru,mts.ru,dzen.ru,vprok.ru,x5.ru,perekrestok.ru,yandex.ru,yandex.com,yandex.net,max.ru,google.com,cloudflare.com

# Block ads and trackers: a TLS handshake whose SNI is a listed domain
# (or a subdomain) is dropped. (true/false)
ENABLE_ADS_FILTER=true

# URLs of ad/tracker domain lists, comma-separated. Cached in DATA_DIR and
# refreshed hourly. Empty loads no ad domains.
ADS_BLOCKLIST_URLS=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt,https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Directory for lists the server downloads at runtime. On the mounted volume,
# so the cache survives restarts.
DATA_DIR=/etc/fptn/data

# Block BitTorrent traffic. (true/false)
ENABLE_TORRENT_FILTER=true

# Block traffic that gets the server blacklisted (true/false). Drops:
#   - outgoing mail: TCP 25/465/587/2525 and any stream starting with an SMTP command
#   - telnet brute-force: TCP 23
#   - NetBIOS/SMB worms: TCP 135/137-139/445, UDP 137/138
#   - amplification reflectors: UDP 1900/11211
# NOTE: the mail part also blocks desktop mail clients (Thunderbird, Outlook)
# sending mail through the tunnel.
ENABLE_SPAM_FILTER=true

# Block blacklisted domains: TLS handshakes by SNI, plus QUIC/ICMP to the IPs
# such domains resolve to. (true/false)
ENABLE_DOMAIN_BLACKLIST_FILTER=true

# URLs of domain lists to block, comma-separated. Cached in DATA_DIR/blacklist
# and refreshed hourly. Empty leaves only the built-in domains.
DOMAIN_BLACKLIST_URLS=https://raw.githubusercontent.com/fptn-project/fptn/refs/heads/master/deploy/domain_blacklist/russia.txt

# Max IP packet size (padded up due to obfuscation).
MTU_SIZE=1400

# Redirect authorization to a master FPTN server (cluster mode). (true/false)
USE_REMOTE_SERVER_AUTH=false
# Master server address for authorization (IP or domain).
REMOTE_SERVER_AUTH_HOST=
# Master server port (default 443 for HTTPS).
REMOTE_SERVER_AUTH_PORT=443

# Key for Prometheus to read server stats. Alphanumeric only, no spaces.
PROMETHEUS_SECRET_ACCESS_KEY=

# Max simultaneous sessions per VPN user.
MAX_ACTIVE_SESSIONS_PER_USER=3

# ============================================
# DNS SERVER
# ============================================
# DNS server for VPN clients:
#   - dnsmasq : lightweight caching forwarder (uses the upstreams below)
#   - unbound : recursive validating resolver
USING_DNS_SERVER=dnsmasq

# Resolve IPv6 (AAAA) records. (true/false)
DNS_IPV6_ENABLE=false

# Upstream DNS, used only with dnsmasq.
DNS_IPV4_PRIMARY=8.8.8.8
DNS_IPV4_SECONDARY=8.8.4.4
DNS_IPV6_PRIMARY=2001:4860:4860::8888
DNS_IPV6_SECONDARY=2001:4860:4860::8844

```

*SERVER_EXTERNAL_IPS* (REQUIRED) - Comma-separated list of your server's public IPv4 addresses. Example: 1.2.3.4,5.6.7.8



## 4. Create SSL certificates

Create a private key and self-signed certificate for HTTPS. Required for secure client connections.

```
docker compose run --rm fptn-server sh -c "cd /etc/fptn && openssl genrsa -out server.key 2048"

docker compose run --rm fptn-server sh -c "cd /etc/fptn && openssl req -new -x509 -key server.key -out server.crt -days 365"

docker compose run --rm fptn-server sh -c "openssl x509 -noout -fingerprint -md5 -in /etc/fptn/server.crt | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f' | xargs -I {} echo 'MD5 Fingerprint: {}'"
```


## 5. Start server

Launch the VPN server container in detached mode.

```bash
docker compose up -d
```

## 6. Check Server Status

Ensure the container is running and healthy.

```bash
docker compose ps
```


## 7. Add a VPN User

Create a VPN user that clients will use to connect. You can set a per-user bandwidth limit.

```bash
docker compose exec fptn-server fptn-passwd --add-user <username> --bandwidth 100
```

- Replace `<username>` with the desired username.
- The `--bandwidth` option sets the maximum connection speed in Mbps for this user.



## 8. Generate a Connection Token

Generate a token for the VPN client. This token includes the username, password, and server IP, and is used in the client app to connect.

```
docker compose run --rm fptn-server token-generator --user <username> --password <password> --server-ip <server_public_ip> --port <server_public_port>
```

Replace:
- `<username>` — the VPN username you created
- `<password>` — the password for this user
- `<server_public_ip>` — the public IP address of your VPN server
- `<server_public_port>` — port number for the VPN server (default: 443, range: 1-65535)

