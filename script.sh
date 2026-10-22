#!/bin/bash

# ============================================================
# PG Node SSH Tunnel Manager v7.2
# GitHub: https://github.com/XiliService/pg-node-ssh-tunnel
# Script File: script.sh
# English Only | Production Ready | Trojan-Style TLS 1.3 + Real Cert + Multi-IP Failover
# v7.0: WebSocket-101 Camouflage + Record Morphing + Parallel Multi-Channel
#       + HW AES-GCM + End-to-End Watchdog + Port-22 Brute-Force Shield
# v7.1: Latency-Aware IP Selection + Bufferbloat Tuning (notsent_lowat + RPS)
#       + TOFU Host-Key Pinning + Unprivileged Sandboxed TLS Wrapper
#       + Zero-Downtime Secret Rotation + Per-IP Accounting + Backup/Restore
# v7.2: Streamlined main menu (frequently-used items) + Other Options submenu
# ============================================================

set -euo pipefail

SCRIPT_VERSION="7.2"
GITHUB_REPO_SLUG="XiliService/pg-node-ssh-tunnel"
GITHUB_API_BASE="https://api.github.com/repos/${GITHUB_REPO_SLUG}"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO_SLUG}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CONF_DIR="/etc/pg-tunnel"
IRAN_CONF="${CONF_DIR}/iran.conf"
FOREIGN_CONF="${CONF_DIR}/foreign.conf"
TRAFFIC_STATE="${CONF_DIR}/traffic.state"
TRAFFIC_LOCK="${CONF_DIR}/traffic.lock"
LAST_GOOD_IP_FILE="${CONF_DIR}/last_good_ip"
TLS_CERT="${CONF_DIR}/tls.crt"
TLS_KEY="${CONF_DIR}/tls.key"
TLS_SERVER_PY="${CONF_DIR}/tls_server.py"
TLS_CLIENT_PY="${CONF_DIR}/tls_client.py"
CRON_FILE="/etc/cron.d/pg-tunnel-restart"
ACCT_CRON_FILE="/etc/cron.d/pg-tunnel-acct"
ACCT_SERVICE="/etc/systemd/system/pg-tunnel-acct.service"
TLS_SERVER_SERVICE="/etc/systemd/system/pg-tls-server.service"
TUNNEL_SERVICE="/etc/systemd/system/reverse-tunnel.service"
MGMT_SERVICE="/etc/systemd/system/pg-tunnel-mgmt.service"
DATA_SERVICE_GLOB="/etc/systemd/system/pg-tunnel-data-*.service"
WATCHDOG_SH="${CONF_DIR}/watchdog.sh"
WATCHDOG_SERVICE="/etc/systemd/system/pg-tunnel-watchdog.service"
WATCHDOG_STATE="${CONF_DIR}/watchdog.state"
SSHBF_DISABLED_FILE="${CONF_DIR}/sshbf.disabled"
KNOWN_HOSTS_FILE="${CONF_DIR}/known_hosts"
PEER_IPS_FILE="${CONF_DIR}/peer_ips"
NET_TUNE_SERVICE="/etc/systemd/system/pg-tunnel-net-tune.service"
SSH_CIPHERS="aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root.${NC}"
        exit 1
    fi
}

ensure_packages() {
    local missing=()
    local pkg
    for pkg in "$@"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        echo -e "${YELLOW}Installing required packages (${missing[*]})...${NC}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
    fi
}

is_valid_ipv4() {
    local ip="${1:-}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    (( 10#$o1 <= 255 && 10#$o2 <= 255 && 10#$o3 <= 255 && 10#$o4 <= 255 ))
}

is_valid_port() {
    local p="${1:-}"
    [[ "$p" =~ ^[0-9]+$ ]] && (( 10#$p >= 1 && 10#$p <= 65535 ))
}

normalize_ports_csv() {
    local raw="${1:-}"
    local out="" p
    IFS=',' read -ra _arr <<< "$raw"
    for p in "${_arr[@]}"; do
        p=$(echo "$p" | xargs)
        [[ -z "$p" ]] && continue
        if ! is_valid_port "$p"; then
            return 1
        fi
        out="${out:+${out},}${p}"
    done
    [[ -n "$out" ]] || return 1
    echo "$out"
}

detect_public_ipv4s() {
    ip -4 addr show scope global 2>/dev/null | awk '
        /inet / {
            ip = $2
            sub(/\/.*/, "", ip)
            if (ip ~ /^10\./ || ip ~ /^127\./ || ip ~ /^169\.254\./ || ip ~ /^192\.168\./) next
            if (ip ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) next
            if (ip ~ /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./) next
            if (!seen[ip]++) print ip
        }
    ' | paste -sd, - || true
}

normalize_bind_ips_csv() {
    local raw="${1:-}"
    raw=$(echo "$raw" | xargs)
    if [[ -z "$raw" ]]; then
        echo ""
        return 0
    fi
    local local_all
    local_all=$(ip -4 addr show 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2}' || true)
    local out="" ip
    IFS=',' read -ra _ips <<< "$raw"
    for ip in "${_ips[@]}"; do
        ip=$(echo "$ip" | xargs)
        [[ -z "$ip" ]] && continue
        if ! is_valid_ipv4 "$ip"; then
            echo -e "${RED}[ERROR] Invalid IPv4 address: '${ip}'.${NC}" >&2
            return 1
        fi
        if [[ -n "$local_all" ]] && ! grep -qxF "$ip" <<< "$local_all"; then
            echo -e "${RED}[ERROR] IP '${ip}' is not assigned to any interface on this server.${NC}" >&2
            return 1
        fi
        out="${out:+${out},}${ip}"
    done
    echo "$out"
}

generate_secret() {
    openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

pick_free_https_port() {
    local cand
    for cand in 2087 2083 9443 2095 8880 52443; do
        if ! ss -tlnp 2>/dev/null | awk -v p=":${cand}$" '$4 ~ p && $0 !~ /tls_server\.py/ {found=1} END{exit !found}'; then
            echo "$cand"
            return 0
        fi
    done
    echo "2087"
}

auto_detect_real_cert() {
    local crt key pub1 pub2 subj iss san dom
    local candidates=()

    if [[ -d /etc/letsencrypt/live ]]; then
        while IFS= read -r -d '' crt; do
            candidates+=("$crt")
        done < <(find /etc/letsencrypt/live -maxdepth 3 -name "fullchain.pem" -print0 2>/dev/null || true)
    fi

    if [[ -d /var/lib/docker/volumes ]]; then
        while IFS= read -r -d '' crt; do
            candidates+=("$crt")
        done < <(find /var/lib/docker/volumes -maxdepth 8 -type f -name "*.crt" -print0 2>/dev/null || true)
    fi

    if [[ -d /root/.acme.sh ]]; then
        while IFS= read -r -d '' crt; do
            candidates+=("$crt")
        done < <(find /root/.acme.sh -maxdepth 4 -type f -name "fullchain.cer" -print0 2>/dev/null || true)
    fi

    for crt in "${candidates[@]}"; do
        key=""
        case "$crt" in
            */fullchain.pem)
                [[ -f "${crt%/fullchain.pem}/privkey.pem" ]] && key="${crt%/fullchain.pem}/privkey.pem"
                ;;
            */fullchain.cer)
                local base_dir="${crt%/fullchain.cer}"
                local found_k
                found_k=$(find "$base_dir" -maxdepth 1 -type f -name "*.key" 2>/dev/null | head -n 1 || true)
                [[ -n "$found_k" ]] && key="$found_k"
                ;;
            *.crt)
                [[ -f "${crt%.crt}.key" ]] && key="${crt%.crt}.key"
                ;;
        esac
        [[ -n "$key" && -f "$key" ]] || continue

        openssl x509 -in "$crt" -noout -checkend 86400 >/dev/null 2>&1 || continue

        subj=$(openssl x509 -in "$crt" -noout -subject 2>/dev/null || true)
        iss=$(openssl x509 -in "$crt" -noout -issuer 2>/dev/null || true)
        [[ -n "$subj" && -n "$iss" && "${subj#subject=}" != "${iss#issuer=}" ]] || continue

        pub1=$(openssl x509 -in "$crt" -noout -pubkey 2>/dev/null || true)
        pub2=$(openssl pkey -in "$key" -pubout 2>/dev/null || true)
        [[ -n "$pub1" && "$pub1" == "$pub2" ]] || continue

        san=$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null || true)
        dom=$(echo "$san" | tr ',' '\n' | sed -n 's/.*DNS:\([^[:space:],]*\).*/\1/p' | grep -v '^\*\.' | head -n 1 || true)
        if [[ -z "$dom" ]]; then
            dom=$(echo "$subj" | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/[:space:]]*\).*/\1/p' | head -n 1 || true)
        fi
        dom="${dom#\*.}"
        if [[ -n "$dom" && "$dom" == *.* ]]; then
            printf '%s|%s|%s\n' "$dom" "$crt" "$key"
            return 0
        fi
    done
    return 1
}

get_cert_badge() {
    if [[ ! -f "$TLS_CERT" ]]; then
        echo "Missing"
        return 0
    fi
    local subj iss
    subj=$(openssl x509 -in "$TLS_CERT" -noout -subject 2>/dev/null || true)
    iss=$(openssl x509 -in "$TLS_CERT" -noout -issuer 2>/dev/null || true)
    if [[ -n "$subj" && -n "$iss" && "${subj#subject=}" != "${iss#issuer=}" ]]; then
        echo "CA-Signed"
    else
        echo "Self-Signed"
    fi
}

configure_iran_sshd_safe() {
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    systemctl mask ssh.socket 2>/dev/null || true
    rm -rf /etc/systemd/system/ssh.socket.d/

    mkdir -p /run/sshd
    if [[ -f /etc/ssh/sshd_config ]]; then
        local tmp_sshd="/etc/ssh/sshd_config.pgtmp.$$"
        {
            echo "Port 22"
            echo "MaxStartups 150:30:300"
            echo "LoginGraceTime 20"
            echo "TCPKeepAlive yes"
            echo "ClientAliveInterval 20"
            echo "ClientAliveCountMax 3"
            grep -vE '^[[:space:]]*(Port|MaxStartups|LoginGraceTime|TCPKeepAlive|ClientAliveInterval|ClientAliveCountMax)[[:space:]]+' /etc/ssh/sshd_config || true
        } > "$tmp_sshd"
        if sshd -t -f "$tmp_sshd" 2>/dev/null; then
            mv -f "$tmp_sshd" /etc/ssh/sshd_config
        else
            rm -f "$tmp_sshd"
        fi
    fi

    systemctl daemon-reload 2>/dev/null || true
    systemctl unmask ssh.service 2>/dev/null || true
    systemctl enable ssh.service >/dev/null 2>&1 || true
    if systemctl is-active --quiet ssh.service; then
        systemctl reload ssh.service 2>/dev/null || systemctl restart ssh.service
    else
        systemctl restart ssh.service
    fi
}

write_tls_server_script() {
    mkdir -p "$CONF_DIR"
    cat > "$TLS_SERVER_PY" <<'EOF'
#!/usr/bin/env python3
import asyncio, base64, email.utils, hashlib, hmac, os, random, re, signal, socket, ssl, subprocess, sys, time

CERT, KEY, LPORT, TPORT = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
CONF_PATH = os.environ.get("PG_IRAN_CONF", "/etc/pg-tunnel/iran.conf")
AUTH_LOCK = asyncio.Lock()
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def load_runtime_conf():
    cfg = {
        "TLS_SECRET": "",
        "TLS_SECRET_OLD": "",
        "TLS_SECRET_OLD_UNTIL": "0",
        "NODE_PORT": "62075",
        "DATA_PORTS": "",
        "FALLBACK_PORT": "80",
        "CERT_SRC": "",
        "KEY_SRC": "",
    }
    try:
        with open(CONF_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip("\x22\x27")
    except Exception:
        pass
    ports = []
    for raw in (cfg.get("NODE_PORT", "") + "," + cfg.get("DATA_PORTS", "")).split(","):
        raw = raw.strip()
        if raw.isdigit():
            p = int(raw)
            if p not in (22, LPORT) and p not in ports:
                ports.append(p)
    fb = int(cfg["FALLBACK_PORT"]) if cfg.get("FALLBACK_PORT", "").isdigit() else 80
    secret_old = cfg.get("TLS_SECRET_OLD", "")
    try:
        old_until = int(cfg.get("TLS_SECRET_OLD_UNTIL", "0"))
    except ValueError:
        old_until = 0
    if not secret_old or (old_until and time.time() >= old_until):
        secret_old = ""
    return cfg.get("TLS_SECRET", ""), secret_old, ports, fb, cfg.get("CERT_SRC", ""), cfg.get("KEY_SRC", "")

def release_zombie_ports(ports):
    if not ports:
        return
    port_re = "|".join(str(p) for p in ports)
    pat = re.compile(rf"^(?:127\.0\.0\.1|\[::1\]):(?:{port_re})$")
    try:
        out = subprocess.check_output(["ss", "-tlnp"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return
    pids = set()
    for line in out.splitlines():
        if "sshd" not in line:
            continue
        parts = line.split()
        if len(parts) >= 4 and pat.match(parts[3]):
            for m in re.finditer(r"pid=(\d+)", line):
                pids.add(int(m.group(1)))
    if not pids:
        return
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    deadline = time.monotonic() + 0.8
    while time.monotonic() < deadline:
        busy = False
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                busy = True
            finally:
                s.close()
            if busy:
                break
        if not busy:
            break
        time.sleep(0.02)

def tune_socket(sock):
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 20)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass

async def mpipe(r, w):
    # Traffic-morphing pipe: emits randomly-sized TLS records for bulk data
    # and coalesces small packets (SSH keepalives / handshakes) inside a short
    # random time window, removing fixed-length / fixed-interval signatures.
    buf = bytearray()
    eof = False
    hold_until = 0.0
    try:
        while True:
            now = time.monotonic()
            if not buf:
                hold_until = 0.0
            elif hold_until and (len(buf) >= 2048 or now >= hold_until):
                hold_until = 0.0
            if buf and (len(buf) >= 2048 or not hold_until):
                n = len(buf) if len(buf) <= 2048 else random.randint(1024, 16384)
                w.write(bytes(buf[:n]))
                del buf[:n]
                await w.drain()
                continue
            if eof:
                if buf:
                    w.write(bytes(buf))
                    await w.drain()
                break
            tmo = max(0.0, hold_until - time.monotonic()) if hold_until else 30.0
            try:
                data = await asyncio.wait_for(r.read(65536), timeout=tmo)
            except asyncio.TimeoutError:
                data = None
            if data is None:
                hold_until = 0.0
                continue
            if data == b"":
                eof = True
                continue
            buf.extend(data)
            if 0 < len(buf) < 512 and not hold_until:
                hold_until = time.monotonic() + random.uniform(0.002, 0.015)
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass

async def serve_fallback(cr, cw, initial_buf, fb_port):
    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", fb_port), timeout=3.0)
        if initial_buf:
            uw.write(initial_buf)
            await uw.drain()
        await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
        return
    except Exception:
        pass
    body = b"<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>200 OK</h1></body></html>\r\n"
    hdr = (
        f"HTTP/1.1 200 OK\r\n"
        f"Server: nginx\r\n"
        f"Date: {email.utils.formatdate(usegmt=True)}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    try:
        cw.write(hdr + body)
        await cw.drain()
    except Exception:
        pass
    try:
        cw.close()
    except Exception:
        pass

async def handle(cr, cw):
    tune_socket(cw.get_extra_info("socket"))
    secret, secret_old, cleanup_ports, fb_port, _, _ = load_runtime_conf()
    buf = bytearray()
    authed = False
    role = "tunnel"
    owned_port = 0
    proto2 = False
    ws_key = ""
    rest = b""

    try:
        while len(buf) < 8192:
            chunk = await asyncio.wait_for(cr.read(4096), timeout=10.0)
            if not chunk:
                cw.close()
                return
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                hdr_bytes, rest = bytes(buf).split(b"\r\n\r\n", 1)
                hdr_text = hdr_bytes.decode("latin1", errors="ignore")
                got_auth = ""
                for line in hdr_text.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        kl = k.strip().lower()
                        if kl == "x-auth":
                            got_auth = v.strip()
                        elif kl == "x-role":
                            role = v.strip().lower()
                        elif kl == "x-port":
                            try:
                                owned_port = int(v.strip())
                            except ValueError:
                                owned_port = 0
                        elif kl == "x-proto":
                            proto2 = v.strip() == "2"
                        elif kl == "sec-websocket-key":
                            ws_key = v.strip()
                if secret and hmac.compare_digest(got_auth, secret):
                    authed = True
                elif secret_old and hmac.compare_digest(got_auth, secret_old):
                    authed = True
                elif not secret and got_auth == "":
                    authed = True
                break
            if not secret and buf.startswith(b"SSH-2.0-"):
                authed = True
                role = "legacy"
                rest = bytes(buf)
                break
            if len(buf) >= 2048 and b"HTTP/" not in buf[:64]:
                break
    except asyncio.TimeoutError:
        hdr = (
            f"HTTP/1.1 408 Request Timeout\r\n"
            f"Server: nginx\r\n"
            f"Date: {email.utils.formatdate(usegmt=True)}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            cw.write(hdr)
            await cw.drain()
        except Exception:
            pass
        try:
            cw.close()
        except Exception:
            pass
        return
    except Exception:
        try:
            cw.close()
        except Exception:
            pass
        return

    if not authed:
        await serve_fallback(cr, cw, bytes(buf), fb_port)
        return

    if proto2:
        # Real WebSocket-style 101 Switching Protocols response (v7.0 clients).
        accept = ""
        if ws_key:
            try:
                accept = base64.b64encode(
                    hashlib.sha1((ws_key + WS_GUID).encode("ascii")).digest()
                ).decode("ascii")
            except Exception:
                accept = ""
        pad = "".join(
            random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            for _ in range(random.randint(24, 80))
        )
        lines = [
            "HTTP/1.1 101 Switching Protocols",
            "Server: nginx",
            "Date: " + email.utils.formatdate(usegmt=True),
            "Connection: Upgrade",
            "Upgrade: websocket",
        ]
        if accept:
            lines.append("Sec-WebSocket-Accept: " + accept)
        lines.append("X-Pad: " + pad)
        try:
            cw.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            await cw.drain()
        except Exception:
            try:
                cw.close()
            except Exception:
                pass
            return

    async with AUTH_LOCK:
        if role == "tunnel":
            await asyncio.get_running_loop().run_in_executor(None, release_zombie_ports, cleanup_ports)
        elif owned_port:
            await asyncio.get_running_loop().run_in_executor(None, release_zombie_ports, [owned_port])
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TPORT), timeout=8.0)
            tune_socket(uw.get_extra_info("socket"))
            if rest:
                uw.write(rest)
                await uw.drain()
        except Exception:
            cw.close()
            return

    await asyncio.gather(mpipe(cr, uw), mpipe(ur, cw))

async def cert_reloader(ctx):
    last_mtime = 0.0
    while True:
        try:
            _, _, _, _, cert_src, key_src = load_runtime_conf()
            if cert_src and key_src and os.path.isfile(cert_src) and os.path.isfile(key_src):
                mt = max(os.path.getmtime(cert_src), os.path.getmtime(key_src))
                if last_mtime == 0.0:
                    last_mtime = mt
                elif mt > last_mtime:
                    with open(cert_src, "rb") as fc, open(CERT, "wb") as dc:
                        dc.write(fc.read())
                    with open(key_src, "rb") as fk, open(KEY, "wb") as dk:
                        dk.write(fk.read())
                    os.chmod(KEY, 0o600)
                    ctx.load_cert_chain(CERT, KEY)
                    last_mtime = mt
        except Exception:
            pass
        await asyncio.sleep(3600)

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    ctx.load_cert_chain(CERT, KEY)
    asyncio.create_task(cert_reloader(ctx))
    srv = await asyncio.start_server(handle, "0.0.0.0", LPORT, ssl=ctx, backlog=512)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
EOF
    chmod +x "$TLS_SERVER_PY"
}

write_tls_client_script() {
    mkdir -p "$CONF_DIR"
    cat > "$TLS_CLIENT_PY" <<'EOF'
#!/usr/bin/env python3
import base64, os, random, selectors, socket, ssl, sys, time

CONF_PATH = os.environ.get("PG_FOREIGN_CONF", "/etc/pg-tunnel/foreign.conf")
LAST_IP_FILE = os.environ.get("PG_LAST_IP_FILE", "/etc/pg-tunnel/last_good_ip")

WS_PATHS = [
    "/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
    "/api/v2/stream", "/v1/realtime/sync", "/cdn-cgi/trace",
    "/graphql", "/hub", "/live", "/events",
]
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

def load_conf():
    cfg = {}
    try:
        with open(CONF_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip("\x22\x27")
    except Exception:
        pass
    return cfg

cfg = load_conf()
HOST = sys.argv[1]
PORT = int(sys.argv[2])
SNI = (sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else cfg.get("TLS_SNI", "")) or "www.microsoft.com"
RAW_BIPS = sys.argv[4] if len(sys.argv) > 4 else cfg.get("BIND_IPS", "")
SECRET = sys.argv[5] if len(sys.argv) > 5 else cfg.get("TLS_SECRET", "")
ROLE = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else "tunnel"
PREFER = (sys.argv[7] if len(sys.argv) > 7 else "").strip()
OWN_PORT = (sys.argv[8] if len(sys.argv) > 8 else "").strip()

pool = []
for x in RAW_BIPS.split(","):
    x = x.strip()
    if x and x not in pool:
        pool.append(x)

last_good = ""
try:
    with open(LAST_IP_FILE, "r", encoding="utf-8") as lf:
        _lg = lf.read().strip()
        if _lg and _lg in pool:
            last_good = _lg
except Exception:
    pass

def probe_latency(bip, timeout=2.5):
    # Quick TCP-only latency probe used to rank failover candidates.
    # Runs only when the preferred source IP is not set or has failed,
    # so healthy connections pay zero extra cost.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if bip:
            s.bind((bip, 0))
        t0 = time.monotonic()
        s.connect((HOST, PORT))
        return time.monotonic() - t0
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

attempts = []
if PREFER:
    attempts.append(PREFER)

rest = [b for b in ([last_good] + pool) if b and b not in attempts]
if len(rest) > 1:
    scored = []
    for b in rest:
        lat = probe_latency(b)
        if lat is not None:
            scored.append((lat, b))
    if scored:
        scored.sort(key=lambda x: x[0])
        # Hysteresis: stick to last_good unless the best candidate is
        # meaningfully faster (>= 20% lower connect latency).
        if not PREFER and last_good:
            lg_idx = next((i for i, (l, b) in enumerate(scored) if b == last_good), None)
            if lg_idx is not None:
                best_lat, best_bip = scored[0]
                if best_bip != last_good and best_lat > scored[lg_idx][0] * 0.8:
                    scored.insert(0, scored.pop(lg_idx))
        rest = [b for _, b in scored]
attempts.extend(rest)
attempts.append("")

def establish_connection(bip):
    deadline = time.monotonic() + 7.0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 20)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        s.settimeout(6.0)
        if bip:
            s.bind((bip, 0))
        s.connect((HOST, PORT))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        in_bio = ssl.MemoryBIO()
        out_bio = ssl.MemoryBIO()
        sslobj = ctx.wrap_bio(in_bio, out_bio, server_hostname=SNI)

        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("TLS handshake timeout")
            s.settimeout(rem)
            try:
                sslobj.do_handshake()
                out = out_bio.read()
                if out:
                    s.sendall(out)
                break
            except ssl.SSLWantReadError:
                out = out_bio.read()
                if out:
                    s.sendall(out)
                data = s.recv(65536)
                if not data:
                    raise EOFError("EOF during TLS handshake")
                in_bio.write(data)
            except ssl.SSLWantWriteError:
                out = out_bio.read()
                if out:
                    s.sendall(out)

        pad = "".join(
            random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            for _ in range(random.randint(32, 128))
        )
        path = random.choice(WS_PATHS)
        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        req_lines = [
            "GET " + path + " HTTP/1.1",
            "Host: " + SNI,
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: " + ws_key,
            "Sec-WebSocket-Version: 13",
            "User-Agent: " + random.choice(UA_POOL),
            "X-Auth: " + SECRET,
            "X-Role: " + ROLE,
            "X-Proto: 2",
        ]
        if OWN_PORT.isdigit():
            req_lines.append("X-Port: " + OWN_PORT)
        req_lines.append("X-Pad: " + pad)
        req = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii")
        off = 0
        while off < len(req):
            off += sslobj.write(memoryview(req)[off:])
        out = out_bio.read()
        if out:
            s.sendall(out)

        first_plain = bytearray()
        while not first_plain:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("SSH banner exchange timeout")
            s.settimeout(rem)
            try:
                chunk = sslobj.read(65536)
                if not chunk:
                    raise EOFError("EOF waiting for SSH banner")
                first_plain.extend(chunk)
            except ssl.SSLWantReadError:
                data = s.recv(65536)
                if not data:
                    raise EOFError("EOF before SSH banner")
                in_bio.write(data)
            except ssl.SSLWantWriteError:
                out = out_bio.read()
                if out:
                    s.sendall(out)

        head = bytes(first_plain)
        if head.startswith(b"SSH-"):
            pass  # Legacy (v6.x) server: raw SSH passthrough, no 101 response.
        elif head.startswith(b"HTTP/1.1"):
            while b"\r\n\r\n" not in head:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError("WebSocket upgrade response timeout")
                s.settimeout(rem)
                try:
                    chunk = sslobj.read(65536)
                    if not chunk:
                        raise EOFError("EOF during 101 response")
                    head += chunk
                except ssl.SSLWantReadError:
                    data = s.recv(65536)
                    if not data:
                        raise EOFError("EOF during 101 response")
                    in_bio.write(data)
                except ssl.SSLWantWriteError:
                    out = out_bio.read()
                    if out:
                        s.sendall(out)
            status_line = head.split(b"\r\n", 1)[0]
            status_code = status_line.split(b" ")[1] if b" " in status_line else b""
            if status_code != b"101":
                raise RuntimeError("Upstream rejected handshake (status " + status_code.decode("latin1", "ignore") + ")")
            body = head.split(b"\r\n\r\n", 1)[1]
            if body and not body.startswith(b"SSH-"):
                raise RuntimeError("Invalid upstream stream after 101")
            first_plain = bytearray(body)
        else:
            raise RuntimeError("Invalid upstream response (rejected secret or blocked)")

        return s, sslobj, in_bio, out_bio, first_plain
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise

raw = None
err = None
chosen_bip = ""
for bip in attempts:
    try:
        raw, sslobj, in_bio, out_bio, plain_out = establish_connection(bip)
        chosen_bip = bip
        break
    except Exception as e:
        err = e

if raw is None:
    sys.stderr.write(f"TLS tunnel connect failed across {attempts}: {err}\n")
    sys.exit(1)

if chosen_bip:
    try:
        os.makedirs(os.path.dirname(LAST_IP_FILE), exist_ok=True)
        tmp = f"{LAST_IP_FILE}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(chosen_bip + "\n")
        os.replace(tmp, LAST_IP_FILE)
    except Exception:
        pass

in_fd = 0
out_fd = os.dup(1)
raw.setblocking(False)
os.set_blocking(in_fd, False)
os.set_blocking(out_fd, False)

sel = selectors.DefaultSelector()
cipher_out = bytearray(out_bio.read())
raw_eof = False
ssl_eof = False
stdin_eof = False
MAX_BUF = 262144
pending = bytearray()
flush_at = 0.0

def pump_ssl():
    global ssl_eof
    if not ssl_eof and len(plain_out) < MAX_BUF:
        while len(plain_out) < MAX_BUF:
            try:
                d = sslobj.read(65536)
                if not d:
                    ssl_eof = True
                    break
                plain_out.extend(d)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                break
            except ssl.SSLEOFError:
                ssl_eof = True
                break
    out = out_bio.read()
    if out:
        cipher_out.extend(out)

pump_ssl()

def try_flush_pending(force=False):
    # Morphing writer: coalesces small payloads inside a short random time
    # window and emits randomly-sized TLS records for bulk streams, removing
    # fixed-length / fixed-interval traffic signatures on the wire.
    global pending, flush_at
    if not pending:
        flush_at = 0.0
        return
    now = time.monotonic()
    if not force and len(pending) < 2048 and flush_at and now < flush_at:
        return
    flush_at = 0.0
    while pending:
        n = len(pending) if len(pending) <= 2048 else random.randint(1024, 16384)
        chunk = bytes(pending[:n])
        off = 0
        while off < len(chunk):
            try:
                off += sslobj.write(memoryview(chunk)[off:])
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                out = out_bio.read()
                if out:
                    cipher_out.extend(out)
                if off:
                    del pending[:off]
                return
            except OSError:
                os._exit(0)
        del pending[:n]
    out = out_bio.read()
    if out:
        cipher_out.extend(out)

try:
    while not (ssl_eof and not plain_out):
        if stdin_eof and not pending and not cipher_out and raw_eof and ssl_eof:
            break

        try_flush_pending()

        ev_raw = 0
        if not raw_eof and len(plain_out) < MAX_BUF:
            ev_raw |= selectors.EVENT_READ
        if cipher_out:
            ev_raw |= selectors.EVENT_WRITE

        ev_in = selectors.EVENT_READ if (not stdin_eof and len(cipher_out) < MAX_BUF and len(pending) < MAX_BUF) else 0
        ev_out = selectors.EVENT_WRITE if plain_out else 0

        for fd, ev in ((raw, ev_raw), (in_fd, ev_in), (out_fd, ev_out)):
            try:
                key = sel.get_key(fd)
                if ev == 0:
                    sel.unregister(fd)
                elif key.events != ev:
                    sel.modify(fd, ev)
            except KeyError:
                if ev != 0:
                    sel.register(fd, ev)

        sel_tmo = 5.0
        if pending and flush_at:
            sel_tmo = min(5.0, max(0.001, flush_at - time.monotonic()))
        events = sel.select(timeout=sel_tmo)
        for key, mask in events:
            fd = key.fileobj
            if fd is raw:
                if mask & selectors.EVENT_READ:
                    try:
                        d = raw.recv(65536)
                        if not d:
                            raw_eof = True
                            in_bio.write_eof()
                        else:
                            in_bio.write(d)
                    except BlockingIOError:
                        pass
                    except OSError:
                        raw_eof = True
                        in_bio.write_eof()
                if mask & selectors.EVENT_WRITE and cipher_out:
                    try:
                        n = raw.send(cipher_out)
                        del cipher_out[:n]
                    except BlockingIOError:
                        pass
                    except OSError:
                        os._exit(0)
            elif fd == in_fd and (mask & selectors.EVENT_READ):
                try:
                    d = os.read(in_fd, 65536)
                    if not d:
                        stdin_eof = True
                        try_flush_pending(force=True)
                        try:
                            sslobj.unwrap()
                        except Exception:
                            pass
                        out = out_bio.read()
                        if out:
                            cipher_out.extend(out)
                        if not cipher_out:
                            os._exit(0)
                    else:
                        pending.extend(d)
                        if len(pending) >= 2048:
                            try_flush_pending(force=True)
                        elif not flush_at:
                            flush_at = time.monotonic() + random.uniform(0.002, 0.015)
                except BlockingIOError:
                    pass
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
                except OSError:
                    os._exit(0)
            elif fd == out_fd and (mask & selectors.EVENT_WRITE) and plain_out:
                try:
                    n = os.write(out_fd, plain_out)
                    del plain_out[:n]
                except BlockingIOError:
                    pass
                except OSError:
                    os._exit(0)

        pump_ssl()
except Exception:
    pass
finally:
    os._exit(0)
EOF
    chmod +x "$TLS_CLIENT_PY"
}

write_watchdog_script() {
    mkdir -p "$CONF_DIR"
    cat > "$WATCHDOG_SH" <<'EOF'
#!/bin/bash
# PG Tunnel End-to-End Watchdog (Iran side)
# Monitors reverse-forward listeners + TLS sessions and self-heals the
# TLS wrapper when the tunnel is fully wedged. Conservative by design:
# healthy or partially-healthy states never trigger a restart.
set -u
CONF="/etc/pg-tunnel/iran.conf"
STATE_FILE="/etc/pg-tunnel/watchdog.state"
[ -r "$CONF" ] || exit 0
OUT_IP=""; NODE_PORT="62075"; DATA_PORTS=""; SEC_SSH=""; TLS_SNI=""; TLS_SECRET=""
# shellcheck disable=SC1090
source "$CONF"
PORTS="${NODE_PORT:-62075},${DATA_PORTS:-}"
SEC_SSH="${SEC_SSH:-2087}"
MISS=0
LAST_TLS_RESTART=0

write_state() {
    printf '%s|%s\n' "$1" "$(date '+%Y-%m-%d %H:%M:%S')" > "$STATE_FILE" 2>/dev/null || true
}

while true; do
    LISTEN=0
    EST=0
    IFS=',' read -ra _pp <<< "$PORTS"
    for _p in "${_pp[@]}"; do
        _p="$(echo "$_p" | xargs)"
        [ -n "$_p" ] || continue
        if ss -tln 2>/dev/null | awk -v ep="127\\.0\\.0\\.1:${_p}$|\\[::1\\]:${_p}$" '$4 ~ ep {f=1} END{exit !f}'; then
            LISTEN=$(( LISTEN + 1 ))
        fi
    done
    EST=$(ss -tn state established 2>/dev/null | awk -v sp=":${SEC_SSH}" '$3 ~ sp"$" {n++} END{print n+0}')

    if (( LISTEN > 0 )); then
        MISS=0
        write_state "OK listeners=${LISTEN} tls_sessions=${EST}"
    else
        MISS=$(( MISS + 1 ))
        write_state "DEGRADED cycles=${MISS} tls_sessions=${EST}"
        if (( MISS >= 4 && EST == 0 )); then
            _now=$(date +%s)
            if (( _now - LAST_TLS_RESTART >= 600 )); then
                LAST_TLS_RESTART=$_now
                MISS=0
                write_state "RESTARTING_TLS_WRAPPER"
                systemctl restart pg-tls-server.service >/dev/null 2>&1 || true
            fi
        fi
    fi
    sleep 15
done
EOF
    chmod +x "$WATCHDOG_SH"
}

enable_brute_force_shield() {
    command -v iptables >/dev/null 2>&1 || { echo -e "${YELLOW}[WARN] iptables not available; brute-force shield skipped.${NC}"; return 1; }

    iptables -N PG_SSHBF_PROBE 2>/dev/null || true
    if ! iptables -A PG_SSHBF_PROBE -m recent --name PG_TEST --set 2>/dev/null; then
        iptables -X PG_SSHBF_PROBE 2>/dev/null || true
        echo -e "${YELLOW}[WARN] iptables 'recent' module unavailable; brute-force shield skipped.${NC}"
        return 1
    fi
    iptables -X PG_SSHBF_PROBE 2>/dev/null || true

    iptables -N PG_SSHBF 2>/dev/null || true
    iptables -F PG_SSHBF
    iptables -A PG_SSHBF -i lo -j RETURN
    iptables -A PG_SSHBF -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
    iptables -A PG_SSHBF -p tcp --syn -m recent --name PG_SSHBF --update --seconds 60 --hitcount 8 -j DROP
    iptables -A PG_SSHBF -p tcp --syn -m recent --name PG_SSHBF --set -j RETURN
    if ! iptables -C INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; then
        iptables -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -N PG_SSHBF 2>/dev/null || true
        ip6tables -F PG_SSHBF
        ip6tables -A PG_SSHBF -i lo -j RETURN
        ip6tables -A PG_SSHBF -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
        ip6tables -A PG_SSHBF -p tcp --syn -m recent --name PG_SSHBF --update --seconds 60 --hitcount 8 -j DROP 2>/dev/null || true
        ip6tables -A PG_SSHBF -p tcp --syn -m recent --name PG_SSHBF --set -j RETURN 2>/dev/null || true
        if ! ip6tables -C INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; then
            ip6tables -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null || true
        fi
    fi

    rm -f "$SSHBF_DISABLED_FILE"
    netfilter-persistent save >/dev/null 2>&1 || true
    echo -e "${GREEN}[OK] SSH brute-force shield active on port 22 (max 8 new connections / 60s per source IP).${NC}"
    return 0
}

disable_brute_force_shield() {
    local i=0
    while (( i < 10 )) && iptables -D INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; do
        i=$(( i + 1 ))
    done
    iptables -F PG_SSHBF 2>/dev/null || true
    iptables -X PG_SSHBF 2>/dev/null || true
    if command -v ip6tables >/dev/null 2>&1; then
        i=0
        while (( i < 10 )) && ip6tables -D INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; do
            i=$(( i + 1 ))
        done
        ip6tables -F PG_SSHBF 2>/dev/null || true
        ip6tables -X PG_SSHBF 2>/dev/null || true
    fi
    mkdir -p "$CONF_DIR"
    touch "$SSHBF_DISABLED_FILE"
    netfilter-persistent save >/dev/null 2>&1 || true
    echo -e "${YELLOW}[OK] SSH brute-force shield disabled and rules removed.${NC}"
}

brute_force_shield_menu() {
    print_header
    echo -e "${CYAN}=== SSH Brute-Force Shield (Port 22) ===${NC}"
    echo
    local st="${YELLOW}Disabled${NC}"
    if iptables -C INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; then
        local tracked=0
        [[ -r /proc/net/xt_recent/PG_SSHBF ]] && tracked=$(grep -c "^src=" /proc/net/xt_recent/PG_SSHBF 2>/dev/null || echo 0)
        st="${GREEN}Active (limit: 8 new connections / 60s per IP | tracked sources: ${tracked})${NC}"
    fi
    echo -e "  Current Status : ${st}"
    echo
    echo "  1) Enable Shield (kernel-level rate limit on port 22)"
    echo "  2) Disable Shield (remove rules)"
    echo "  0) Back to Menu"
    echo -e "------------------------------------------------------------"
    read -p "Select option [0-2]: " sf_choice
    case "$sf_choice" in
        1) enable_brute_force_shield || true ;;
        2) disable_brute_force_shield ;;
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
    read -p "Press Enter to return to menu..."
}

ensure_network_tuning() {
    # Best-effort hot re-apply of critical tunnel tuning (BBR + fq +
    # bufferbloat limit + RPS). Called by cron auto-heal and the boot
    # oneshot unit so a provider reset or module reload never silently
    # degrades the tunnel.
    modprobe tcp_bbr 2>/dev/null || true
    local cur
    cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    [[ "$cur" == "bbr" ]] || sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    cur=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
    [[ "$cur" == "fq" ]] || sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    cur=$(sysctl -n net.ipv4.tcp_notsent_lowat 2>/dev/null || true)
    [[ "$cur" == "131072" ]] || sysctl -w net.ipv4.tcp_notsent_lowat=131072 >/dev/null 2>&1 || true
    local q
    for q in /sys/class/net/*/queues/rx-*/rps_cpus; do
        [[ -w "$q" ]] || continue
        if [[ "$(cat "$q" 2>/dev/null || true)" == "00000000" ]]; then
            echo ffffffff > "$q" 2>/dev/null || true
        fi
    done
    return 0
}

rotate_tls_secret() {
    print_header
    echo -e "${CYAN}=== Rotate TLS Secret (Zero Downtime) ===${NC}"
    echo
    if [[ ! -f "$IRAN_CONF" ]]; then
        echo -e "${RED}[ERROR] This option must be used on the IRAN server (iran.conf not found).${NC}"
        read -p "Press Enter to return to menu..."
        return
    fi
    local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET="" FALLBACK_PORT="80" CERT_SRC="" KEY_SRC="" TLS_SECRET_OLD="" TLS_SECRET_OLD_UNTIL=""
    source "$IRAN_CONF"
    echo "  Current Secret : ${TLS_SECRET:-<none>}"
    if [[ -n "${TLS_SECRET_OLD:-}" ]]; then
        echo "  Rotation State : old secret still accepted (window active)"
    fi
    echo
    echo "  1) Rotate Now    (new secret active immediately; old stays valid 24h)"
    echo "  2) Finalize      (drop old secret now, after Foreign server updated)"
    echo "  0) Back to Menu"
    echo -e "------------------------------------------------------------"
    read -p "Select option [0-2]: " rot_choice
    case "$rot_choice" in
        1)
            local new_secret=""
            read -p "New secret [Enter = auto-generate]: " custom
            custom=$(echo "$custom" | xargs)
            if [[ -n "$custom" ]]; then
                new_secret="$custom"
            else
                new_secret=$(generate_secret)
            fi
            if [[ -z "$new_secret" ]]; then
                echo -e "${RED}[ERROR] Could not build a new secret.${NC}"
                sleep 1
                return
            fi
            local until_epoch=$(( $(date +%s) + 86400 ))
            cat > "$IRAN_CONF" <<EOF
OUT_IP=${OUT_IP}
NODE_PORT=${NODE_PORT:-62075}
DATA_PORTS=${DATA_PORTS}
SEC_SSH=${SEC_SSH}
TLS_SNI=${TLS_SNI}
TLS_SECRET=${new_secret}
TLS_SECRET_OLD=${TLS_SECRET}
TLS_SECRET_OLD_UNTIL=${until_epoch}
FALLBACK_PORT=${FALLBACK_PORT:-80}
CERT_SRC=${CERT_SRC}
KEY_SRC=${KEY_SRC}
EOF
            chown root:pg-tunnel "$IRAN_CONF" 2>/dev/null || true
            chmod 640 "$IRAN_CONF" 2>/dev/null || true
            echo
            echo -e "${GREEN}[OK] Rotation active (no restart needed; new connections use the new key).${NC}"
            echo -e "Now run ${CYAN}Install (Option 1 -> 2)${NC} on the FOREIGN server and paste this new secret:"
            echo -e "  ${YELLOW}${new_secret}${NC}"
            echo "After the Foreign server is updated, run Other Options -> Rotate TLS Secret -> 2) Finalize here to drop the old key."
            ;;
        2)
            if [[ -z "${TLS_SECRET_OLD:-}" ]]; then
                echo -e "${YELLOW}No rotation in progress (old secret not set).${NC}"
            else
                cat > "$IRAN_CONF" <<EOF
OUT_IP=${OUT_IP}
NODE_PORT=${NODE_PORT:-62075}
DATA_PORTS=${DATA_PORTS}
SEC_SSH=${SEC_SSH}
TLS_SNI=${TLS_SNI}
TLS_SECRET=${TLS_SECRET}
FALLBACK_PORT=${FALLBACK_PORT:-80}
CERT_SRC=${CERT_SRC}
KEY_SRC=${KEY_SRC}
EOF
                chown root:pg-tunnel "$IRAN_CONF" 2>/dev/null || true
                chmod 640 "$IRAN_CONF" 2>/dev/null || true
                echo -e "${GREEN}[OK] Old secret dropped. Only the current secret is accepted now.${NC}"
            fi
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}"; sleep 1; return ;;
    esac
    read -p "Press Enter to return to menu..."
}

backup_restore_menu() {
    print_header
    echo -e "${CYAN}=== Backup / Restore Configuration ===${NC}"
    echo
    echo "  1) Create Backup Now  (configs + services + cron -> /root/pg-tunnel-backup-<ts>.tar.gz)"
    echo "  2) Restore From Backup File"
    echo "  0) Back to Menu"
    echo -e "------------------------------------------------------------"
    read -p "Select option [0-2]: " br_choice
    case "$br_choice" in
        1)
            local ts out f items=()
            ts=$(date '+%Y%m%d-%H%M%S')
            out="/root/pg-tunnel-backup-${ts}.tar.gz"
            items=("etc/pg-tunnel")
            for f in "$MGMT_SERVICE" "$TLS_SERVER_SERVICE" "$WATCHDOG_SERVICE" "$NET_TUNE_SERVICE" "$CRON_FILE" "$TUNNEL_SERVICE"; do
                [[ -f "$f" ]] && items+=("${f#/}")
            done
            for f in $DATA_SERVICE_GLOB; do
                [[ -f "$f" ]] && items+=("${f#/}")
            done
            if tar czf "$out" -C / "${items[@]}"; then
                chmod 600 "$out" 2>/dev/null || true
                echo
                echo -e "${GREEN}[OK] Backup created: ${out}${NC}"
                echo -e "${YELLOW}Note: SSH keys (/root/.ssh) are intentionally not included.${NC}"
            else
                echo -e "${RED}[ERROR] Backup failed.${NC}"
            fi
            ;;
        2)
            local bfile bad
            read -p "Path to backup file: " bfile
            bfile=$(echo "$bfile" | xargs)
            if [[ ! -f "$bfile" ]]; then
                echo -e "${RED}[ERROR] File not found: ${bfile}${NC}"
                sleep 1
                return
            fi
            bad=$(tar tzf "$bfile" 2>/dev/null | grep -vE '^etc/(pg-tunnel(/.*)?|systemd/system/(pg-tunnel-[a-z0-9-]+|reverse-tunnel|pg-tls-server)\.service|cron\.d/pg-tunnel-restart)$' || true)
            if [[ -n "$bad" ]]; then
                echo -e "${RED}[ERROR] Backup contains unexpected paths - aborted for safety:${NC}"
                echo "$bad" | head -5
                sleep 1
                return
            fi
            tar xzf "$bfile" -C /
            systemctl daemon-reload 2>/dev/null || true
            echo
            echo -e "${GREEN}[OK] Configuration restored.${NC}"
            echo -e "${YELLOW}Now run Option 6 (Repair / Restart) to bring the tunnels back up.${NC}"
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid option.${NC}"; sleep 1; return ;;
    esac
    read -p "Press Enter to return to menu..."
}

get_boot_id() {
    if [[ -r /proc/sys/kernel/random/boot_id ]]; then
        cat /proc/sys/kernel/random/boot_id
    else
        echo "default-boot"
    fi
}

get_chain_bytes() {
    local chain="$1"
    local total=0
    local pkts bytes rest
    while read -r pkts bytes rest; do
        if [[ "$pkts" =~ ^[0-9]+$ && "$bytes" =~ ^[0-9]+$ ]]; then
            total=$(( total + bytes ))
        fi
    done < <(iptables -t mangle -L "$chain" -v -x -n 2>/dev/null || true)
    echo "$total"
}

format_traffic_size() {
    local bytes="${1:-0}"
    awk -v b="$bytes" 'BEGIN {
        kb = (b + 0.0) / 1024.0
        mb = kb / 1024.0
        gb = mb / 1024.0
        if (mb >= 1024.0 || sprintf("%.2f", mb) == "1024.00") {
            printf "%.2f GB", gb
        } else if (mb >= 1.0) {
            printf "%.2f MB", mb
        } else {
            printf "%.2f KB", kb
        }
    }'
}

format_live_speed() {
    local delta_bytes="${1:-0}"
    local delta_ns="${2:-1000000000}"
    awk -v db="$delta_bytes" -v dns="$delta_ns" 'BEGIN {
        if (db <= 0 || dns <= 0) {
            printf "0.00 KB/s  (0.00 Mbps)"
        } else {
            sec = (dns + 0.0) / 1000000000.0
            bps = (db + 0.0) / sec
            kbs = bps / 1024.0
            mbs = kbs / 1024.0
            mbps = (bps * 8.0) / 1000000.0
            if (mbs >= 1.0) {
                printf "%.2f MB/s  (%.2f Mbps)", mbs, mbps
            } else {
                printf "%.2f KB/s  (%.2f Mbps)", kbs, mbps
            }
        }
    }'
}

ensure_accounting_rules() {
    command -v iptables >/dev/null 2>&1 || return 0

    if [[ -f "$IRAN_CONF" ]]; then
        local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
        source "$IRAN_CONF"
        [[ -n "${SEC_SSH:-}" ]] || return 0

        iptables -t mangle -N PG_TUNNEL_IN 2>/dev/null || true
        iptables -t mangle -N PG_TUNNEL_OUT 2>/dev/null || true
        iptables -t mangle -C INPUT -j PG_TUNNEL_IN 2>/dev/null || \
            iptables -t mangle -I INPUT 1 -j PG_TUNNEL_IN
        iptables -t mangle -C OUTPUT -j PG_TUNNEL_OUT 2>/dev/null || \
            iptables -t mangle -I OUTPUT 1 -j PG_TUNNEL_OUT

        # Discover live TLS peer IPs (one per parallel channel / bind IP)
        local live_peers=() p stored=() s merged=() dup
        while read -r p; do
            [[ "$p" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            live_peers+=("$p")
        done < <(ss -tn state established 2>/dev/null | awk -v sp=":${SEC_SSH}" '$3 ~ sp"$" {sub(/:[0-9]+$/, "", $4); if ($4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $4}' | sort -u)
        if [[ -f "$PEER_IPS_FILE" ]]; then
            while read -r s; do
                [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
                stored+=("$s")
            done < "$PEER_IPS_FILE"
        fi
        for p in ${live_peers[@]+"${live_peers[@]}"} ${stored[@]+"${stored[@]}"}; do
            dup=0
            for s in ${merged[@]+"${merged[@]}"}; do
                [[ "$s" == "$p" ]] && dup=1
            done
            (( dup == 0 )) && merged+=("$p")
            (( ${#merged[@]} >= 8 )) && break
        done
        if (( ${#merged[@]} > 0 )); then
            mkdir -p "$CONF_DIR"
            printf '%s\n' "${merged[@]}" > "${PEER_IPS_FILE}.tmp.$$"
            mv -f "${PEER_IPS_FILE}.tmp.$$" "$PEER_IPS_FILE"
        fi

        # Per-peer rules first (first-match counters), catch-all last.
        # Rebuild only when the desired rule set differs (stale/duplicate safe).
        local want_n=$(( ${#merged[@]} + 1 )) have_n rebuild=0
        have_n=$(iptables -t mangle -S PG_TUNNEL_IN 2>/dev/null | grep -c '^-A ' || true)
        if [[ "$have_n" != "$want_n" ]]; then
            rebuild=1
        else
            for p in ${merged[@]+"${merged[@]}"}; do
                iptables -t mangle -C PG_TUNNEL_IN -s "$p" -p tcp --dport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
            done
            iptables -t mangle -C PG_TUNNEL_IN ! -i lo -p tcp --dport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
        fi
        if (( rebuild == 1 )); then
            iptables -t mangle -F PG_TUNNEL_IN 2>/dev/null || true
            for p in ${merged[@]+"${merged[@]}"}; do
                iptables -t mangle -A PG_TUNNEL_IN -s "$p" -p tcp --dport "$SEC_SSH" -j RETURN
            done
            iptables -t mangle -A PG_TUNNEL_IN ! -i lo -p tcp --dport "$SEC_SSH" -j RETURN
        fi

        rebuild=0
        have_n=$(iptables -t mangle -S PG_TUNNEL_OUT 2>/dev/null | grep -c '^-A ' || true)
        if [[ "$have_n" != "$want_n" ]]; then
            rebuild=1
        else
            for p in ${merged[@]+"${merged[@]}"}; do
                iptables -t mangle -C PG_TUNNEL_OUT -d "$p" -p tcp --sport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
            done
            iptables -t mangle -C PG_TUNNEL_OUT ! -o lo -p tcp --sport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
        fi
        if (( rebuild == 1 )); then
            iptables -t mangle -F PG_TUNNEL_OUT 2>/dev/null || true
            for p in ${merged[@]+"${merged[@]}"}; do
                iptables -t mangle -A PG_TUNNEL_OUT -d "$p" -p tcp --sport "$SEC_SSH" -j RETURN
            done
            iptables -t mangle -A PG_TUNNEL_OUT ! -o lo -p tcp --sport "$SEC_SSH" -j RETURN
        fi

    elif [[ -f "$FOREIGN_CONF" ]]; then
        local IR_IP="" SEC_SSH="" NODE_PORT="62075" DATA_PORTS="" TLS_SNI="www.microsoft.com" BIND_IPS="" TLS_SECRET=""
        source "$FOREIGN_CONF"
        [[ -n "${IR_IP:-}" && -n "${SEC_SSH:-}" ]] || return 0

        iptables -t mangle -N PG_TUNNEL_IN 2>/dev/null || true
        iptables -t mangle -N PG_TUNNEL_OUT 2>/dev/null || true
        iptables -t mangle -C INPUT -j PG_TUNNEL_IN 2>/dev/null || \
            iptables -t mangle -I INPUT 1 -j PG_TUNNEL_IN
        iptables -t mangle -C OUTPUT -j PG_TUNNEL_OUT 2>/dev/null || \
            iptables -t mangle -I OUTPUT 1 -j PG_TUNNEL_OUT

        local bips_list=() b
        for b in ${BIND_IPS//,/ }; do
            b=$(echo "$b" | xargs)
            [[ "$b" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            local seen=0
            for s in ${bips_list[@]+"${bips_list[@]}"}; do
                [[ "$s" == "$b" ]] && seen=1
            done
            (( seen == 0 )) && bips_list+=("$b")
        done

        local want_n=$(( ${#bips_list[@]} + 1 )) have_n rebuild=0
        have_n=$(iptables -t mangle -S PG_TUNNEL_IN 2>/dev/null | grep -c '^-A ' || true)
        if [[ "$have_n" != "$want_n" ]]; then
            rebuild=1
        else
            for b in ${bips_list[@]+"${bips_list[@]}"}; do
                iptables -t mangle -C PG_TUNNEL_IN -d "$b" -p tcp --sport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
            done
            iptables -t mangle -C PG_TUNNEL_IN -s "$IR_IP" -p tcp --sport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
        fi
        if (( rebuild == 1 )); then
            iptables -t mangle -F PG_TUNNEL_IN 2>/dev/null || true
            for b in ${bips_list[@]+"${bips_list[@]}"}; do
                iptables -t mangle -A PG_TUNNEL_IN -d "$b" -p tcp --sport "$SEC_SSH" -j RETURN
            done
            iptables -t mangle -A PG_TUNNEL_IN -s "$IR_IP" -p tcp --sport "$SEC_SSH" -j RETURN
        fi

        rebuild=0
        have_n=$(iptables -t mangle -S PG_TUNNEL_OUT 2>/dev/null | grep -c '^-A ' || true)
        if [[ "$have_n" != "$want_n" ]]; then
            rebuild=1
        else
            for b in ${bips_list[@]+"${bips_list[@]}"}; do
                iptables -t mangle -C PG_TUNNEL_OUT -s "$b" -d "$IR_IP" -p tcp --dport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
            done
            iptables -t mangle -C PG_TUNNEL_OUT -d "$IR_IP" -p tcp --dport "$SEC_SSH" -j RETURN 2>/dev/null || rebuild=1
        fi
        if (( rebuild == 1 )); then
            iptables -t mangle -F PG_TUNNEL_OUT 2>/dev/null || true
            for b in ${bips_list[@]+"${bips_list[@]}"}; do
                iptables -t mangle -A PG_TUNNEL_OUT -s "$b" -d "$IR_IP" -p tcp --dport "$SEC_SSH" -j RETURN
            done
            iptables -t mangle -A PG_TUNNEL_OUT -d "$IR_IP" -p tcp --dport "$SEC_SSH" -j RETURN
        fi
    fi

}

cleanup_accounting_rules() {
    command -v iptables >/dev/null 2>&1 || return 0
    local i=0
    while (( i < 20 )) && iptables -t mangle -D INPUT -j PG_TUNNEL_IN 2>/dev/null; do
        i=$(( i + 1 ))
    done
    i=0
    while (( i < 20 )) && iptables -t mangle -D OUTPUT -j PG_TUNNEL_OUT 2>/dev/null; do
        i=$(( i + 1 ))
    done
    iptables -t mangle -F PG_TUNNEL_IN 2>/dev/null || true
    iptables -t mangle -X PG_TUNNEL_IN 2>/dev/null || true
    iptables -t mangle -F PG_TUNNEL_OUT 2>/dev/null || true
    iptables -t mangle -X PG_TUNNEL_OUT 2>/dev/null || true
}

sync_traffic_state() {
    mkdir -p "$CONF_DIR"
    (
        flock -x 9

        local cur_boot k_rx k_tx
        cur_boot=$(get_boot_id)
        k_rx=$(get_chain_bytes "PG_TUNNEL_IN")
        k_tx=$(get_chain_bytes "PG_TUNNEL_OUT")

        local CREATED_AT="" BOOT_ID=""
        local SAVED_RX_BYTES=0 SAVED_TX_BYTES=0
        local LAST_KERNEL_RX=0 LAST_KERNEL_TX=0

        if [[ -f "$TRAFFIC_STATE" ]]; then
            source "$TRAFFIC_STATE"
        fi

        if [[ -z "$CREATED_AT" ]]; then
            CREATED_AT=$(date '+%Y-%m-%d %H:%M:%S')
            BOOT_ID="$cur_boot"
            SAVED_RX_BYTES="$k_rx"
            SAVED_TX_BYTES="$k_tx"
            LAST_KERNEL_RX="$k_rx"
            LAST_KERNEL_TX="$k_tx"
        else
            local delta_rx=0 delta_tx=0
            if [[ "$cur_boot" != "$BOOT_ID" ]]; then
                delta_rx="$k_rx"
                delta_tx="$k_tx"
            else
                if (( k_rx >= LAST_KERNEL_RX )); then
                    delta_rx=$(( k_rx - LAST_KERNEL_RX ))
                else
                    delta_rx="$k_rx"
                fi
                if (( k_tx >= LAST_KERNEL_TX )); then
                    delta_tx=$(( k_tx - LAST_KERNEL_TX ))
                else
                    delta_tx="$k_tx"
                fi
            fi

            SAVED_RX_BYTES=$(( SAVED_RX_BYTES + delta_rx ))
            SAVED_TX_BYTES=$(( SAVED_TX_BYTES + delta_tx ))
            LAST_KERNEL_RX="$k_rx"
            LAST_KERNEL_TX="$k_tx"
            BOOT_ID="$cur_boot"
        fi

        local tmp_file="${TRAFFIC_STATE}.tmp.$$"
        cat > "$tmp_file" <<EOF
CREATED_AT="${CREATED_AT}"
BOOT_ID="${BOOT_ID}"
SAVED_RX_BYTES=${SAVED_RX_BYTES}
SAVED_TX_BYTES=${SAVED_TX_BYTES}
LAST_KERNEL_RX=${LAST_KERNEL_RX}
LAST_KERNEL_TX=${LAST_KERNEL_TX}
EOF
        mv -f "$tmp_file" "$TRAFFIC_STATE"
        printf '%s|%s|%s\n' "$SAVED_RX_BYTES" "$SAVED_TX_BYTES" "$CREATED_AT"
    ) 9>"$TRAFFIC_LOCK"
}

reset_traffic_accounting() {
    mkdir -p "$CONF_DIR"
    cleanup_accounting_rules
    rm -f "$TRAFFIC_STATE" "${TRAFFIC_STATE}.tmp."*
}

setup_accounting_persistence() {
    ensure_accounting_rules
    sync_traffic_state >/dev/null

    if [[ ! -f "$ACCT_SERVICE" ]]; then
        cat > "$ACCT_SERVICE" <<'EOF'
[Unit]
Description=PG Tunnel Persistent Traffic Accounting
DefaultDependencies=no
After=local-fs.target systemd-sysctl.service netfilter-persistent.service
Before=network-online.target ssh.service pg-tls-server.service reverse-tunnel.service shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/pg-tunnel acct-init
ExecStop=/usr/local/bin/pg-tunnel acct-sync

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable pg-tunnel-acct.service >/dev/null 2>&1 || true
    fi

    if [[ ! -f "$ACCT_CRON_FILE" ]]; then
        echo "*/5 * * * * root /usr/local/bin/pg-tunnel acct-sync >/dev/null 2>&1" > "$ACCT_CRON_FILE"
        chmod 644 "$ACCT_CRON_FILE"
    fi
}

release_iran_tunnel_ports() {
    [[ -f "$IRAN_CONF" ]] || return 0
    local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
    source "$IRAN_CONF"

    local port_regex="" p
    IFS=',' read -ra _ports <<< "${NODE_PORT:-62075},${DATA_PORTS:-}"
    for p in "${_ports[@]}"; do
        p=$(echo "$p" | xargs)
        if [[ "$p" =~ ^[0-9]+$ && "$p" != "22" && "$p" != "${SEC_SSH:-}" ]]; then
            port_regex="${port_regex:+${port_regex}|}${p}"
        fi
    done
    [[ -n "$port_regex" ]] || return 0

    local pids=""
    pids=$(ss -tlnp 2>/dev/null | awk -v pr="^127\\.0\\.0\\.1:(${port_regex})$|^\\[::1\\]:(${port_regex})$" '
        $4 ~ pr && /sshd/ {
            if (match($0, /pid=[0-9]+/)) {
                pid = substr($0, RSTART + 4, RLENGTH - 4)
                if (!seen[pid]++) print pid
            }
        }' || true)

    if [[ -n "$pids" ]]; then
        local pid
        for pid in $pids; do
            kill -KILL "$pid" 2>/dev/null || true
        done
        sleep 0.2
    fi
}

migrate_existing_state() {
    if [[ -f "$TUNNEL_SERVICE" ]]; then
        local changed=0
        if grep -q '^StartLimitIntervalSec=' "$TUNNEL_SERVICE"; then
            if ! awk '/^\[Unit\]/{u=1; next} /^\[/{u=0} u && /^StartLimitIntervalSec=/{found=1} END{exit !found}' "$TUNNEL_SERVICE"; then
                sed -i '/^StartLimitIntervalSec=/d' "$TUNNEL_SERVICE"
                sed -i '/^\[Unit\]/a StartLimitIntervalSec=0' "$TUNNEL_SERVICE"
                changed=1
            fi
        fi
        if (( changed == 1 )); then
            systemctl daemon-reload 2>/dev/null || true
        fi

        if [[ -f "$FOREIGN_CONF" ]] && grep -q 'tls_client\.py' "$TUNNEL_SERVICE"; then
            if ! grep -q '^TLS_SNI=' "$FOREIGN_CONF"; then
                local parsed_sni=""
                parsed_sni=$(sed -n 's/.*tls_client\.py [^ ]* [^ ]* \([^ "]*\).*/\1/p' "$TUNNEL_SERVICE" | head -n 1)
                echo "TLS_SNI=${parsed_sni:-www.microsoft.com}" >> "$FOREIGN_CONF"
            fi
            if ! grep -q '^BIND_IPS=' "$FOREIGN_CONF"; then
                local parsed_bips=""
                parsed_bips=$(sed -n 's/.*tls_client\.py [^ ]* [^ ]* [^ "]* \([^ "]*\).*/\1/p' "$TUNNEL_SERVICE" | head -n 1)
                echo "BIND_IPS=${parsed_bips}" >> "$FOREIGN_CONF"
            fi
            write_tls_client_script
        fi
    fi

    if [[ -f "$IRAN_CONF" ]]; then
        if ! grep -q '^NODE_PORT=' "$IRAN_CONF"; then
            echo "NODE_PORT=62075" >> "$IRAN_CONF"
        fi
        if ! grep -q '^TLS_SNI=' "$IRAN_CONF"; then
            echo "TLS_SNI=www.microsoft.com" >> "$IRAN_CONF"
        fi
        if [[ -f /etc/ssh/sshd_config ]] && ! grep -q '^MaxStartups 150:30:300' /etc/ssh/sshd_config; then
            configure_iran_sshd_safe
        fi
    fi

    if [[ -f "$FOREIGN_CONF" && -f "$CRON_FILE" ]]; then
        if grep -q '^0 ' "$CRON_FILE"; then
            sed -i 's/^0 /1 /' "$CRON_FILE"
        fi
    fi
}

bootstrap_existing_accounting() {
    migrate_existing_state
    if [[ -f "$IRAN_CONF" || -f "$FOREIGN_CONF" ]]; then
        setup_accounting_persistence 2>/dev/null || true
    fi
}

handle_cli_subcommands() {
    case "${1:-}" in
        ensure-tuning)
            check_root
            ensure_network_tuning >/dev/null 2>&1 || true
            exit 0
            ;;
        reset-hostkey)
            check_root
            rm -f "$KNOWN_HOSTS_FILE"
            echo "[OK] Pinned SSH host keys cleared. They will be re-pinned on the next connection."
            exit 0
            ;;
        cron-auto-repair)
            check_root
            sync_traffic_state >/dev/null 2>&1 || true
            ensure_network_tuning >/dev/null 2>&1 || true
            if [[ -f "$IRAN_CONF" ]]; then
                local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
                source "$IRAN_CONF"
                if ! systemctl is-active --quiet ssh.service; then
                    systemctl restart ssh.service 2>/dev/null || true
                fi
                if [[ -f "$TLS_SERVER_SERVICE" ]] && ! systemctl is-active --quiet pg-tls-server.service; then
                    systemctl restart pg-tls-server.service 2>/dev/null || true
                fi
                if [[ -f "$WATCHDOG_SERVICE" ]] && ! systemctl is-active --quiet pg-tunnel-watchdog.service; then
                    systemctl restart pg-tunnel-watchdog.service 2>/dev/null || true
                fi
                IFS=',' read -ra PORTS <<< "$DATA_PORTS"
                for port in "${PORTS[@]}"; do
                    port=$(echo "$port" | xargs)
                    [[ -n "$port" ]] || continue
                    iptables -t nat -C OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || \
                    iptables -t nat -A OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
                done
                ensure_accounting_rules 2>/dev/null || true
                sync_traffic_state >/dev/null 2>&1 || true
            elif [[ -f "$FOREIGN_CONF" ]]; then
                ensure_accounting_rules 2>/dev/null || true
                if [[ -f "$MGMT_SERVICE" ]]; then
                    if ! systemctl is-active --quiet pg-tunnel-mgmt; then
                        systemctl restart pg-tunnel-mgmt 2>/dev/null || true
                    fi
                    local cu_file cu_name
                    for cu_file in $DATA_SERVICE_GLOB; do
                        [[ -f "$cu_file" ]] || continue
                        cu_name=$(basename "$cu_file" .service)
                        if ! systemctl is-active --quiet "$cu_name"; then
                            systemctl restart "$cu_name" 2>/dev/null || true
                        fi
                    done
                fi
                if [[ -f "$TUNNEL_SERVICE" ]] && ! systemctl is-active --quiet reverse-tunnel; then
                    systemctl restart reverse-tunnel 2>/dev/null || true
                fi
                sync_traffic_state >/dev/null 2>&1 || true
            fi
            exit 0
            ;;
        acct-init|acct-sync)
            check_root
            if [[ -f "$IRAN_CONF" || -f "$FOREIGN_CONF" ]]; then
                ensure_accounting_rules 2>/dev/null || true
                sync_traffic_state >/dev/null 2>&1 || true
            fi
            exit 0
            ;;
    esac
}

self_install() {
    if [[ "$(realpath "$0")" != "/usr/local/bin/pg-tunnel" ]]; then
        echo -e "${YELLOW}Installing pg-tunnel globally...${NC}"
        cp "$0" /usr/local/bin/pg-tunnel
        chmod +x /usr/local/bin/pg-tunnel
        echo -e "${GREEN}[OK] Installed! You can now run 'pg-tunnel' from anywhere.${NC}"
    fi
    mkdir -p "$CONF_DIR"
}

print_header() {
    clear 2>/dev/null || printf '\033[2J\033[H'
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${CYAN}       PG Node SSH Tunnel Manager v${SCRIPT_VERSION}${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

install_iran() {
    print_header
    echo -e "${CYAN}=== Configuring IRAN Server (Trojan-Style TLS 1.3 Anti-DPI) ===${NC}"
    echo

    local cur_out_ip="" cur_node_port="62075" cur_data_ports="" cur_sec="" cur_sni="" cur_secret=""
    if [[ -f "$IRAN_CONF" ]]; then
        local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
        source "$IRAN_CONF"
        cur_out_ip="${OUT_IP:-}"
        cur_node_port="${NODE_PORT:-62075}"
        cur_data_ports="${DATA_PORTS:-}"
        cur_sec="${SEC_SSH:-}"
        cur_sni="${TLS_SNI:-}"
        cur_secret="${TLS_SECRET:-}"
    fi

    while true; do
        if [[ -n "$cur_out_ip" ]]; then
            read -p "Foreign Server IP (PasarGuard Outbound IP) [default: ${cur_out_ip}]: " OUT_IP
            OUT_IP=${OUT_IP:-$cur_out_ip}
        else
            read -p "Foreign Server IP (PasarGuard Outbound IP): " OUT_IP
        fi
        OUT_IP=$(echo "$OUT_IP" | xargs)
        if is_valid_ipv4 "$OUT_IP"; then
            break
        fi
        echo -e "${RED}[ERROR] Required: please enter a valid IPv4 address (e.g. 147.90.59.178).${NC}"
    done

    while true; do
        read -p "Node management port [default: ${cur_node_port}]: " NODE_PORT
        NODE_PORT=${NODE_PORT:-$cur_node_port}
        NODE_PORT=$(echo "$NODE_PORT" | xargs)
        if is_valid_port "$NODE_PORT"; then
            break
        fi
        echo -e "${RED}[ERROR] Please enter a valid port number (1-65535).${NC}"
    done

    while true; do
        if [[ -n "$cur_data_ports" ]]; then
            read -p "Outbound data ports (comma separated) [default: ${cur_data_ports}]: " DATA_PORTS
            DATA_PORTS=${DATA_PORTS:-$cur_data_ports}
        else
            read -p "Outbound data ports (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
        fi
        if DATA_PORTS=$(normalize_ports_csv "$DATA_PORTS"); then
            break
        fi
        echo -e "${RED}[ERROR] Outbound data ports cannot be empty. Enter valid port numbers separated by commas.${NC}"
    done

    local suggested_port
    suggested_port=$(pick_free_https_port)
    [[ -n "$cur_sec" ]] && suggested_port="$cur_sec"
    while true; do
        read -p "Anti-DPI HTTPS Port [recommended free port: ${suggested_port}]: " SEC_SSH
        SEC_SSH=${SEC_SSH:-$suggested_port}
        SEC_SSH=$(echo "$SEC_SSH" | xargs)
        if ! is_valid_port "$SEC_SSH"; then
            echo -e "${RED}[ERROR] Invalid port number. Enter a value between 1 and 65535.${NC}"
            continue
        fi
        if [[ "$SEC_SSH" == "22" || "$SEC_SSH" == "80" || "$SEC_SSH" == "443" ]]; then
            echo -e "${RED}[ERROR] Do not use port ${SEC_SSH} (reserved for SSH/Caddy/Xray).${NC}"
            continue
        fi
        local conflict_proc=""
        conflict_proc=$(ss -tlnp 2>/dev/null | awk -v p=":${SEC_SSH}$" '$4 ~ p && $0 !~ /tls_server\.py/ {print $0}' || true)
        if [[ -n "$conflict_proc" ]]; then
            echo -e "${RED}[WARN] Port ${SEC_SSH} is currently occupied by another process:${NC}"
            echo "  $conflict_proc"
            echo -e "${YELLOW}Please pick another free port (e.g. 2087, 2083, 9443).${NC}"
            continue
        fi
        break
    done

    local detected_line="" det_dom="" det_crt="" det_key="" CERT_SRC="" KEY_SRC=""
    if detected_line=$(auto_detect_real_cert); then
        IFS='|' read -r det_dom det_crt det_key <<< "$detected_line"
        echo
        echo -e "${GREEN}[AUTO-DETECTED] Valid CA SSL Certificate found on this server:${NC}"
        echo -e "  Domain : ${CYAN}${det_dom}${NC}"
        echo -e "  Source : ${det_crt}"
    fi

    local default_sni="${det_dom:-${cur_sni:-www.microsoft.com}}"
    while true; do
        read -p "TLS Cover Domain (SNI) [default: ${default_sni}]: " TLS_SNI
        TLS_SNI=${TLS_SNI:-$default_sni}
        TLS_SNI=$(echo "$TLS_SNI" | xargs)
        if [[ -n "$TLS_SNI" && "$TLS_SNI" == *.* ]]; then
            break
        fi
        echo -e "${RED}[ERROR] Please enter a valid domain name.${NC}"
    done

    if [[ -n "$det_dom" && "$TLS_SNI" == "$det_dom" ]]; then
        CERT_SRC="$det_crt"
        KEY_SRC="$det_key"
    fi

    local default_secret="${cur_secret:-$(generate_secret)}"
    while true; do
        read -p "Anti-Prober Secret Key [Enter = ${default_secret}]: " TLS_SECRET
        TLS_SECRET=${TLS_SECRET:-$default_secret}
        TLS_SECRET=$(echo "$TLS_SECRET" | xargs)
        if [[ -n "$TLS_SECRET" ]]; then
            break
        fi
        echo -e "${RED}[ERROR] Secret key cannot be empty.${NC}"
    done

    if [[ ! -f "$IRAN_CONF" ]]; then
        reset_traffic_accounting
    elif [[ "$SEC_SSH" != "$cur_sec" ]]; then
        sync_traffic_state >/dev/null 2>&1 || true
        cleanup_accounting_rules
    fi

    cat > "$IRAN_CONF" <<EOF
OUT_IP=${OUT_IP}
NODE_PORT=${NODE_PORT}
DATA_PORTS=${DATA_PORTS}
SEC_SSH=${SEC_SSH}
TLS_SNI=${TLS_SNI}
TLS_SECRET=${TLS_SECRET}
FALLBACK_PORT=80
CERT_SRC=${CERT_SRC}
KEY_SRC=${KEY_SRC}
EOF

    apply_iran_configs
}

apply_iran_configs() {
    if [[ ! -f "$IRAN_CONF" ]]; then
        echo -e "${RED}[ERROR] Configuration not found. Run installation first.${NC}"
        sleep 2; return
    fi
    local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="www.microsoft.com" TLS_SECRET="" FALLBACK_PORT="80" CERT_SRC="" KEY_SRC=""
    source "$IRAN_CONF"
    TLS_SNI=${TLS_SNI:-www.microsoft.com}

    ensure_packages iptables-persistent netfilter-persistent openssh-server openssl python3

    echo -e "${YELLOW}Hardening SSH daemon (Port 22 + anti-brute-force preauth pool)...${NC}"
    configure_iran_sshd_safe

    echo -e "${YELLOW}Preparing TLS 1.3 Certificate & Trojan-Style Web Camouflage on Port ${SEC_SSH}...${NC}"
    write_tls_server_script

    if [[ -n "${CERT_SRC:-}" && -f "${CERT_SRC}" && -n "${KEY_SRC:-}" && -f "${KEY_SRC}" ]]; then
        cp -f "$CERT_SRC" "$TLS_CERT"
        cp -f "$KEY_SRC" "$TLS_KEY"
        chmod 600 "$TLS_KEY"
    else
        local detected_line="" d_dom="" d_crt="" d_key=""
        if detected_line=$(auto_detect_real_cert); then
            IFS='|' read -r d_dom d_crt d_key <<< "$detected_line"
            if [[ "$TLS_SNI" == "$d_dom" ]]; then
                cp -f "$d_crt" "$TLS_CERT"
                cp -f "$d_key" "$TLS_KEY"
                chmod 600 "$TLS_KEY"
            fi
        fi
        if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
                -keyout "$TLS_KEY" -out "$TLS_CERT" \
                -days 3650 -subj "/CN=${TLS_SNI}" \
                -addext "subjectAltName=DNS:${TLS_SNI}" >/dev/null 2>&1 || \
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout "$TLS_KEY" -out "$TLS_CERT" \
                -days 3650 -subj "/CN=${TLS_SNI}" >/dev/null 2>&1
            chmod 600 "$TLS_KEY"
        fi
    fi

    echo -e "${YELLOW}Hardening TLS wrapper (dedicated unprivileged user + systemd sandbox)...${NC}"
    if ! id -u pg-tunnel >/dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -d /nonexistent pg-tunnel 2>/dev/null || true
    fi
    chown pg-tunnel:pg-tunnel "$TLS_CERT" "$TLS_KEY" 2>/dev/null || true
    chmod 600 "$TLS_KEY" 2>/dev/null || true
    chown root:pg-tunnel "$IRAN_CONF" 2>/dev/null || true
    chmod 640 "$IRAN_CONF" 2>/dev/null || true

    cat > "$TLS_SERVER_SERVICE" <<EOF
[Unit]
Description=PG Tunnel Trojan-Style TLS 1.3 Anti-DPI Server
After=network-online.target ssh.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=pg-tunnel
Group=pg-tunnel
ExecStart=/usr/bin/python3 ${TLS_SERVER_PY} ${TLS_CERT} ${TLS_KEY} ${SEC_SSH} 22
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/pg-tunnel
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable pg-tls-server.service >/dev/null 2>&1
    systemctl restart pg-tls-server.service

    echo -e "${YELLOW}Enabling end-to-end watchdog & port-22 brute-force shield...${NC}"
    write_watchdog_script
    cat > "$WATCHDOG_SERVICE" <<EOF
[Unit]
Description=PG Tunnel End-to-End Watchdog (Listener + TLS Session Monitor)
After=network-online.target pg-tls-server.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/bin/bash ${WATCHDOG_SH}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable pg-tunnel-watchdog.service >/dev/null 2>&1
    systemctl restart pg-tunnel-watchdog.service

    if [[ ! -f "$SSHBF_DISABLED_FILE" ]]; then
        enable_brute_force_shield || true
    fi

    echo -e "${YELLOW}Applying targeted iptables NAT REDIRECT rules...${NC}"
    IFS=',' read -ra PORTS <<< "$DATA_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        [[ -n "$port" ]] || continue
        iptables -t nat -C OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || \
        iptables -t nat -A OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port"
        echo "  -> Redirected $OUT_IP:$port"
    done

    setup_accounting_persistence
    netfilter-persistent save >/dev/null 2>&1 || true

    local pub_ir_ip
    pub_ir_ip=$(detect_public_ipv4s | cut -d',' -f1)
    pub_ir_ip=${pub_ir_ip:-"<IRAN_IP>"}

    echo
    echo -e "${GREEN}[OK] Iran server configured successfully ($(get_cert_badge) certificate active).${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${CYAN}  ENTER THESE EXACT VALUES ON YOUR FOREIGN SERVER (Option 1):${NC}"
    echo -e "  Iran Server IP : ${YELLOW}${pub_ir_ip}${NC}"
    echo -e "  TLS Port       : ${YELLOW}${SEC_SSH}${NC}"
    echo -e "  TLS SNI Domain : ${YELLOW}${TLS_SNI}${NC}"
    echo -e "  TLS Secret Key : ${YELLOW}${TLS_SECRET}${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo
    read -p "Press Enter to return to menu..."
}

install_foreign() {
    print_header
    echo -e "${CYAN}=== Configuring FOREIGN Server (TLS 1.3 + Secret + Multi-IP) ===${NC}"
    echo

    ensure_packages openssh-client openssl python3

    local cur_ir_ip="" cur_sec="2087" cur_sni="" cur_secret="" cur_node="62075" cur_data="" cur_bips=""
    if [[ -f "$FOREIGN_CONF" ]]; then
        local IR_IP="" SEC_SSH="" NODE_PORT="62075" DATA_PORTS="" TLS_SNI="" BIND_IPS="" TLS_SECRET=""
        source "$FOREIGN_CONF"
        cur_ir_ip="${IR_IP:-}"
        cur_sec="${SEC_SSH:-2087}"
        cur_sni="${TLS_SNI:-}"
        cur_secret="${TLS_SECRET:-}"
        cur_node="${NODE_PORT:-62075}"
        cur_data="${DATA_PORTS:-}"
        cur_bips="${BIND_IPS:-}"
    fi

    while true; do
        if [[ -n "$cur_ir_ip" ]]; then
            read -p "Iran Server IP [default: ${cur_ir_ip}]: " IR_IP
            IR_IP=${IR_IP:-$cur_ir_ip}
        else
            read -p "Iran Server IP: " IR_IP
        fi
        IR_IP=$(echo "$IR_IP" | xargs)
        if is_valid_ipv4 "$IR_IP"; then
            break
        fi
        echo -e "${RED}[ERROR] Required: please enter a valid Iran Server IPv4 address.${NC}"
    done

    while true; do
        read -p "Anti-DPI HTTPS Port on Iran [default: ${cur_sec}]: " SEC_SSH
        SEC_SSH=${SEC_SSH:-$cur_sec}
        SEC_SSH=$(echo "$SEC_SSH" | xargs)
        if is_valid_port "$SEC_SSH"; then
            break
        fi
        echo -e "${RED}[ERROR] Please enter a valid port number (1-65535).${NC}"
    done

    while true; do
        if [[ -n "$cur_sni" ]]; then
            read -p "TLS SNI Domain (from Iran summary) [default: ${cur_sni}]: " TLS_SNI
            TLS_SNI=${TLS_SNI:-$cur_sni}
        else
            read -p "TLS SNI Domain (paste from Iran summary): " TLS_SNI
        fi
        TLS_SNI=$(echo "$TLS_SNI" | xargs)
        if [[ -n "$TLS_SNI" && "$TLS_SNI" == *.* ]]; then
            break
        fi
        echo -e "${RED}[ERROR] TLS SNI Domain cannot be empty (paste exact domain shown on Iran server).${NC}"
    done

    while true; do
        if [[ -n "$cur_secret" ]]; then
            read -p "TLS Secret Key (from Iran summary) [default: ${cur_secret}]: " TLS_SECRET
            TLS_SECRET=${TLS_SECRET:-$cur_secret}
        else
            read -p "TLS Secret Key (paste from Iran summary): " TLS_SECRET
        fi
        TLS_SECRET=$(echo "$TLS_SECRET" | xargs)
        if [[ -n "$TLS_SECRET" ]]; then
            break
        fi
        echo -e "${RED}[ERROR] TLS Secret Key cannot be empty (paste exact key shown on Iran server).${NC}"
    done

    while true; do
        read -p "Node management port [default: ${cur_node}]: " NODE_PORT
        NODE_PORT=${NODE_PORT:-$cur_node}
        NODE_PORT=$(echo "$NODE_PORT" | xargs)
        if is_valid_port "$NODE_PORT"; then
            break
        fi
        echo -e "${RED}[ERROR] Please enter a valid port number (1-65535).${NC}"
    done

    while true; do
        if [[ -n "$cur_data" ]]; then
            read -p "Outbound data ports to tunnel [default: ${cur_data}]: " DATA_PORTS
            DATA_PORTS=${DATA_PORTS:-$cur_data}
        else
            read -p "Outbound data ports to tunnel (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
        fi
        if DATA_PORTS=$(normalize_ports_csv "$DATA_PORTS"); then
            break
        fi
        echo -e "${RED}[ERROR] Outbound data ports cannot be empty. Enter valid port numbers separated by commas.${NC}"
    done

    local detected_ips
    detected_ips=$(detect_public_ipv4s)
    if [[ -n "$detected_ips" ]]; then
        echo -e "${CYAN}Detected Public IPv4s on this server:${NC} ${detected_ips}"
    fi
    while true; do
        if [[ -n "$cur_bips" ]]; then
            read -p "Source Bind IPs for failover [default: ${cur_bips}]: " BIND_IPS
            BIND_IPS=${BIND_IPS:-$cur_bips}
        else
            read -p "Optional Clean Source Bind IPs (comma separated, Enter = Auto/Default): " BIND_IPS
        fi
        if BIND_IPS=$(normalize_bind_ips_csv "$BIND_IPS"); then
            break
        fi
    done

    if [[ ! -f "$FOREIGN_CONF" ]]; then
        reset_traffic_accounting
    elif [[ "$SEC_SSH" != "$cur_sec" || "$IR_IP" != "$cur_ir_ip" ]]; then
        sync_traffic_state >/dev/null 2>&1 || true
        cleanup_accounting_rules
    fi
    rm -f "$LAST_GOOD_IP_FILE"

    cat > "$FOREIGN_CONF" <<EOF
IR_IP=${IR_IP}
SEC_SSH=${SEC_SSH}
NODE_PORT=${NODE_PORT}
DATA_PORTS=${DATA_PORTS}
TLS_SNI=${TLS_SNI}
BIND_IPS=${BIND_IPS}
TLS_SECRET=${TLS_SECRET}
EOF

    write_tls_client_script

    echo -e "${YELLOW}Checking SSH key & TLS 1.3 connectivity to Iran...${NC}"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    if [[ ! -f /root/.ssh/tunnel_key ]]; then
        ssh-keygen -t ed25519 -f /root/.ssh/tunnel_key -N "" -q
    fi

    local proxy_opt="ProxyCommand=/usr/bin/python3 ${TLS_CLIENT_PY} ${IR_IP} ${SEC_SSH} ${TLS_SNI} '${BIND_IPS}' '${TLS_SECRET}' probe"
    if ssh -i /root/.ssh/tunnel_key -o "$proxy_opt" -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${KNOWN_HOSTS_FILE} root@"$IR_IP" "true" >/dev/null 2>&1; then
        echo -e "${GREEN}[OK] SSH public key already verified over TLS 1.3 + Secret!${NC}"
    else
        local key_ok=0 attempt=0
        for attempt in 1 2 3; do
            echo -e "${CYAN}Enter Iran Server root password once to authorize SSH key over TLS 1.3 (attempt ${attempt}/3):${NC}"
            if ssh-copy-id -i /root/.ssh/tunnel_key.pub \
                -o "$proxy_opt" \
                -o StrictHostKeyChecking=accept-new \
                -o UserKnownHostsFile=${KNOWN_HOSTS_FILE} \
                -o ConnectTimeout=20 \
                root@"$IR_IP"; then
                key_ok=1
                break
            fi
            echo -e "${YELLOW}[WARN] ssh-copy-id attempt ${attempt} failed (wrong password or transient timeout).${NC}"
            sleep 2
        done
        if (( key_ok == 0 )); then
            echo -e "${RED}[ERROR] Could not authorize the SSH key after 3 attempts. Check the Iran root password / TLS settings, then re-run Install.${NC}"
            read -p "Press Enter to return to menu..."
            return
        fi
    fi

    apply_foreign_configs
}

apply_foreign_configs() {
    if [[ ! -f "$FOREIGN_CONF" ]]; then
        echo -e "${RED}[ERROR] Configuration not found. Run installation first.${NC}"
        sleep 2; return
    fi
    local IR_IP="" SEC_SSH="" NODE_PORT="62075" DATA_PORTS="" TLS_SNI="www.microsoft.com" BIND_IPS="" TLS_SECRET=""
    source "$FOREIGN_CONF"
    TLS_SNI=${TLS_SNI:-www.microsoft.com}

    ensure_packages openssh-client openssl python3
    write_tls_client_script
    setup_accounting_persistence

    echo -e "${YELLOW}Creating parallel multi-channel reverse tunnel services (TLS 1.3 + Secret + Failover)...${NC}"

    if [[ -f "$TUNNEL_SERVICE" ]]; then
        systemctl stop reverse-tunnel 2>/dev/null || true
        systemctl disable reverse-tunnel 2>/dev/null || true
        rm -f "$TUNNEL_SERVICE"
        echo -e "  -> Legacy single-tunnel service decommissioned (split into independent parallel channels)."
    fi

    local bind_pool=() n_bips=0 idx=0 prefer=""
    if [[ -n "${BIND_IPS:-}" ]]; then
        IFS=',' read -ra bind_pool <<< "$BIND_IPS"
        n_bips=${#bind_pool[@]}
    fi
    local proxy_base="/usr/bin/python3 ${TLS_CLIENT_PY} ${IR_IP} ${SEC_SSH} ${TLS_SNI} '${BIND_IPS}' '${TLS_SECRET}'"

    cat > "$MGMT_SERVICE" <<EOF
[Unit]
Description=PG Tunnel Management Channel (Node Port ${NODE_PORT}) over TLS 1.3
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/ssh -R ${NODE_PORT}:127.0.0.1:${NODE_PORT} root@${IR_IP} -N -i /root/.ssh/tunnel_key -o "ProxyCommand=${proxy_base} mgmt '' ${NODE_PORT}" -o ConnectTimeout=15 -o TCPKeepAlive=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=2 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${KNOWN_HOSTS_FILE} -o Compression=no -c ${SSH_CIPHERS}
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    local new_units=() port="" unit_file="" unit_name=""
    IFS=',' read -ra PORTS <<< "$DATA_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        [[ -n "$port" ]] || continue
        prefer=""
        if (( n_bips > 0 )); then
            prefer=$(echo "${bind_pool[$(( idx % n_bips ))]}" | xargs)
        fi
        unit_file="/etc/systemd/system/pg-tunnel-data-${port}.service"
        cat > "$unit_file" <<EOF
[Unit]
Description=PG Tunnel Data Channel (Port ${port}) over TLS 1.3
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/ssh -R ${port}:127.0.0.1:${port} root@${IR_IP} -N -i /root/.ssh/tunnel_key -o "ProxyCommand=${proxy_base} data '${prefer}' ${port}" -o ConnectTimeout=15 -o TCPKeepAlive=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=2 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${KNOWN_HOSTS_FILE} -o Compression=no -c ${SSH_CIPHERS}
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
        new_units+=("pg-tunnel-data-${port}")
        idx=$(( idx + 1 ))
    done

    local f="" base="" keep=0
    for f in $DATA_SERVICE_GLOB; do
        [[ -f "$f" ]] || continue
        base=$(basename "$f" .service)
        keep=0
        for unit_name in ${new_units[@]+"${new_units[@]}"}; do
            [[ "$base" == "$unit_name" ]] && keep=1
        done
        if (( keep == 0 )); then
            systemctl stop "$base" 2>/dev/null || true
            systemctl disable "$base" 2>/dev/null || true
            rm -f "$f"
        fi
    done

    systemctl daemon-reload
    systemctl enable pg-tunnel-mgmt >/dev/null 2>&1
    systemctl restart pg-tunnel-mgmt
    for unit_name in ${new_units[@]+"${new_units[@]}"}; do
        systemctl enable "$unit_name" >/dev/null 2>&1
        systemctl restart "$unit_name"
    done

    sleep 3
    echo
    echo -e "${CYAN}--- Parallel Channel Status ---${NC}"
    if systemctl is-active --quiet pg-tunnel-mgmt; then
        echo -e "  mgmt (Node ${NODE_PORT}) : ${GREEN}ACTIVE${NC}"
    else
        echo -e "  mgmt (Node ${NODE_PORT}) : ${RED}FAILED${NC}"
    fi
    for unit_name in ${new_units[@]+"${new_units[@]}"}; do
        if systemctl is-active --quiet "$unit_name"; then
            echo -e "  data (${unit_name#pg-tunnel-data-}) : ${GREEN}ACTIVE${NC}"
        else
            echo -e "  data (${unit_name#pg-tunnel-data-}) : ${RED}FAILED${NC}"
        fi
    done

    if systemctl is-active --quiet pg-tunnel-mgmt || [[ ${#new_units[@]} -gt 0 ]]; then
        echo
        echo -e "${GREEN}[OK] Foreign server active & connected over TLS 1.3 (${IR_IP}:${SEC_SSH}, SNI: ${TLS_SNI}).${NC}"
    else
        echo -e "${RED}[ERROR] Tunnel channels failed to connect. Check logs (Other Options -> 1) or verify Secret/Port.${NC}"
    fi
    echo
    read -p "Press Enter to return to menu..."
}

manage_service() {
    local c_green=$'\033[0;32m'
    local c_red=$'\033[0;31m'
    local c_yellow=$'\033[1;33m'
    local c_cyan=$'\033[0;36m'
    local c_nc=$'\033[0m'
    local clr_eol=$'\033[K'
    local nl=$'\n'

    local is_configured=0
    local is_foreign=0
    if [[ -f "$FOREIGN_CONF" ]]; then
        is_configured=1
        is_foreign=1
        ensure_accounting_rules
    elif [[ -f "$IRAN_CONF" ]]; then
        is_configured=1
        ensure_accounting_rules
    fi

    local prev_krx=0 prev_ktx=0 prev_ns=0
    local cur_krx=0 cur_ktx=0 cur_ns=0
    local state_line="" created_at="Not configured"
    if (( is_configured == 1 )); then
        prev_krx=$(get_chain_bytes "PG_TUNNEL_IN")
        prev_ktx=$(get_chain_bytes "PG_TUNNEL_OUT")
        prev_ns=$(date +%s%N)
        sleep 0.25
    fi

    printf '\033[?1049h\033[?25l\033[2J\033[H'
    local cleanup_done=0
    restore_terminal() {
        if (( cleanup_done == 0 )); then
            cleanup_done=1
            printf '\033[?25h\033[?1049l'
        fi
    }
    trap 'restore_terminal; exit 0' INT TERM

    while true; do
        local dl_bytes=0 ul_bytes=0 dl_delta=0 ul_delta=0 elapsed_ns=1000000000
        if (( is_configured == 1 )); then
            cur_krx=$(get_chain_bytes "PG_TUNNEL_IN")
            cur_ktx=$(get_chain_bytes "PG_TUNNEL_OUT")
            cur_ns=$(date +%s%N)

            state_line=$(sync_traffic_state)
            local raw_saved_rx=0 raw_saved_tx=0
            IFS='|' read -r raw_saved_rx raw_saved_tx created_at <<< "$state_line"

            elapsed_ns=$(( cur_ns - prev_ns ))
            (( elapsed_ns <= 0 )) && elapsed_ns=1000000000

            local delta_rx=$(( cur_krx - prev_krx ))
            local delta_tx=$(( cur_ktx - prev_ktx ))
            (( delta_rx < 0 )) && delta_rx=0
            (( delta_tx < 0 )) && delta_tx=0

            if (( is_foreign == 1 )); then
                # On Foreign server: TX to Iran = User Download, RX from Iran = User Upload
                dl_bytes="$raw_saved_tx"
                ul_bytes="$raw_saved_rx"
                dl_delta="$delta_tx"
                ul_delta="$delta_rx"
            else
                # On Iran server: RX from Foreign = User Download, TX to Foreign = User Upload
                dl_bytes="$raw_saved_rx"
                ul_bytes="$raw_saved_tx"
                dl_delta="$delta_rx"
                ul_delta="$delta_tx"
            fi

            prev_krx="$cur_krx"
            prev_ktx="$cur_ktx"
            prev_ns="$cur_ns"
        fi

        local dl_total ul_total sum_total dl_speed ul_speed
        dl_total=$(format_traffic_size "$dl_bytes")
        ul_total=$(format_traffic_size "$ul_bytes")
        sum_total=$(format_traffic_size "$(( dl_bytes + ul_bytes ))")
        dl_speed=$(format_live_speed "$dl_delta" "$elapsed_ns")
        ul_speed=$(format_live_speed "$ul_delta" "$elapsed_ns")

        local r_dl_spd="" r_ul_spd="" r_dl_tot="" r_ul_tot="" r_sum_tot=""
        printf -v r_dl_spd  "  Download Speed     : %s%s%s%s" "$c_green" "$dl_speed" "$c_nc" "$clr_eol"
        printf -v r_ul_spd  "  Upload Speed       : %s%s%s%s" "$c_yellow" "$ul_speed" "$c_nc" "$clr_eol"
        printf -v r_dl_tot  "  Download Used      : %s%s%s%s" "$c_green" "$dl_total" "$c_nc" "$clr_eol"
        printf -v r_ul_tot  "  Upload Used        : %s%s%s%s" "$c_yellow" "$ul_total" "$c_nc" "$clr_eol"
        printf -v r_sum_tot "  Total Traffic Used : %s%s%s%s" "$c_cyan" "$sum_total" "$c_nc" "$clr_eol"

        local frame=""
        frame+="${c_green}============================================================${c_nc}${clr_eol}${nl}"
        frame+="${c_cyan}  PG Node SSH Tunnel Manager v${SCRIPT_VERSION}         [Live $(date '+%H:%M:%S')]${c_nc}${clr_eol}${nl}"
        frame+="${c_green}============================================================${c_nc}${clr_eol}${nl}"
        frame+="${c_cyan}=== Live Tunnel Speed ===${c_nc}${clr_eol}${nl}"
        frame+="${r_dl_spd}${nl}"
        frame+="${r_ul_spd}${nl}"
        frame+="------------------------------------------------------------${clr_eol}${nl}"
        frame+="${c_cyan}=== Cumulative Traffic Usage (Since: ${created_at}) ===${c_nc}${clr_eol}${nl}"
        frame+="${r_dl_tot}${nl}"
        frame+="${r_ul_tot}${nl}"
        frame+="${r_sum_tot}${nl}"
        frame+="------------------------------------------------------------${clr_eol}${nl}"

        frame+="${c_cyan}=== System & Anti-DPI Status ===${c_nc}${clr_eol}${nl}"
        if [[ -f "$MGMT_SERVICE" || -f "$TUNNEL_SERVICE" ]]; then
            local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS="" TLS_SNI="www.microsoft.com" BIND_IPS="" TLS_SECRET=""
            [[ -f "$FOREIGN_CONF" ]] && source "$FOREIGN_CONF"
            local active_ip auth_tag last_log ch_state ch_file ch_unit
            active_ip="Default"
            [[ -f "$LAST_GOOD_IP_FILE" ]] && active_ip=$(cat "$LAST_GOOD_IP_FILE" 2>/dev/null | xargs || echo "Default")
            auth_tag="Legacy"
            [[ -n "${TLS_SECRET:-}" ]] && auth_tag="Secret+WS-Camo"
            frame+="  TLS 1.3 Target     : ${IR_IP:-N/A}:${SEC_SSH:-N/A} | SNI: ${TLS_SNI} [${auth_tag}]${clr_eol}${nl}"
            frame+="  Bind IP Pool       : ${BIND_IPS:-Default} (Last Good: ${active_ip})${clr_eol}${nl}"
            frame+="  Tunnel Ports       : Node ${NODE_PORT:-N/A} | Data ${DATA_PORTS:-N/A}${clr_eol}${nl}"
            local kcc kqd knl
            kcc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
            kqd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
            knl=$(sysctl -n net.ipv4.tcp_notsent_lowat 2>/dev/null || echo "?")
            if [[ "$kcc" == "bbr" && "$kqd" == "fq" ]]; then
                frame+="  Kernel Tuning      : ${c_green}${kcc} / ${kqd} / notsent_lowat=${knl}${c_nc}${clr_eol}${nl}"
            else
                frame+="  Kernel Tuning      : ${c_yellow}${kcc} / ${kqd} / notsent_lowat=${knl} (run Option 4)${c_nc}${clr_eol}${nl}"
            fi
            frame+="  --- Parallel Channels ---${clr_eol}${nl}"
            if [[ -f "$MGMT_SERVICE" ]]; then
                ch_state=$(systemctl is-active pg-tunnel-mgmt 2>/dev/null || true)
                [[ -z "$ch_state" ]] && ch_state="unknown"
                if [[ "$ch_state" == "active" ]]; then
                    frame+="  Channel mgmt       : ${c_green}${ch_state}${c_nc} (Node Port ${NODE_PORT:-N/A})${clr_eol}${nl}"
                else
                    frame+="  Channel mgmt       : ${c_red}${ch_state}${c_nc} (Node Port ${NODE_PORT:-N/A})${clr_eol}${nl}"
                fi
                for ch_file in $DATA_SERVICE_GLOB; do
                    [[ -f "$ch_file" ]] || continue
                    ch_unit=$(basename "$ch_file" .service)
                    ch_state=$(systemctl is-active "$ch_unit" 2>/dev/null || true)
                    [[ -z "$ch_state" ]] && ch_state="unknown"
                    if [[ "$ch_state" == "active" ]]; then
                        frame+="  Channel data       : ${c_green}${ch_state}${c_nc} (Port ${ch_unit#pg-tunnel-data-})${clr_eol}${nl}"
                    else
                        frame+="  Channel data       : ${c_red}${ch_state}${c_nc} (Port ${ch_unit#pg-tunnel-data-})${clr_eol}${nl}"
                    fi
                done
            fi
            if [[ -f "$TUNNEL_SERVICE" ]]; then
                ch_state=$(systemctl is-active reverse-tunnel 2>/dev/null || true)
                [[ -z "$ch_state" ]] && ch_state="unknown"
                if [[ "$ch_state" == "active" ]]; then
                    frame+="  Channel legacy     : ${c_green}${ch_state}${c_nc} (single-tunnel, pre-v7)${clr_eol}${nl}"
                else
                    frame+="  Channel legacy     : ${c_red}${ch_state}${c_nc} (single-tunnel, pre-v7)${clr_eol}${nl}"
                fi
            fi
            local ip_pairs ip_ip ip_bytes
            ip_pairs=$(iptables -t mangle -L PG_TUNNEL_OUT -v -x -n 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $8 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $8, $2}' | sort -k2 -rn | head -4 || true)
            if [[ -n "$ip_pairs" ]]; then
                frame+="  --- Per-IP Channel Usage ---${clr_eol}${nl}"
                while IFS=' ' read -r ip_ip ip_bytes; do
                    [[ -n "$ip_ip" ]] || continue
                    frame+="    ${ip_ip} : $(format_traffic_size "$ip_bytes")${clr_eol}${nl}"
                done <<< "$ip_pairs"
            fi
            last_log=$(journalctl -u pg-tunnel-mgmt --no-pager -n 1 --output=cat 2>/dev/null | cut -c1-56 || true)
            [[ -z "$last_log" && -f "$TUNNEL_SERVICE" ]] && last_log=$(journalctl -u reverse-tunnel --no-pager -n 1 --output=cat 2>/dev/null | cut -c1-56 || true)
            [[ -n "$last_log" ]] && frame+="  Latest Log         : ${last_log}${clr_eol}${nl}"
        else
            local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="www.microsoft.com" TLS_SECRET=""
            [[ -f "$IRAN_CONF" ]] && source "$IRAN_CONF"
            local tls_status="${c_red}Inactive${c_nc}" cert_badge auth_mode="Legacy"
            cert_badge=$(get_cert_badge)
            [[ -n "${TLS_SECRET:-}" ]] && auth_mode="Trojan-Auth+WebCamo"
            if systemctl is-active --quiet pg-tls-server.service 2>/dev/null; then
                tls_status="${c_green}Active on Port ${SEC_SSH} (${cert_badge}, ${auth_mode})${c_nc}"
            fi
            frame+="  TLS 1.3 Server     : ${tls_status}${clr_eol}${nl}"
            frame+="  Cover Domain       : ${TLS_SNI:-N/A}${clr_eol}${nl}"

            local ssh_ports tunnel_ports
            ssh_ports=$(ss -tlnp 2>/dev/null | awk '/sshd/ && $4 !~ /^127\./ && $4 !~ /^\[::1\]/ {sub(/.*:/,"",$4); if(!seen[$4]++) out=out (out?", ":"") $4} END{print out ? out : "None"}')
            tunnel_ports=$(ss -tlnp 2>/dev/null | awk '/sshd/ && ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) {sub(/.*:/,"",$4); if(!seen[$4]++) out=out (out?", ":"") $4} END{print out ? out : "None"}')
            frame+="  SSH / Tunnel Ports : SSH [${ssh_ports}] | Local [${tunnel_ports}]${clr_eol}${nl}"
            local wd_status="Inactive" wd_line="N/A" shield_status="Disabled" est_count=0
            if systemctl is-active --quiet pg-tunnel-watchdog.service 2>/dev/null; then
                wd_status="Active"
            fi
            [[ -r "$WATCHDOG_STATE" ]] && wd_line=$(cut -d'|' -f1 "$WATCHDOG_STATE" 2>/dev/null | xargs || true)
            [[ -z "$wd_line" ]] && wd_line="N/A"
            if iptables -C INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; then
                shield_status="Active on Port 22 (8/60s)"
            fi
            est_count=$(ss -tn state established 2>/dev/null | awk -v sp=":${SEC_SSH}" '$3 ~ sp"$" {n++} END{print n+0}')
            frame+="  End-to-End Watchdog : ${wd_status} (${wd_line})${clr_eol}${nl}"
            frame+="  Brute-Force Shield  : ${shield_status}${clr_eol}${nl}"
            frame+="  TLS Client Sessions : ${est_count}${clr_eol}${nl}"
            local kcc kqd knl
            kcc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
            kqd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
            knl=$(sysctl -n net.ipv4.tcp_notsent_lowat 2>/dev/null || echo "?")
            if [[ "$kcc" == "bbr" && "$kqd" == "fq" ]]; then
                frame+="  Kernel Tuning      : ${c_green}${kcc} / ${kqd} / notsent_lowat=${knl}${c_nc}${clr_eol}${nl}"
            else
                frame+="  Kernel Tuning      : ${c_yellow}${kcc} / ${kqd} / notsent_lowat=${knl} (run Option 4)${c_nc}${clr_eol}${nl}"
            fi
            local ip_pairs ip_ip ip_bytes
            ip_pairs=$(iptables -t mangle -L PG_TUNNEL_IN -v -x -n 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $8 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $8, $2}' | sort -k2 -rn | head -4 || true)
            if [[ -n "$ip_pairs" ]]; then
                frame+="  --- Per-IP Channel Usage ---${clr_eol}${nl}"
                while IFS=' ' read -r ip_ip ip_bytes; do
                    [[ -n "$ip_ip" ]] || continue
                    frame+="    ${ip_ip} : $(format_traffic_size "$ip_bytes")${clr_eol}${nl}"
                done <<< "$ip_pairs"
            fi
            frame+="  NAT OUTPUT Rules   :${clr_eol}${nl}"
            local nat_summary
            nat_summary=$(iptables -t nat -L OUTPUT -n -v --line-numbers 2>/dev/null | awk '
                NR > 2 && NF >= 10 {
                    rule = "    #" $1 " " $4 " -> " $10
                    if ($4 == "REDIRECT") rule = rule ":" $12 " => :" $NF
                    print rule " (pkts:" $2 ", " $3 ")"
                }' | head -n 6 || true)
            if [[ -n "$nat_summary" ]]; then
                local nline
                while IFS= read -r nline; do
                    frame+="${nline}${clr_eol}${nl}"
                done <<< "$nat_summary"
            else
                frame+="    (No active NAT OUTPUT rules)${clr_eol}${nl}"
            fi
        fi

        frame+="${c_cyan}=== Smart Auto-Heal Cronjob ===${c_nc}${clr_eol}${nl}"
        if [[ -f "$CRON_FILE" ]]; then
            local cron_sched
            cron_sched=$(awk '{print $1" "$2" "$3" "$4" "$5}' "$CRON_FILE" 2>/dev/null || echo "Active")
            frame+="  Schedule           : ${c_green}Active (${cron_sched})${c_nc}${clr_eol}${nl}"
        else
            frame+="  Schedule           : ${c_yellow}Disabled${c_nc}${clr_eol}${nl}"
        fi
        frame+="------------------------------------------------------------${clr_eol}${nl}"
        frame+="${c_yellow}Updating every 1s... Press [Enter] or [q] to return to menu.${c_nc}${clr_eol}"

        printf '\033[H%s\033[J' "$frame"

        local key="" t_wait_start t_wait_end
        t_wait_start=$(date +%s%N)
        if IFS= read -r -s -n 1 -t 1 key; then
            if [[ -z "$key" || "$key" == $'\r' || "$key" == $'\n' || "$key" == "q" || "$key" == "Q" || "$key" == "0" ]]; then
                read -r -s -t 0.02 -n 100 _ 2>/dev/null || true
                break
            fi
        else
            t_wait_end=$(date +%s%N)
            if (( t_wait_end - t_wait_start < 200000000 )); then
                sleep 1
            fi
        fi
    done

    trap - INT TERM
    restore_terminal
}

uninstall_all() {
    print_header
    echo -e "${RED}=== Safe Uninstall ===${NC}"
    rm -f "$CRON_FILE" "$ACCT_CRON_FILE"
    systemctl disable pg-tunnel-net-tune.service >/dev/null 2>&1 || true
    rm -f "$NET_TUNE_SERVICE"

    if [[ -f "$ACCT_SERVICE" ]]; then
        systemctl disable pg-tunnel-acct.service >/dev/null 2>&1 || true
        rm -f "$ACCT_SERVICE"
    fi

    cleanup_accounting_rules

    if [[ -f "$FOREIGN_CONF" ]]; then
        systemctl stop reverse-tunnel 2>/dev/null || true
        systemctl disable reverse-tunnel 2>/dev/null || true
        systemctl stop pg-tunnel-mgmt 2>/dev/null || true
        systemctl disable pg-tunnel-mgmt 2>/dev/null || true
        local du_file du_name
        for du_file in $DATA_SERVICE_GLOB; do
            [[ -f "$du_file" ]] || continue
            du_name=$(basename "$du_file" .service)
            systemctl stop "$du_name" 2>/dev/null || true
            systemctl disable "$du_name" 2>/dev/null || true
            rm -f "$du_file"
        done
        rm -f "$TUNNEL_SERVICE" "$MGMT_SERVICE" "$TLS_CLIENT_PY" "$LAST_GOOD_IP_FILE" "$KNOWN_HOSTS_FILE" "$PEER_IPS_FILE"
        systemctl daemon-reload
        rm -f "$FOREIGN_CONF" "$TRAFFIC_STATE" "$TRAFFIC_LOCK"
        echo -e "${GREEN}[OK] Reverse TLS tunnel channels & accounting removed from Foreign server.${NC}"
    elif [[ -f "$IRAN_CONF" ]]; then
        local OUT_IP="" NODE_PORT="" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
        source "$IRAN_CONF"
        systemctl stop pg-tls-server.service 2>/dev/null || true
        systemctl disable pg-tls-server.service 2>/dev/null || true
        systemctl stop pg-tunnel-watchdog.service 2>/dev/null || true
        systemctl disable pg-tunnel-watchdog.service 2>/dev/null || true
        rm -f "$TLS_SERVER_SERVICE" "$TLS_SERVER_PY" "$TLS_CERT" "$TLS_KEY"
        rm -f "$WATCHDOG_SERVICE" "$WATCHDOG_SH" "$WATCHDOG_STATE"
        local s_i=0
        while (( s_i < 10 )) && iptables -D INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null; do
            s_i=$(( s_i + 1 ))
        done
        iptables -F PG_SSHBF 2>/dev/null || true
        iptables -X PG_SSHBF 2>/dev/null || true
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -D INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j PG_SSHBF 2>/dev/null || true
            ip6tables -F PG_SSHBF 2>/dev/null || true
            ip6tables -X PG_SSHBF 2>/dev/null || true
        fi
        systemctl daemon-reload
        release_iran_tunnel_ports 2>/dev/null || true
        IFS=',' read -ra PORTS <<< "$DATA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            [[ -n "$port" ]] || continue
            iptables -t nat -D OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        done
        netfilter-persistent save >/dev/null 2>&1 || true
        rm -f "$IRAN_CONF" "$TRAFFIC_STATE" "$TRAFFIC_LOCK" "$PEER_IPS_FILE"
        echo -e "${GREEN}[OK] TLS 1.3 server, iptables rules & accounting removed safely from Iran server.${NC}"
    else
        rm -f "$TRAFFIC_STATE" "$TRAFFIC_LOCK"
        systemctl daemon-reload 2>/dev/null || true
        echo -e "${YELLOW}No configuration found to uninstall.${NC}"
    fi
    read -p "Press Enter to return to menu..."
}

view_logs() {
    print_header
    if [[ -f "$MGMT_SERVICE" || -f "$TUNNEL_SERVICE" ]]; then
        echo -e "${CYAN}Live Foreign Tunnel Logs - All Channels (Press Ctrl+C to return)...${NC}"
        local log_units="-u pg-tunnel-mgmt"
        local lu_file lu_name
        for lu_file in $DATA_SERVICE_GLOB; do
            [[ -f "$lu_file" ]] || continue
            lu_name=$(basename "$lu_file" .service)
            log_units+=" -u ${lu_name}"
        done
        [[ -f "$TUNNEL_SERVICE" ]] && log_units+=" -u reverse-tunnel"
        journalctl ${log_units} -n 30 -f --no-pager || true
    elif [[ -f "$TLS_SERVER_SERVICE" ]]; then
        echo -e "${CYAN}Live Iran TLS 1.3 & SSH Logs (Press Ctrl+C to return)...${NC}"
        journalctl -u pg-tls-server.service -u pg-tunnel-watchdog.service -u ssh.service -n 30 -f --no-pager || true
    else
        echo -e "${RED}No active tunnel service found on this server.${NC}"
        read -p "Press Enter to return to menu..."
    fi
}

optimizer() {
    print_header
    echo -e "${CYAN}=== Network & System Optimizer ===${NC}"
    echo -e "${YELLOW}Applying kernel TCP tuning, BBR & buffer limits...${NC}"
    echo

    cat > /etc/sysctl.d/99-pg-tunnel-optimize.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 4096
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
net.netfilter.nf_conntrack_max = 1048576
fs.file-max = 2097152
vm.swappiness = 10
EOF

    modprobe tcp_bbr 2>/dev/null || true
    modprobe nf_conntrack 2>/dev/null || true
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true

    cat > /etc/security/limits.d/99-pg-tunnel.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    sysctl --system >/dev/null 2>&1

    ensure_network_tuning

    cat > "$NET_TUNE_SERVICE" <<'EOF'
[Unit]
Description=PG Tunnel Network Tuning (BBR/fq verify + RPS)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pg-tunnel ensure-tuning

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable pg-tunnel-net-tune.service >/dev/null 2>&1 || true

    echo -e "${GREEN}[OK] Optimizations applied system-wide.${NC}"
    echo
    echo -e "${CYAN}--- Active Tuning Status ---${NC}"
    echo "  TCP Congestion Control  : $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'N/A')"
    echo "  Default Queue Discipline: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'N/A')"
    echo "  TCP Fast Open           : $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo 'N/A')"
    echo "  System File Limit (Max) : $(sysctl -n fs.file-max 2>/dev/null || echo 'N/A')"
    echo "  Max Socket Connections  : $(sysctl -n net.core.somaxconn 2>/dev/null || echo 'N/A')"
    echo "  Max Conntrack Entries   : $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 'N/A')"
    echo "  TCP Read Memory Max     : $(sysctl -n net.core.rmem_max 2>/dev/null || echo 'N/A') bytes"
    echo "  TCP Write Memory Max    : $(sysctl -n net.core.wmem_max 2>/dev/null || echo 'N/A') bytes"
    echo "  TCP Notsent Lowat       : $(sysctl -n net.ipv4.tcp_notsent_lowat 2>/dev/null || echo 'N/A') bytes (bufferbloat guard)"
    local _rps=0 _q
    for _q in /sys/class/net/*/queues/rx-*/rps_cpus; do
        [[ -r "$_q" ]] || continue
        [[ "$(cat "$_q" 2>/dev/null || true)" != "00000000" ]] && _rps=$((_rps + 1))
    done
    echo "  RPS-Enabled RX Queues   : ${_rps}"
    echo
    read -p "Press Enter to return to menu..."
}

version_gt() {
    local v1="${1#v}" v2="${2#v}"
    [[ "$v1" == "$v2" ]] && return 1
    local highest
    highest=$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | tail -n 1)
    [[ "$highest" == "$v1" ]]
}

extract_script_version() {
    local file="$1"
    local ver=""
    ver=$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)".*/\1/p' "$file" 2>/dev/null | head -n 1 || true)
    if [[ -z "$ver" ]]; then
        ver=$(sed -n 's/.*Tunnel Manager v\([0-9][0-9.]*\).*/\1/p' "$file" 2>/dev/null | head -n 1 || true)
    fi
    echo "${ver:-0.0}"
}

validate_downloaded_script() {
    local file="$1"
    [[ -s "$file" ]] || return 1
    head -n 1 "$file" | grep -q '^#!/bin/bash' || return 1
    bash -n "$file" >/dev/null 2>&1 || return 1
    return 0
}

normalize_git_ref() {
    local raw="$1"
    raw=$(echo "$raw" | xargs)
    raw="${raw#https://github.com/${GITHUB_REPO_SLUG}/tree/}"
    raw="${raw#https://github.com/${GITHUB_REPO_SLUG}/commit/}"
    raw="${raw#origin/}"
    raw="${raw%/}"
    echo "$raw"
}

resolve_ref_latest_sha() {
    local ref="$1"
    local json="" sha=""
    json=$(curl -fsSL --connect-timeout 8 --max-time 15 \
        -G --data-urlencode "sha=${ref}" --data-urlencode "per_page=1" \
        -H "Accept: application/vnd.github+json" \
        -H "Cache-Control: no-cache" \
        "${GITHUB_API_BASE}/commits" 2>/dev/null || true)
    if [[ -n "$json" ]]; then
        sha=$(echo "$json" | grep -m 1 '"sha"' | sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{7,40\}\)".*/\1/p' || true)
    fi
    echo "$sha"
}

fetch_script_from_ref() {
    local ref="$1"
    local out_file="$2"
    local sha="" target_ref="$ref"

    sha=$(resolve_ref_latest_sha "$ref")
    if [[ -n "$sha" ]]; then
        target_ref="$sha"
    fi

    if curl -fsSL --connect-timeout 8 --max-time 20 \
        -G --data-urlencode "ref=${target_ref}" \
        -H "Accept: application/vnd.github.raw+json" \
        -H "Cache-Control: no-cache" \
        "${GITHUB_API_BASE}/contents/script.sh" -o "$out_file" 2>/dev/null && validate_downloaded_script "$out_file"; then
        echo "$target_ref"
        return 0
    fi

    if curl -fsSL --connect-timeout 8 --max-time 20 \
        -H "Cache-Control: no-cache" \
        "${GITHUB_RAW_BASE}/${target_ref}/script.sh?cb=$(date +%s)" -o "$out_file" 2>/dev/null && validate_downloaded_script "$out_file"; then
        echo "$target_ref"
        return 0
    fi

    rm -f "$out_file"
    return 1
}

update_script() {
    print_header
    echo -e "${CYAN}=== Update Script from GitHub ===${NC}"
    echo -e "Current Installed Version : ${GREEN}v${SCRIPT_VERSION}${NC}"
    echo

    local tmp_main="/tmp/pg-tunnel-main.$$"
    local tmp_target="/tmp/pg-tunnel-target.$$"
    rm -f "$tmp_main" "$tmp_target"

    echo -e "${YELLOW}Checking latest version on 'main' branch...${NC}"
    local main_ref="" main_ver="0.0"
    if main_ref=$(fetch_script_from_ref "main" "$tmp_main"); then
        main_ver=$(extract_script_version "$tmp_main")
        echo -e "Latest Version on 'main'  : ${CYAN}v${main_ver}${NC} (${main_ref:0:7})"
    else
        echo -e "${YELLOW}[WARN] Could not reach 'main' branch info.${NC}"
    fi
    echo

    if [[ -s "$tmp_main" ]] && version_gt "$main_ver" "$SCRIPT_VERSION"; then
        echo -e "${GREEN}Newer version found on 'main' (v${main_ver}). Installing update...${NC}"
        mv -f "$tmp_main" /usr/local/bin/pg-tunnel
        chmod +x /usr/local/bin/pg-tunnel
        echo -e "${GREEN}[OK] pg-tunnel updated to v${main_ver} (${main_ref:0:7})!${NC}"
        echo -e "${YELLOW}Restarting manager...${NC}"
        sleep 2
        exec /usr/local/bin/pg-tunnel
    fi

    rm -f "$tmp_main"
    echo -e "${YELLOW}Branch 'main' version (v${main_ver}) is lower than or equal to current version (v${SCRIPT_VERSION}).${NC}"
    echo -e "Enter a branch name or commit SHA to fetch its latest version directly without PR/Merge."

    local input_ref=""
    read -p "Enter branch name or commit SHA (0 = Cancel): " input_ref

    input_ref=$(normalize_git_ref "$input_ref")
    if [[ -z "$input_ref" || "$input_ref" == "0" ]]; then
        echo -e "${YELLOW}Update cancelled.${NC}"
        sleep 1
        return
    fi

    echo
    echo -e "${YELLOW}Resolving latest commit for '${input_ref}' and downloading script.sh...${NC}"
    local resolved_ref=""
    if resolved_ref=$(fetch_script_from_ref "$input_ref" "$tmp_target"); then
        local target_ver
        target_ver=$(extract_script_version "$tmp_target")
        mv -f "$tmp_target" /usr/local/bin/pg-tunnel
        chmod +x /usr/local/bin/pg-tunnel
        echo -e "${GREEN}[OK] Updated from '${input_ref}' at latest commit (${resolved_ref:0:7}) -> v${target_ver}!${NC}"
        echo -e "${YELLOW}Restarting manager...${NC}"
        sleep 2
        exec /usr/local/bin/pg-tunnel
    else
        rm -f "$tmp_target"
        echo -e "${RED}[ERROR] Failed to download valid script.sh for '${input_ref}'. Verify branch/commit name.${NC}"
        read -p "Press Enter to return to menu..."
    fi
}

repair_tunnels() {
    print_header
    echo -e "${CYAN}=== Repair / Restart Tunnels ===${NC}"
    sync_traffic_state >/dev/null 2>&1 || true
    if [[ -f "$IRAN_CONF" ]]; then
        echo -e "${YELLOW}Releasing stale tunnel sockets, restarting SSH + TLS 1.3 wrapper, and re-applying rules...${NC}"
        release_iran_tunnel_ports 2>/dev/null || true
        apply_iran_configs
    elif [[ -f "$FOREIGN_CONF" ]]; then
        echo -e "${YELLOW}Rebuilding & restarting Reverse SSH over TLS 1.3 service...${NC}"
        apply_foreign_configs
    else
        echo -e "${RED}No previous configuration found to repair.${NC}"
        read -p "Press Enter to return to menu..."
    fi
}

setup_cronjob() {
    print_header
    echo -e "${CYAN}=== Smart Auto-Heal Cronjob Configuration ===${NC}"
    echo "  1) Every 1 Hour"
    echo "  2) Every 2 Hours"
    echo "  3) Every 3 Hours"
    echo "  4) Every 5 Hours"
    echo "  5) Every 12 Hours"
    echo "  6) Every 24 Hours (Daily)"
    echo "  7) Disable Cronjob"
    echo -e "------------------------------------------------------------"
    read -p "Select interval option [1-7]: " cron_choice

    local min_slot="0"
    [[ -f "$FOREIGN_CONF" ]] && min_slot="1"

    local schedule=""
    case $cron_choice in
        1) schedule="${min_slot} * * * *" ;;
        2) schedule="${min_slot} */2 * * *" ;;
        3) schedule="${min_slot} */3 * * *" ;;
        4) schedule="${min_slot} */5 * * *" ;;
        5) schedule="${min_slot} */12 * * *" ;;
        6) schedule="${min_slot} 0 * * *" ;;
        7)
            rm -f "$CRON_FILE"
            echo -e "${GREEN}[OK] Auto-heal cronjob disabled.${NC}"
            read -p "Press Enter to return to menu..."
            return
            ;;
        *)
            echo -e "${RED}Invalid option.${NC}"
            sleep 1
            return
            ;;
    esac

    echo "$schedule root /usr/local/bin/pg-tunnel cron-auto-repair >/dev/null 2>&1" > "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    echo -e "${GREEN}[OK] Smart non-disruptive auto-heal scheduled: ($schedule)${NC}"
    echo
    read -p "Press Enter to return to menu..."
}

other_options_menu() {
    while true; do
        print_header
        echo -e "${CYAN}=== Other Options ===${NC}"
        echo
        echo "  1. View Tunnel Logs"
        echo "  2. Setup Auto-Restart Cronjob"
        echo "  3. SSH Brute-Force Shield (Port 22)"
        echo "  4. Rotate TLS Secret (Iran, Zero Downtime)"
        echo "  5. Backup / Restore Configs"
        echo "  0. Back to Main Menu"
        echo -e "------------------------------------------------------------"
        read -p "Select option [0-5]: " other_choice
        case $other_choice in
            1) view_logs ;;
            2) setup_cronjob ;;
            3) brute_force_shield_menu ;;
            4) rotate_tls_secret ;;
            5) backup_restore_menu ;;
            0) return ;;
            *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

main_menu() {
    while true; do
        print_header
        echo "  1. Install / Configure Tunnel"
        echo "  2. Check Status / Rules & Live Speed"
        echo "  3. Uninstall Safely"
        echo "  4. Network Optimizer"
        echo "  5. Update Script (from GitHub)"
        echo "  6. Repair / Restart Tunnels (Fix Connection)"
        echo "  7. Other Options"
        echo "  0. Exit"
        echo -e "------------------------------------------------------------"
        read -p "Select option [0-7]: " choice

        case $choice in
            1)
                echo -e "\n1) Iran Server\n2) Foreign Server"
                read -p "Select [1-2]: " st
                case $st in
                    1) install_iran ;;
                    2) install_foreign ;;
                    *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
                esac
                ;;
            2) manage_service ;;
            3) uninstall_all ;;
            4) optimizer ;;
            5) update_script ;;
            6) repair_tunnels ;;
            7) other_options_menu ;;
            0) echo -e "${GREEN}Goodbye.${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

handle_cli_subcommands "${1:-}"
check_root
self_install
bootstrap_existing_accounting
main_menu
