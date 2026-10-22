#!/bin/bash

# ============================================================
# PG Node SSH Tunnel Manager v6.5
# GitHub: https://github.com/XiliService/pg-node-ssh-tunnel
# Script File: script.sh
# English Only | Production Ready | Trojan-Style TLS 1.3 + Real Cert + Multi-IP Failover
# ============================================================

set -euo pipefail

SCRIPT_VERSION="6.5"
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
    # Output format on match: DOMAIN|CERT_PATH|KEY_PATH
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
import asyncio, email.utils, hmac, os, re, signal, socket, ssl, subprocess, sys, time

CERT, KEY, LPORT, TPORT = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
CONF_PATH = os.environ.get("PG_IRAN_CONF", "/etc/pg-tunnel/iran.conf")
AUTH_LOCK = asyncio.Lock()

def load_runtime_conf():
    cfg = {
        "TLS_SECRET": "",
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
    return cfg.get("TLS_SECRET", ""), ports, fb, cfg.get("CERT_SRC", ""), cfg.get("KEY_SRC", "")

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
    secret, cleanup_ports, fb_port, _, _ = load_runtime_conf()
    buf = bytearray()
    authed = False
    role = "tunnel"
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
                if secret and hmac.compare_digest(got_auth, secret):
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

    async with AUTH_LOCK:
        if role == "tunnel":
            await asyncio.get_running_loop().run_in_executor(None, release_zombie_ports, cleanup_ports)
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TPORT), timeout=8.0)
            tune_socket(uw.get_extra_info("socket"))
            if rest:
                uw.write(rest)
                await uw.drain()
        except Exception:
            cw.close()
            return

    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))

async def cert_reloader(ctx):
    last_mtime = 0.0
    while True:
        try:
            _, _, _, cert_src, key_src = load_runtime_conf()
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
import os, secrets, selectors, socket, ssl, sys, time

CONF_PATH = os.environ.get("PG_FOREIGN_CONF", "/etc/pg-tunnel/foreign.conf")
LAST_IP_FILE = os.environ.get("PG_LAST_IP_FILE", "/etc/pg-tunnel/last_good_ip")

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

bips = []
for x in RAW_BIPS.split(","):
    x = x.strip()
    if x and x not in bips:
        bips.append(x)
if "" not in bips:
    bips.append("")

try:
    with open(LAST_IP_FILE, "r", encoding="utf-8") as lf:
        last_good = lf.read().strip()
    if last_good in bips:
        bips.remove(last_good)
        bips.insert(0, last_good)
except Exception:
    pass

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

        pad = secrets.token_urlsafe(secrets.randbelow(96) + 32)
        req = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: {SNI}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"X-Auth: {SECRET}\r\n"
            f"X-Role: {ROLE}\r\n"
            f"X-Pad: {pad}\r\n\r\n"
        ).encode("ascii")
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

        if not first_plain.startswith(b"SSH-"):
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
for bip in bips:
    try:
        raw, sslobj, in_bio, out_bio, plain_out = establish_connection(bip)
        chosen_bip = bip
        break
    except Exception as e:
        err = e

if raw is None:
    sys.stderr.write(f"TLS tunnel connect failed across {bips}: {err}\n")
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

try:
    while not (ssl_eof and not plain_out):
        if stdin_eof and not cipher_out and raw_eof and ssl_eof:
            break

        ev_raw = 0
        if not raw_eof and len(plain_out) < MAX_BUF:
            ev_raw |= selectors.EVENT_READ
        if cipher_out:
            ev_raw |= selectors.EVENT_WRITE

        ev_in = selectors.EVENT_READ if (not stdin_eof and len(cipher_out) < MAX_BUF) else 0
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

        events = sel.select(timeout=5.0)
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
                        off = 0
                        while off < len(d):
                            off += sslobj.write(memoryview(d)[off:])
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
        mb = (b + 0.0) / 1048576.0
        gb = mb / 1024.0
        if (mb >= 1024.0 || sprintf("%.2f", mb) == "1024.00") {
            printf "%.2f GB", gb
        } else {
            printf "%.2f MB", mb
        }
    }'
}

format_speed_mbs() {
    local delta_bytes="${1:-0}"
    local delta_ns="${2:-1000000000}"
    awk -v db="$delta_bytes" -v dns="$delta_ns" 'BEGIN {
        if (db <= 0 || dns <= 0) {
            printf "0.00 MB/s"
        } else {
            sec = (dns + 0.0) / 1000000000.0
            mbs = ((db + 0.0) / 1048576.0) / sec
            printf "%.2f MB/s", mbs
        }
    }'
}

ensure_accounting_rules() {
    command -v iptables >/dev/null 2>&1 || return 0

    if [[ -f "$IRAN_CONF" ]]; then
        local OUT_IP="" NODE_PORT="" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
        source "$IRAN_CONF"
        [[ -n "${SEC_SSH:-}" ]] || return 0

        iptables -t mangle -N PG_TUNNEL_IN 2>/dev/null || true
        iptables -t mangle -N PG_TUNNEL_OUT 2>/dev/null || true

        iptables -t mangle -C INPUT -j PG_TUNNEL_IN 2>/dev/null || \
            iptables -t mangle -I INPUT 1 -j PG_TUNNEL_IN
        iptables -t mangle -C OUTPUT -j PG_TUNNEL_OUT 2>/dev/null || \
            iptables -t mangle -I OUTPUT 1 -j PG_TUNNEL_OUT

        iptables -t mangle -C PG_TUNNEL_IN ! -i lo -p tcp --dport "$SEC_SSH" -j RETURN 2>/dev/null || \
            iptables -t mangle -A PG_TUNNEL_IN ! -i lo -p tcp --dport "$SEC_SSH" -j RETURN
        iptables -t mangle -C PG_TUNNEL_OUT ! -o lo -p tcp --sport "$SEC_SSH" -j RETURN 2>/dev/null || \
            iptables -t mangle -A PG_TUNNEL_OUT ! -o lo -p tcp --sport "$SEC_SSH" -j RETURN

    elif [[ -f "$FOREIGN_CONF" ]]; then
        local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS="" TLS_SNI="" BIND_IPS="" TLS_SECRET=""
        source "$FOREIGN_CONF"
        [[ -n "${IR_IP:-}" && -n "${SEC_SSH:-}" ]] || return 0

        iptables -t mangle -N PG_TUNNEL_IN 2>/dev/null || true
        iptables -t mangle -N PG_TUNNEL_OUT 2>/dev/null || true

        iptables -t mangle -C INPUT -j PG_TUNNEL_IN 2>/dev/null || \
            iptables -t mangle -I INPUT 1 -j PG_TUNNEL_IN
        iptables -t mangle -C OUTPUT -j PG_TUNNEL_OUT 2>/dev/null || \
            iptables -t mangle -I OUTPUT 1 -j PG_TUNNEL_OUT

        iptables -t mangle -C PG_TUNNEL_IN -s "$IR_IP" -p tcp --sport "$SEC_SSH" -j RETURN 2>/dev/null || \
            iptables -t mangle -A PG_TUNNEL_IN -s "$IR_IP" -p tcp --sport "$SEC_SSH" -j RETURN
        iptables -t mangle -C PG_TUNNEL_OUT -d "$IR_IP" -p tcp --dport "$SEC_SSH" -j RETURN 2>/dev/null || \
            iptables -t mangle -A PG_TUNNEL_OUT -d "$IR_IP" -p tcp --dport "$SEC_SSH" -j RETURN
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
        cron-auto-repair)
            check_root
            sync_traffic_state >/dev/null 2>&1 || true
            if [[ -f "$IRAN_CONF" ]]; then
                local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
                source "$IRAN_CONF"
                if ! systemctl is-active --quiet ssh.service; then
                    systemctl restart ssh.service 2>/dev/null || true
                fi
                if [[ -f "$TLS_SERVER_SERVICE" ]] && ! systemctl is-active --quiet pg-tls-server.service; then
                    systemctl restart pg-tls-server.service 2>/dev/null || true
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
                if ! systemctl is-active --quiet reverse-tunnel; then
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

    if [[ -n "$cur_out_ip" ]]; then
        read -p "Foreign Server IP (PasarGuard Outbound IP) [default: ${cur_out_ip}]: " OUT_IP
        OUT_IP=${OUT_IP:-$cur_out_ip}
    else
        read -p "Foreign Server IP (PasarGuard Outbound IP): " OUT_IP
    fi

    read -p "Node management port [default: ${cur_node_port}]: " NODE_PORT
    NODE_PORT=${NODE_PORT:-$cur_node_port}

    if [[ -n "$cur_data_ports" ]]; then
        read -p "Outbound data ports (comma separated) [default: ${cur_data_ports}]: " DATA_PORTS
        DATA_PORTS=${DATA_PORTS:-$cur_data_ports}
    else
        read -p "Outbound data ports (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
    fi

    local suggested_port
    suggested_port=$(pick_free_https_port)
    while true; do
        read -p "Anti-DPI HTTPS Port [recommended free port: ${suggested_port}]: " SEC_SSH
        SEC_SSH=${SEC_SSH:-$suggested_port}
        if [[ "$SEC_SSH" == "22" || "$SEC_SSH" == "80" || "$SEC_SSH" == "443" ]]; then
            echo -e "${RED}[ERROR] Do not use port ${SEC_SSH} (reserved for SSH/Caddy/Xray). Pick e.g. ${suggested_port}.${NC}"
            continue
        fi
        local conflict_proc=""
        conflict_proc=$(ss -tlnp 2>/dev/null | awk -v p=":${SEC_SSH}$" '$4 ~ p && $0 !~ /tls_server\.py/ {print $0}' || true)
        if [[ -n "$conflict_proc" ]]; then
            echo -e "${RED}[WARN] Port ${SEC_SSH} is currently occupied by another process:${NC}"
            echo "  $conflict_proc"
            echo -e "${YELLOW}Please pick a free port (recommended: ${suggested_port}).${NC}"
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
    read -p "TLS Cover Domain (SNI) [default: ${default_sni}]: " TLS_SNI
    TLS_SNI=${TLS_SNI:-$default_sni}

    if [[ -n "$det_dom" && "$TLS_SNI" == "$det_dom" ]]; then
        CERT_SRC="$det_crt"
        KEY_SRC="$det_key"
    fi

    local default_secret="${cur_secret:-$(generate_secret)}"
    read -p "Anti-Prober Secret Key [Enter = ${default_secret}]: " TLS_SECRET
    TLS_SECRET=${TLS_SECRET:-$default_secret}

    if [[ -z "$cur_sec" || "$SEC_SSH" != "$cur_sec" ]]; then
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

    cat > "$TLS_SERVER_SERVICE" <<EOF
[Unit]
Description=PG Tunnel Trojan-Style TLS 1.3 Anti-DPI Server
After=network-online.target ssh.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${TLS_SERVER_PY} ${TLS_CERT} ${TLS_KEY} ${SEC_SSH} 22
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable pg-tls-server.service >/dev/null 2>&1
    systemctl restart pg-tls-server.service

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
    pub_ir_ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}' || echo "<IRAN_IP>")

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

    if [[ -n "$cur_ir_ip" ]]; then
        read -p "Iran Server IP [default: ${cur_ir_ip}]: " IR_IP
        IR_IP=${IR_IP:-$cur_ir_ip}
    else
        read -p "Iran Server IP: " IR_IP
    fi

    read -p "Anti-DPI HTTPS Port on Iran [default: ${cur_sec}]: " SEC_SSH
    SEC_SSH=${SEC_SSH:-$cur_sec}

    local sni_prompt="${cur_sni:-www.microsoft.com}"
    read -p "TLS SNI Domain (from Iran summary) [default: ${sni_prompt}]: " TLS_SNI
    TLS_SNI=${TLS_SNI:-$sni_prompt}

    if [[ -n "$cur_secret" ]]; then
        read -p "TLS Secret Key (from Iran summary) [default: ${cur_secret}]: " TLS_SECRET
        TLS_SECRET=${TLS_SECRET:-$cur_secret}
    else
        read -p "TLS Secret Key (paste from Iran summary): " TLS_SECRET
    fi

    read -p "Node management port [default: ${cur_node}]: " NODE_PORT
    NODE_PORT=${NODE_PORT:-$cur_node}

    if [[ -n "$cur_data" ]]; then
        read -p "Outbound data ports to tunnel [default: ${cur_data}]: " DATA_PORTS
        DATA_PORTS=${DATA_PORTS:-$cur_data}
    else
        read -p "Outbound data ports to tunnel (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
    fi

    local detected_ips
    detected_ips=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2}' | paste -sd, - || true)
    if [[ -n "$detected_ips" ]]; then
        echo -e "${CYAN}Detected Public IPv4s on this server:${NC} ${detected_ips}"
    fi
    if [[ -n "$cur_bips" ]]; then
        read -p "Source Bind IPs for failover [default: ${cur_bips}]: " BIND_IPS
        BIND_IPS=${BIND_IPS:-$cur_bips}
    else
        read -p "Optional Clean Source Bind IPs (comma separated, Enter = Auto/Default): " BIND_IPS
    fi

    cleanup_accounting_rules
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
    if ssh -i /root/.ssh/tunnel_key -o "$proxy_opt" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$IR_IP" "true" >/dev/null 2>&1; then
        echo -e "${GREEN}[OK] SSH public key already verified over TLS 1.3 + Secret!${NC}"
    else
        echo -e "${CYAN}Enter Iran Server root password once to authorize SSH key over TLS 1.3:${NC}"
        ssh-copy-id -i /root/.ssh/tunnel_key.pub \
            -o "$proxy_opt" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            root@"$IR_IP"
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

    echo -e "${YELLOW}Creating systemd reverse-tunnel service (TLS 1.3 + Secret + Failover)...${NC}"
    local SSH_CMD="/usr/bin/ssh -R ${NODE_PORT}:localhost:${NODE_PORT}"
    IFS=',' read -ra PORTS <<< "$DATA_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        [[ -n "$port" ]] || continue
        SSH_CMD+=" -R ${port}:localhost:${port}"
    done
    SSH_CMD+=" root@${IR_IP} -N -i /root/.ssh/tunnel_key"
    SSH_CMD+=" -o \"ProxyCommand=/usr/bin/python3 ${TLS_CLIENT_PY} ${IR_IP} ${SEC_SSH} ${TLS_SNI} '${BIND_IPS}' '${TLS_SECRET}' tunnel\""
    SSH_CMD+=" -o ConnectTimeout=12 -o TCPKeepAlive=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    cat > "$TUNNEL_SERVICE" <<EOF
[Unit]
Description=Reverse SSH Tunnel over TLS 1.3 to Iran Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${SSH_CMD}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable reverse-tunnel >/dev/null 2>&1
    systemctl restart reverse-tunnel

    sleep 2.5
    if systemctl is-active --quiet reverse-tunnel; then
        echo -e "${GREEN}[OK] Foreign server active & connected over TLS 1.3 (${IR_IP}:${SEC_SSH}, SNI: ${TLS_SNI}).${NC}"
    else
        echo -e "${RED}[ERROR] Tunnel service failed to connect. Check logs (Option 4) or verify Secret/Port.${NC}"
    fi
    echo
    read -p "Press Enter to return to menu..."
}

manage_service() {
    local is_configured=0
    if [[ -f "$IRAN_CONF" || -f "$FOREIGN_CONF" ]]; then
        is_configured=1
        ensure_accounting_rules
    fi

    local prev_rx=0 prev_tx=0 prev_ns=0
    local cur_rx=0 cur_tx=0 cur_ns=0
    local state_line="" created_at="Not configured"
    if (( is_configured == 1 )); then
        state_line=$(sync_traffic_state)
        IFS='|' read -r prev_rx prev_tx created_at <<< "$state_line"
        prev_ns=$(date +%s%N)
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
            state_line=$(sync_traffic_state)
            IFS='|' read -r cur_rx cur_tx created_at <<< "$state_line"
            cur_ns=$(date +%s%N)

            elapsed_ns=$(( cur_ns - prev_ns ))
            (( elapsed_ns <= 0 )) && elapsed_ns=1000000000

            local delta_rx=$(( cur_rx - prev_rx ))
            local delta_tx=$(( cur_tx - prev_tx ))
            (( delta_rx < 0 )) && delta_rx=0
            (( delta_tx < 0 )) && delta_tx=0

            dl_bytes="$cur_rx"
            ul_bytes="$cur_tx"
            dl_delta="$delta_rx"
            ul_delta="$delta_tx"

            prev_rx="$cur_rx"
            prev_tx="$cur_tx"
            prev_ns="$cur_ns"
        fi

        local dl_total ul_total sum_total dl_speed ul_speed
        dl_total=$(format_traffic_size "$dl_bytes")
        ul_total=$(format_traffic_size "$ul_bytes")
        sum_total=$(format_traffic_size "$(( dl_bytes + ul_bytes ))")
        dl_speed=$(format_speed_mbs "$dl_delta" "$elapsed_ns")
        ul_speed=$(format_speed_mbs "$ul_delta" "$elapsed_ns")

        local screen_buf=""
        screen_buf+="${GREEN}============================================================${NC}\033[K\n"
        screen_buf+="${CYAN}  PG Node SSH Tunnel Manager v${SCRIPT_VERSION}         [Live $(date '+%H:%M:%S')]${NC}\033[K\n"
        screen_buf+="${GREEN}============================================================${NC}\033[K\n"
        screen_buf+="${CYAN}=== Tunnel Traffic & Speed (Since: ${created_at}) ===${NC}\033[K\n"
        screen_buf+=$(printf "  ${GREEN}Download Used${NC}      : %-12s |  ${GREEN}Download Speed${NC} : %s\033[K\n" "$dl_total" "$dl_speed")
        screen_buf+=$(printf "  ${YELLOW}Upload Used${NC}        : %-12s |  ${YELLOW}Upload Speed${NC}   : %s\033[K\n" "$ul_total" "$ul_speed")
        screen_buf+=$(printf "  ${CYAN}Total Traffic Used${NC} : %-12s\033[K\n" "$sum_total")
        screen_buf+="------------------------------------------------------------\033[K\n"

        screen_buf+="${CYAN}=== System & Anti-DPI Status ===${NC}\033[K\n"
        if [[ -f "$TUNNEL_SERVICE" ]]; then
            local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS="" TLS_SNI="www.microsoft.com" BIND_IPS="" TLS_SECRET=""
            [[ -f "$FOREIGN_CONF" ]] && source "$FOREIGN_CONF"
            local active_state sub_state active_since main_pid mem_bytes mem_mb last_log active_ip auth_tag
            active_state=$(systemctl show reverse-tunnel -p ActiveState --value 2>/dev/null || echo "unknown")
            sub_state=$(systemctl show reverse-tunnel -p SubState --value 2>/dev/null || echo "unknown")
            active_since=$(systemctl show reverse-tunnel -p ActiveEnterTimestamp --value 2>/dev/null || echo "N/A")
            main_pid=$(systemctl show reverse-tunnel -p MainPID --value 2>/dev/null || echo "0")
            mem_bytes=$(systemctl show reverse-tunnel -p MemoryCurrent --value 2>/dev/null || echo "0")
            mem_mb="N/A"
            if [[ "$mem_bytes" =~ ^[0-9]+$ ]] && (( mem_bytes > 0 && mem_bytes < 1099511627776 )); then
                mem_mb=$(awk -v m="$mem_bytes" 'BEGIN { printf "%.1f MB", m / 1048576.0 }')
            fi
            active_ip="Default"
            [[ -f "$LAST_GOOD_IP_FILE" ]] && active_ip=$(cat "$LAST_GOOD_IP_FILE" 2>/dev/null | xargs || echo "Default")
            auth_tag="Legacy"
            [[ -n "${TLS_SECRET:-}" ]] && auth_tag="Secret+Camo"
            last_log=$(journalctl -u reverse-tunnel --no-pager -n 1 --output=cat 2>/dev/null | cut -c1-56 || true)

            if [[ "$active_state" == "active" ]]; then
                screen_buf+="  Service State   : ${GREEN}${active_state} (${sub_state})${NC} since ${active_since:-N/A}\033[K\n"
            else
                screen_buf+="  Service State   : ${RED}${active_state} (${sub_state})${NC}\033[K\n"
            fi
            screen_buf+="  Process / RAM   : Main PID ${main_pid} | Memory: ${mem_mb}\033[K\n"
            screen_buf+="  TLS 1.3 Target  : ${IR_IP:-N/A}:${SEC_SSH:-N/A} | SNI: ${TLS_SNI} [${auth_tag}]\033[K\n"
            screen_buf+="  Active Bind IP  : ${GREEN}${active_ip}${NC} (Pool: ${BIND_IPS:-Default})\033[K\n"
            screen_buf+="  Tunnel Ports    : Node ${NODE_PORT:-N/A} | Data ${DATA_PORTS:-N/A}\033[K\n"
            [[ -n "$last_log" ]] && screen_buf+="  Latest Log      : ${last_log}\033[K\n"
        else
            local OUT_IP="" NODE_PORT="62075" DATA_PORTS="" SEC_SSH="" TLS_SNI="www.microsoft.com" TLS_SECRET=""
            [[ -f "$IRAN_CONF" ]] && source "$IRAN_CONF"
            local tls_status="${RED}Inactive${NC}" cert_badge auth_mode="Legacy"
            cert_badge=$(get_cert_badge)
            [[ -n "${TLS_SECRET:-}" ]] && auth_mode="Trojan-Auth+WebCamo"
            if systemctl is-active --quiet pg-tls-server.service 2>/dev/null; then
                tls_status="${GREEN}Active on Port ${SEC_SSH} (${cert_badge}, ${auth_mode})${NC}"
            fi
            screen_buf+="  TLS 1.3 Server  : ${tls_status}\033[K\n"
            screen_buf+="  Cover Domain    : ${TLS_SNI:-N/A}\033[K\n"

            local ssh_ports tunnel_ports
            ssh_ports=$(ss -tlnp 2>/dev/null | awk '/sshd/ && $4 !~ /^127\./ && $4 !~ /^\[::1\]/ {sub(/.*:/,"",$4); if(!seen[$4]++) out=out (out?", ":"") $4} END{print out ? out : "None"}')
            tunnel_ports=$(ss -tlnp 2>/dev/null | awk '/sshd/ && ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) {sub(/.*:/,"",$4); if(!seen[$4]++) out=out (out?", ":"") $4} END{print out ? out : "None"}')
            screen_buf+="  SSH / Tunnel Prt: SSH [${ssh_ports}] | Local [${tunnel_ports}]\033[K\n"
            screen_buf+="  NAT OUTPUT Rules:\033[K\n"
            local nat_summary
            nat_summary=$(iptables -t nat -L OUTPUT -n -v --line-numbers 2>/dev/null | awk '
                NR > 2 && NF >= 9 {
                    rule = "    #" $1 " " $4 " -> " $9
                    if ($4 == "REDIRECT") rule = rule ":" $12 " => :" $NF
                    print rule " (pkts:" $2 ", " $3 ")"
                }' | head -n 6 || true)
            if [[ -n "$nat_summary" ]]; then
                while IFS= read -r nline; do
                    screen_buf+="${nline}\033[K\n"
                done <<< "$nat_summary"
            else
                screen_buf+="    (No active NAT OUTPUT rules)\033[K\n"
            fi
        fi

        screen_buf+="${CYAN}=== Smart Auto-Heal Cronjob ===${NC}\033[K\n"
        if [[ -f "$CRON_FILE" ]]; then
            local cron_sched
            cron_sched=$(awk '{print $1" "$2" "$3" "$4" "$5}' "$CRON_FILE" 2>/dev/null || echo "Active")
            screen_buf+="  Schedule : ${GREEN}Active (${cron_sched})${NC}\033[K\n"
        else
            screen_buf+="  Schedule : ${YELLOW}Disabled${NC}\033[K\n"
        fi
        screen_buf+="------------------------------------------------------------\033[K\n"
        screen_buf+="${YELLOW}Updating every 1s... Press [Enter] or [q] to return to menu.${NC}\033[K\n"
        screen_buf+="\033[J"

        printf '\033[H%b' "$screen_buf"

        local key=""
        if IFS= read -r -s -n 1 -t 1 key; then
            if [[ -z "$key" || "$key" == "q" || "$key" == "Q" || "$key" == "0" ]]; then
                break
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

    if [[ -f "$ACCT_SERVICE" ]]; then
        systemctl disable pg-tunnel-acct.service >/dev/null 2>&1 || true
        rm -f "$ACCT_SERVICE"
    fi

    cleanup_accounting_rules

    if [[ -f "$FOREIGN_CONF" ]]; then
        systemctl stop reverse-tunnel 2>/dev/null || true
        systemctl disable reverse-tunnel 2>/dev/null || true
        rm -f "$TUNNEL_SERVICE" "$TLS_CLIENT_PY" "$LAST_GOOD_IP_FILE"
        systemctl daemon-reload
        rm -f "$FOREIGN_CONF" "$TRAFFIC_STATE" "$TRAFFIC_LOCK"
        echo -e "${GREEN}[OK] Reverse TLS tunnel service & accounting removed from Foreign server.${NC}"
    elif [[ -f "$IRAN_CONF" ]]; then
        local OUT_IP="" NODE_PORT="" DATA_PORTS="" SEC_SSH="" TLS_SNI="" TLS_SECRET=""
        source "$IRAN_CONF"
        systemctl stop pg-tls-server.service 2>/dev/null || true
        systemctl disable pg-tls-server.service 2>/dev/null || true
        rm -f "$TLS_SERVER_SERVICE" "$TLS_SERVER_PY" "$TLS_CERT" "$TLS_KEY"
        systemctl daemon-reload
        release_iran_tunnel_ports 2>/dev/null || true
        IFS=',' read -ra PORTS <<< "$DATA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            [[ -n "$port" ]] || continue
            iptables -t nat -D OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        done
        netfilter-persistent save >/dev/null 2>&1 || true
        rm -f "$IRAN_CONF" "$TRAFFIC_STATE" "$TRAFFIC_LOCK"
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
    if [[ -f "$TUNNEL_SERVICE" ]]; then
        echo -e "${CYAN}Live Foreign Tunnel Logs (Press Ctrl+C to return)...${NC}"
        journalctl -u reverse-tunnel.service -n 30 -f --no-pager || true
    elif [[ -f "$TLS_SERVER_SERVICE" ]]; then
        echo -e "${CYAN}Live Iran TLS 1.3 & SSH Logs (Press Ctrl+C to return)...${NC}"
        journalctl -u pg-tls-server.service -u ssh.service -n 30 -f --no-pager || true
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

main_menu() {
    while true; do
        print_header
        echo "  1. Install / Configure Tunnel"
        echo "  2. Check Status / Rules & Live Speed"
        echo "  3. Uninstall Safely"
        echo "  4. View Tunnel Logs"
        echo "  5. Network Optimizer"
        echo "  6. Update Script (from GitHub)"
        echo "  7. Repair / Restart Tunnels (Fix Connection)"
        echo "  8. Setup Auto-Restart Cronjob"
        echo "  0. Exit"
        echo -e "------------------------------------------------------------"
        read -p "Select option [0-8]: " choice

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
            4) view_logs ;;
            5) optimizer ;;
            6) update_script ;;
            7) repair_tunnels ;;
            8) setup_cronjob ;;
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
