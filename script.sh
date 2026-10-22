#!/bin/bash

# ============================================================
# PG Node SSH Tunnel Manager v6.4
# GitHub: https://github.com/XiliService/pg-node-ssh-tunnel
# Script File: script.sh
# English Only | TLS 1.3 Anti-DPI | Live Monitor & Smart Updater
# ============================================================

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="6.4"
REPO_SLUG="XiliService/pg-node-ssh-tunnel"
REPO_URL="https://raw.githubusercontent.com/${REPO_SLUG}/main/script.sh"
CONF_DIR="/etc/pg-tunnel"
IRAN_CONF="${CONF_DIR}/iran.conf"
FOREIGN_CONF="${CONF_DIR}/foreign.conf"
TRAFFIC_STATE="${CONF_DIR}/traffic.state"
TRAFFIC_LOCK="${CONF_DIR}/traffic.lock"
TLS_CERT="${CONF_DIR}/tls.crt"
TLS_KEY="${CONF_DIR}/tls.key"
TLS_SERVER_PY="${CONF_DIR}/tls_server.py"
TLS_CLIENT_PY="${CONF_DIR}/tls_client.py"
TLS_SERVER_SERVICE="/etc/systemd/system/pg-tls-server.service"
TUNNEL_SERVICE="/etc/systemd/system/reverse-tunnel.service"
CRON_FILE="/etc/cron.d/pg-tunnel-restart"
ACCT_CRON_FILE="/etc/cron.d/pg-tunnel-acct"
ACCT_SERVICE="/etc/systemd/system/pg-tunnel-acct.service"

trap '[[ -t 1 ]] && printf "\033[?25h\033[?1049l" || true' EXIT

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
        echo -e "${YELLOW}Installing missing packages: ${missing[*]}...${NC}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
    fi
}

write_tls_server_script() {
    mkdir -p "$CONF_DIR"
    cat > "$TLS_SERVER_PY" <<'EOF'
#!/usr/bin/env python3
import asyncio, socket, ssl, sys

CERT, KEY, LPORT, TPORT = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

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

async def handle(cr, cw):
    sock = cw.get_extra_info("socket")
    if sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TPORT), timeout=10)
        usock = uw.get_extra_info("socket")
        if usock:
            usock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        cw.close()
        return
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
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
import os, socket, ssl, sys, threading

HOST, PORT = sys.argv[1], int(sys.argv[2])
SNI = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "www.microsoft.com"
BIPS = [x.strip() for x in (sys.argv[4] if len(sys.argv) > 4 else "").split(",") if x.strip()] + [""]

raw = None
err = None
for bip in BIPS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(8)
        if bip:
            s.bind((bip, 0))
        s.connect((HOST, PORT))
        s.settimeout(None)
        raw = s
        break
    except Exception as e:
        err = e
        try:
            s.close()
        except Exception:
            pass

if raw is None:
    sys.stderr.write(f"TLS connect error: {err}\n")
    sys.exit(1)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
tls = ctx.wrap_socket(raw, server_hostname=SNI)

def tx():
    try:
        while True:
            d = os.read(0, 65536)
            if not d:
                break
            tls.sendall(d)
    except Exception:
        pass
    finally:
        try:
            tls.close()
        except Exception:
            pass
        os._exit(0)

threading.Thread(target=tx, daemon=True).start()
try:
    while True:
        d = tls.recv(65536)
        if not d:
            break
        v = memoryview(d)
        while v:
            v = v[os.write(1, v):]
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
        local OUT_IP="" DATA_PORTS="" SEC_SSH="" TLS_SNI=""
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
        local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS="" TLS_SNI="" BIND_IPS=""
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
    local OUT_IP="" DATA_PORTS="" SEC_SSH="" TLS_SNI=""
    source "$IRAN_CONF"
    [[ -n "${DATA_PORTS:-}" ]] || return 0

    local port_regex="" p
    IFS=',' read -ra _ports <<< "$DATA_PORTS"
    for p in "${_ports[@]}"; do
        p=$(echo "$p" | xargs)
        if [[ "$p" =~ ^[0-9]+$ ]]; then
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
            kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 0.3
        for pid in $pids; do
            kill -KILL "$pid" 2>/dev/null || true
        done
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
        fi
    fi

    if [[ -f "$IRAN_CONF" ]] && ! grep -q '^TLS_SNI=' "$IRAN_CONF"; then
        echo "TLS_SNI=www.microsoft.com" >> "$IRAN_CONF"
    fi

    if [[ -f "$FOREIGN_CONF" && -f "$CRON_FILE" ]]; then
        if grep -q '^0 ' "$CRON_FILE"; then
            sed -i 's/^0 /1 /' "$CRON_FILE"
        fi
    fi

    if [[ -f "$IRAN_CONF" && -f /etc/ssh/sshd_config ]]; then
        if ! grep -q '^ClientAliveInterval 10' /etc/ssh/sshd_config; then
            sed -i '/^ClientAliveInterval /d; /^ClientAliveCountMax /d; /^TCPKeepAlive /d' /etc/ssh/sshd_config
            printf 'TCPKeepAlive yes\nClientAliveInterval 10\nClientAliveCountMax 2\n' >> /etc/ssh/sshd_config
            mkdir -p /run/sshd
            if sshd -t 2>/dev/null; then
                systemctl reload ssh.service 2>/dev/null || systemctl restart ssh.service 2>/dev/null || true
            fi
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
                release_iran_tunnel_ports 2>/dev/null || true
                systemctl restart ssh.service 2>/dev/null || true
                if [[ -f "$TLS_SERVER_SERVICE" ]]; then
                    systemctl restart pg-tls-server.service 2>/dev/null || true
                fi
                source "$IRAN_CONF"
                IFS=',' read -ra PORTS <<< "$DATA_PORTS"
                for port in "${PORTS[@]}"; do
                    port=$(echo "$port" | xargs)
                    iptables -t nat -C OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || \
                    iptables -t nat -A OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
                done
                ensure_accounting_rules 2>/dev/null || true
                sync_traffic_state >/dev/null 2>&1 || true
            elif [[ -f "$FOREIGN_CONF" ]]; then
                ensure_accounting_rules 2>/dev/null || true
                systemctl restart reverse-tunnel 2>/dev/null || true
                sync_traffic_state >/dev/null 2>&1 || true
            fi
            exit 0
            ;;
        acct-init|acct-sync)
            check_root
            ensure_accounting_rules 2>/dev/null || true
            sync_traffic_state >/dev/null 2>&1 || true
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
    echo -e "${CYAN}=== Configuring IRAN Server (TLS 1.3 Anti-DPI) ===${NC}"
    echo

    read -p "Foreign Server IP (inside Pasarguard Outbounds): " OUT_IP
    read -p "Outbound ports (comma separated, e.g. 64483,26132,22971): " DATA_PORTS

    while true; do
        read -p "Custom Anti-DPI TLS Port (default 58443, e.g. 58443 or 2053): " SEC_SSH
        SEC_SSH=${SEC_SSH:-58443}
        if [[ "$SEC_SSH" == "22" ]]; then
            echo -e "${RED}[ERROR] Do not use Port 22 for TLS wrapper. Port 22 stays open for SSH.${NC}"
            continue
        fi
        local conflict_proc=""
        conflict_proc=$(ss -tlnp 2>/dev/null | awk -v p=":${SEC_SSH}$" '$4 ~ p && $0 !~ /tls_server\.py/ {print $0}' || true)
        if [[ -n "$conflict_proc" ]]; then
            echo -e "${RED}[WARN] Port ${SEC_SSH} is currently occupied by another process:${NC}"
            echo "  $conflict_proc"
            echo -e "${YELLOW}Please pick a free port (e.g. 58443).${NC}"
            continue
        fi
        break
    done

    read -p "TLS Cover SNI Domain [default: www.microsoft.com]: " TLS_SNI
    TLS_SNI=${TLS_SNI:-www.microsoft.com}

    reset_traffic_accounting

    cat > "$IRAN_CONF" <<EOF
OUT_IP=${OUT_IP}
DATA_PORTS=${DATA_PORTS}
SEC_SSH=${SEC_SSH}
TLS_SNI=${TLS_SNI}
EOF

    apply_iran_configs
}

apply_iran_configs() {
    if [[ ! -f "$IRAN_CONF" ]]; then
        echo -e "${RED}[ERROR] Configuration not found. Run installation first.${NC}"
        sleep 2; return
    fi
    local OUT_IP="" DATA_PORTS="" SEC_SSH="" TLS_SNI="www.microsoft.com"
    source "$IRAN_CONF"
    TLS_SNI=${TLS_SNI:-www.microsoft.com}

    ensure_packages iptables-persistent netfilter-persistent openssh-server openssl python3

    echo -e "${YELLOW}Disabling ssh.socket and ensuring SSH listens cleanly on Port 22...${NC}"
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    systemctl mask ssh.socket 2>/dev/null || true
    rm -rf /etc/systemd/system/ssh.socket.d/

    sed -i '/^Port /d; /^ClientAliveInterval /d; /^ClientAliveCountMax /d; /^TCPKeepAlive /d' /etc/ssh/sshd_config
    cat >> /etc/ssh/sshd_config <<'EOF'
Port 22
TCPKeepAlive yes
ClientAliveInterval 10
ClientAliveCountMax 2
EOF

    mkdir -p /run/sshd
    systemctl daemon-reload
    systemctl unmask ssh.service 2>/dev/null || true
    systemctl enable ssh.service >/dev/null 2>&1
    systemctl restart ssh.service

    echo -e "${YELLOW}Configuring TLS 1.3 Anti-DPI Wrapper Server on Port ${SEC_SSH} (SNI: ${TLS_SNI})...${NC}"
    write_tls_server_script
    if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$TLS_KEY" -out "$TLS_CERT" \
            -days 3650 -subj "/CN=${TLS_SNI}" >/dev/null 2>&1
    fi

    cat > "$TLS_SERVER_SERVICE" <<EOF
[Unit]
Description=PG Tunnel TLS 1.3 Anti-DPI Wrapper Server
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

    echo -e "${YELLOW}Applying iptables REDIRECT rules...${NC}"
    IFS=',' read -ra PORTS <<< "$DATA_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        iptables -t nat -C OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || \
        iptables -t nat -A OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port"
        echo "  -> Redirected $OUT_IP:$port"
    done

    echo -e "${YELLOW}Enabling persistent tunnel traffic accounting...${NC}"
    setup_accounting_persistence
    netfilter-persistent save >/dev/null 2>&1 || true

    echo -e "${GREEN}[OK] Iran server configured successfully.${NC}"
    echo -e "SSH Port 22 is active | TLS 1.3 Tunnel listening on Port ${SEC_SSH} (SNI: ${TLS_SNI})"
    echo
    read -p "Press Enter to return to menu..."
}

install_foreign() {
    print_header
    echo -e "${CYAN}=== Configuring FOREIGN Server (TLS 1.3 Anti-DPI) ===${NC}"
    echo

    read -p "Iran Server IP: " IR_IP
    read -p "Iran Anti-DPI TLS Port (default 58443): " SEC_SSH
    SEC_SSH=${SEC_SSH:-58443}
    read -p "Node management port (e.g. 62075): " NODE_PORT
    read -p "Outbound ports to tunnel (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
    read -p "TLS Cover SNI Domain [default: www.microsoft.com]: " TLS_SNI
    TLS_SNI=${TLS_SNI:-www.microsoft.com}

    local host_ips=""
    host_ips=$(ip -4 -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth|lo)/ {split($4,a,"/"); out=(out==""?a[1]:out", "a[1])} END{print out}' || true)
    if [[ -n "$host_ips" ]]; then
        echo -e "${CYAN}Detected Public IPs on this server:${NC} ${host_ips}"
    fi
    read -p "Source Bind IP(s) for tunnel [optional, comma-separated, Enter=Auto]: " BIND_IPS
    BIND_IPS=$(echo "${BIND_IPS:-}" | tr -d ' ')

    ensure_packages openssh-client python3 iptables
    write_tls_client_script
    reset_traffic_accounting

    cat > "$FOREIGN_CONF" <<EOF
IR_IP=${IR_IP}
SEC_SSH=${SEC_SSH}
NODE_PORT=${NODE_PORT}
DATA_PORTS=${DATA_PORTS}
TLS_SNI=${TLS_SNI}
BIND_IPS=${BIND_IPS}
EOF

    echo -e "${YELLOW}Generating SSH key...${NC}"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    if [[ ! -f /root/.ssh/tunnel_key ]]; then
        ssh-keygen -t ed25519 -f /root/.ssh/tunnel_key -N "" -q
    fi

    echo -e "${YELLOW}Copying public key to Iran server over encrypted TLS 1.3 wrapper...${NC}"
    echo -e "${CYAN}Enter Iran Server root password when asked below:${NC}"
    local proxy_cmd="/usr/bin/python3 ${TLS_CLIENT_PY} ${IR_IP} ${SEC_SSH} ${TLS_SNI}"
    if [[ -n "$BIND_IPS" ]]; then
        proxy_cmd+=" ${BIND_IPS}"
    fi
    ssh-copy-id -i /root/.ssh/tunnel_key.pub \
        -o "ProxyCommand=${proxy_cmd}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        root@"$IR_IP"

    apply_foreign_configs
}

apply_foreign_configs() {
    if [[ ! -f "$FOREIGN_CONF" ]]; then
        echo -e "${RED}[ERROR] Configuration not found. Run installation first.${NC}"
        sleep 2; return
    fi
    local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS="" TLS_SNI="www.microsoft.com" BIND_IPS=""
    source "$FOREIGN_CONF"
    TLS_SNI=${TLS_SNI:-www.microsoft.com}

    ensure_packages openssh-client python3 iptables
    write_tls_client_script

    echo -e "${YELLOW}Enabling persistent tunnel traffic accounting...${NC}"
    setup_accounting_persistence

    echo -e "${YELLOW}Creating systemd reverse-tunnel service (SSH over TLS 1.3)...${NC}"
    local proxy_arg="ProxyCommand=/usr/bin/python3 ${TLS_CLIENT_PY} ${IR_IP} ${SEC_SSH} ${TLS_SNI}"
    if [[ -n "${BIND_IPS:-}" ]]; then
        proxy_arg+=" ${BIND_IPS}"
    fi

    local SSH_CMD="/usr/bin/ssh -R ${NODE_PORT}:localhost:${NODE_PORT}"
    IFS=',' read -ra PORTS <<< "$DATA_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        SSH_CMD+=" -R ${port}:localhost:${port}"
    done
    SSH_CMD+=" root@${IR_IP} -N -i /root/.ssh/tunnel_key"
    SSH_CMD+=" -o \"${proxy_arg}\""
    SSH_CMD+=" -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

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
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable reverse-tunnel >/dev/null 2>&1
    systemctl restart reverse-tunnel

    sleep 3
    if systemctl is-active --quiet reverse-tunnel; then
        echo -e "${GREEN}[OK] Foreign server configured. TLS 1.3 Tunnel is active to ${IR_IP}:${SEC_SSH}.${NC}"
    else
        echo -e "${RED}[ERROR] Tunnel service failed to start. Check logs (option 4).${NC}"
    fi
    echo
    read -p "Press Enter to return to menu..."
}

manage_service() {
    local stop_live=0
    trap 'stop_live=1' INT

    if [[ -f "$IRAN_CONF" || -f "$FOREIGN_CONF" ]]; then
        setup_accounting_persistence
    fi

    local prev_ns prev_state prev_rx=0 prev_tx=0 created_at="Not Configured"
    prev_ns=$(date +%s%N)
    if [[ -f "$IRAN_CONF" || -f "$FOREIGN_CONF" ]]; then
        prev_state=$(sync_traffic_state)
        IFS='|' read -r prev_rx prev_tx created_at <<< "$prev_state"
        sleep 0.4
    fi

    local esc=$'\033'
    local clr_eol="${esc}[K"
    local nl=$'\n'
    local c_green="${esc}[0;32m"
    local c_red="${esc}[0;31m"
    local c_yellow="${esc}[1;33m"
    local c_cyan="${esc}[0;36m"
    local c_nc="${esc}[0m"

    printf '\033[?1049h\033[2J\033[H\033[?25l'

    while [[ "$stop_live" -eq 0 ]]; do
        local now_ns live_clock cur_rx=0 cur_tx=0 total_bytes=0 delta_ns=1000000000 delta_rx=0 delta_tx=0
        now_ns=$(date +%s%N)
        live_clock=$(date '+%H:%M:%S')
        delta_ns=$(( now_ns - prev_ns ))
        if (( delta_ns <= 0 )); then
            delta_ns=1
        fi

        if [[ -f "$IRAN_CONF" || -f "$FOREIGN_CONF" ]]; then
            ensure_accounting_rules
            local cur_state
            cur_state=$(sync_traffic_state)
            IFS='|' read -r cur_rx cur_tx created_at <<< "$cur_state"
            delta_rx=$(( cur_rx - prev_rx ))
            delta_tx=$(( cur_tx - prev_tx ))
            if (( delta_rx < 0 )); then
                delta_rx=0
            fi
            if (( delta_tx < 0 )); then
                delta_tx=0
            fi
            total_bytes=$(( cur_rx + cur_tx ))
        fi

        local dl_used ul_used total_used dl_speed ul_speed
        dl_used=$(format_traffic_size "$cur_rx")
        ul_used=$(format_traffic_size "$cur_tx")
        total_used=$(format_traffic_size "$total_bytes")
        dl_speed=$(format_speed_mbs "$delta_rx" "$delta_ns")
        ul_speed=$(format_speed_mbs "$delta_tx" "$delta_ns")

        prev_rx="$cur_rx"
        prev_tx="$cur_tx"
        prev_ns="$now_ns"

        local cron_info
        if [[ -f "$CRON_FILE" ]]; then
            local cron_sched
            cron_sched=$(awk '{print $1,$2,$3,$4,$5}' "$CRON_FILE" 2>/dev/null || echo "enabled")
            cron_info="  Schedule : ${c_green}Active (${cron_sched})${c_nc}"
        else
            cron_info="  Schedule : ${c_yellow}Disabled${c_nc}"
        fi

        local sys_details=""
        if [[ -f "$TUNNEL_SERVICE" ]]; then
            local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS="" TLS_SNI="www.microsoft.com" BIND_IPS=""
            if [[ -f "$FOREIGN_CONF" ]]; then
                source "$FOREIGN_CONF"
            fi
            local svc_props active_st="unknown" sub_st="" main_pid="0" mem_bytes="" since_ts=""
            svc_props=$(systemctl show reverse-tunnel.service --no-page -p ActiveState,SubState,MainPID,MemoryCurrent,ActiveEnterTimestamp 2>/dev/null || true)
            while IFS='=' read -r k v; do
                case "$k" in
                    ActiveState) active_st="$v" ;;
                    SubState) sub_st="$v" ;;
                    MainPID) main_pid="$v" ;;
                    MemoryCurrent) mem_bytes="$v" ;;
                    ActiveEnterTimestamp) since_ts="$v" ;;
                esac
            done <<< "$svc_props"

            local mem_str st_color="$c_red"
            if [[ "$active_st" == "active" ]]; then
                st_color="$c_green"
            elif [[ "$active_st" == "activating" ]]; then
                st_color="$c_yellow"
            fi
            mem_str=$(awk -v m="${mem_bytes:-}" 'BEGIN {
                if (m ~ /^[0-9]+$/ && (m + 0.0) < 1099511627776.0) printf "%.1f MB", (m + 0.0) / 1048576.0
                else printf "N/A"
            }')
            local last_log
            last_log=$(journalctl -u reverse-tunnel.service -n 1 --no-pager -o cat 2>/dev/null || true)
            last_log="${last_log:-No recent log entries}"
            last_log="${last_log:0:52}"

            sys_details+="  Service State   : ${st_color}${active_st} (${sub_st})${c_nc}${since_ts:+ since ${since_ts:0:27}}${nl}"
            sys_details+="  Process / RAM   : Main PID ${main_pid} | Memory: ${mem_str}${nl}"
            sys_details+="  TLS 1.3 Target  : ${IR_IP:-N/A}:${SEC_SSH:-N/A} (SNI: ${TLS_SNI:-www.microsoft.com})${nl}"
            sys_details+="  Source / Ports  : Bind ${BIND_IPS:-Auto} | Node ${NODE_PORT:-N/A}, Data ${DATA_PORTS:-N/A}${nl}"
            sys_details+="  Latest Log      : ${last_log}"

        elif [[ -f "$IRAN_CONF" ]]; then
            local OUT_IP="" DATA_PORTS="" SEC_SSH="" TLS_SNI="www.microsoft.com"
            source "$IRAN_CONF"
            local tls_status="${c_yellow}Not Installed (Raw SSH Mode)${c_nc}"
            if [[ -f "$TLS_SERVER_SERVICE" ]]; then
                if systemctl is-active --quiet pg-tls-server.service 2>/dev/null; then
                    tls_status="${c_green}Active on Port ${SEC_SSH} (SNI: ${TLS_SNI:-www.microsoft.com})${c_nc}"
                else
                    tls_status="${c_red}Inactive on Port ${SEC_SSH}${c_nc}"
                fi
            fi

            local ss_raw pub_ssh_ports tun_local_ports nat_compact
            ss_raw=$(ss -tlnp4 2>/dev/null || ss -tlnp 2>/dev/null || true)
            pub_ssh_ports=$(awk '/sshd/ && $4 !~ /^127\./ && $4 !~ /^\[::1\]/ {
                n = split($4, a, ":"); p = a[n]
                if (!seen[p]++) out = (out == "" ? p : out ", " p)
            } END { print (out == "" ? "None" : out) }' <<< "$ss_raw")
            tun_local_ports=$(awk '/sshd/ && ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) {
                n = split($4, a, ":"); p = a[n]
                if (!seen[p]++) out = (out == "" ? p : out ", " p)
            } END { print out }' <<< "$ss_raw")

            if [[ -n "$tun_local_ports" ]]; then
                tun_local_ports="${c_green}${tun_local_ports:0:50}${c_nc}"
            else
                tun_local_ports="${c_red}None (Tunnel Not Connected)${c_nc}"
            fi

            nat_compact=$(iptables -t nat -L OUTPUT -n -v --line-numbers 2>/dev/null | awk '
                NR > 2 && NF >= 9 && count < 6 {
                    count++
                    num = $1; pkts = $2; bytes = $3; tgt = $4
                    dst = ($6 == "--" && NF >= 10) ? $10 : $9
                    dpt = ""; rpt = ""
                    for (i = 9; i <= NF; i++) {
                        if ($i ~ /^dpt:/) { sub(/^dpt:/, "", $i); dpt = ":" $i }
                        if ($i == "ports" && (i + 1) <= NF) { rpt = " => :" $(i + 1) }
                    }
                    printf "    #%s %-8s -> %s%s%s (pkts:%s, %s)\n", num, tgt, dst, dpt, rpt, pkts, bytes
                }' || true)
            nat_compact="${nat_compact:-    No rules in nat OUTPUT chain}"

            sys_details+="  TLS 1.3 Server   : ${tls_status}${nl}"
            sys_details+="  SSH / Tunnel Prt : SSH [${pub_ssh_ports}] | Local [${tun_local_ports}]${nl}"
            sys_details+="  NAT OUTPUT Rules :${nl}${nat_compact}"
        else
            sys_details+="  ${c_yellow}No tunnel configuration detected on this server yet.${c_nc}"
        fi

        local frame=""
        frame+="${c_green}============================================================${c_nc}${clr_eol}${nl}"
        frame+="$(printf "  ${c_cyan}PG Node SSH Tunnel Manager v%s${c_nc}         ${c_yellow}[Live %s]${c_nc}" "$SCRIPT_VERSION" "$live_clock")${clr_eol}${nl}"
        frame+="${c_green}============================================================${c_nc}${clr_eol}${nl}"
        frame+="${c_cyan}=== Tunnel Traffic & Speed (Since: ${created_at}) ===${c_nc}${clr_eol}${nl}"
        frame+=$(printf "  Download Used      : ${c_green}%-12s${c_nc} |  Download Speed : ${c_cyan}%s${c_nc}${clr_eol}" "$dl_used" "$dl_speed")$'\n'
        frame+=$(printf "  Upload Used        : ${c_green}%-12s${c_nc} |  Upload Speed   : ${c_cyan}%s${c_nc}${clr_eol}" "$ul_used" "$ul_speed")$'\n'
        frame+=$(printf "  Total Traffic Used : ${c_yellow}%s${c_nc}${clr_eol}" "$total_used")$'\n'
        frame+="------------------------------------------------------------${clr_eol}${nl}"
        frame+="${c_cyan}=== System & Rules Status ===${c_nc}${clr_eol}${nl}"
        while IFS= read -r line; do
            frame+="${line}${clr_eol}${nl}"
        done <<< "$sys_details"
        frame+="${c_cyan}=== Auto-Restart Cronjob ===${c_nc}${clr_eol}${nl}"
        frame+="${cron_info}${clr_eol}${nl}"
        frame+="------------------------------------------------------------${clr_eol}${nl}"
        frame+="${c_yellow}Updating every 1s... Press [Enter] or [q] to return to menu.${c_nc}${clr_eol}"

        printf '\033[H%s\033[J' "$frame"

        local key=""
        if read -r -s -n 1 -t 1 key; then
            if [[ -z "$key" || "$key" == $'\r' || "$key" == $'\n' || "$key" == "q" || "$key" == "Q" ]]; then
                read -r -s -t 0.02 -n 100 _ 2>/dev/null || true
                break
            fi
        fi
    done

    trap - INT
    printf '\033[?25h\033[?1049l'
}

uninstall_all() {
    print_header
    echo -e "${RED}=== Safe Uninstall ===${NC}"
    rm -f "$CRON_FILE" "$ACCT_CRON_FILE"

    if [[ -f "$ACCT_SERVICE" ]]; then
        systemctl stop pg-tunnel-acct.service 2>/dev/null || true
        systemctl disable pg-tunnel-acct.service 2>/dev/null || true
        rm -f "$ACCT_SERVICE"
        systemctl daemon-reload 2>/dev/null || true
    fi

    cleanup_accounting_rules
    rm -f "$TRAFFIC_STATE" "$TRAFFIC_LOCK" "${TRAFFIC_STATE}.tmp."*

    if [[ -f "$FOREIGN_CONF" ]]; then
        systemctl stop reverse-tunnel 2>/dev/null || true
        systemctl disable reverse-tunnel 2>/dev/null || true
        rm -f "$TUNNEL_SERVICE" "$TLS_CLIENT_PY"
        systemctl daemon-reload
        rm -f "$FOREIGN_CONF"
        echo -e "${GREEN}[OK] Service, TLS client, and traffic counters removed from Foreign server.${NC}"
    elif [[ -f "$IRAN_CONF" ]]; then
        if [[ -f "$TLS_SERVER_SERVICE" ]]; then
            systemctl stop pg-tls-server.service 2>/dev/null || true
            systemctl disable pg-tls-server.service 2>/dev/null || true
            rm -f "$TLS_SERVER_SERVICE"
            systemctl daemon-reload 2>/dev/null || true
        fi
        rm -f "$TLS_SERVER_PY" "$TLS_CERT" "$TLS_KEY"
        source "$IRAN_CONF"
        IFS=',' read -ra PORTS <<< "$DATA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            iptables -t nat -D OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        done
        netfilter-persistent save >/dev/null 2>&1 || true
        rm -f "$IRAN_CONF"
        echo -e "${GREEN}[OK] TLS server, iptables rules, and traffic counters removed from Iran server.${NC}"
    else
        echo -e "${YELLOW}No configuration found to uninstall.${NC}"
    fi
    read -p "Press Enter to return to menu..."
}

view_logs() {
    print_header
    if [[ -f "$TUNNEL_SERVICE" ]]; then
        echo -e "${CYAN}Live Foreign Tunnel Logs (Press Ctrl+C to exit)...${NC}"
        journalctl -u reverse-tunnel.service -f --no-pager
    elif [[ -f "$TLS_SERVER_SERVICE" ]]; then
        echo -e "${CYAN}Live Iran TLS Wrapper & SSH Logs (Press Ctrl+C to exit)...${NC}"
        journalctl -u pg-tls-server.service -u ssh.service -f --no-pager
    else
        echo -e "${RED}Tunnel service not found on this server.${NC}"
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

normalize_git_ref() {
    local ref="$1"
    ref=$(echo "$ref" | xargs)
    ref="${ref#https://github.com/${REPO_SLUG}/tree/}"
    ref="${ref#https://github.com/${REPO_SLUG}/blob/}"
    ref="${ref#https://github.com/${REPO_SLUG}/commit/}"
    ref="${ref#origin/}"
    ref="${ref%/script.sh}"
    echo "$ref"
}

extract_script_version() {
    local file="$1"
    local ver=""
    ver=$(sed -n 's/^SCRIPT_VERSION="\([0-9][0-9.]*\)"/\1/p' "$file" | head -n 1)
    if [[ -z "$ver" ]]; then
        ver=$(sed -n 's/^#.*Manager v\([0-9][0-9.]*\).*/\1/p' "$file" | head -n 1)
    fi
    echo "${ver:-0.0}"
}

version_gt() {
    local v1="$1" v2="$2"
    if [[ "$v1" == "$v2" ]]; then
        return 1
    fi
    local IFS=.
    local i a=() b=()
    read -ra a <<< "$v1"
    read -ra b <<< "$v2"
    local len=${#a[@]}
    if (( ${#b[@]} > len )); then
        len=${#b[@]}
    fi
    for (( i=0; i<len; i++ )); do
        local n1="${a[i]:-0}"
        local n2="${b[i]:-0}"
        if (( 10#$n1 > 10#$n2 )); then
            return 0
        elif (( 10#$n1 < 10#$n2 )); then
            return 1
        fi
    done
    return 1
}

fetch_script_from_ref() {
    local target_ref="$1"
    local dest_file="$2"
    local resolved_sha=""
    local api_json=""

    api_json=$(curl -fsSL --connect-timeout 8 --max-time 15 \
        -G --data-urlencode "sha=${target_ref}" --data-urlencode "per_page=1" \
        "https://api.github.com/repos/${REPO_SLUG}/commits" 2>/dev/null || true)

    if [[ -n "$api_json" ]]; then
        resolved_sha=$(sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' <<< "$api_json" | head -n 1)
    fi

    local download_ref="${resolved_sha:-$target_ref}"
    local downloaded=0

    if curl -fsSL --connect-timeout 8 --max-time 25 \
        -H "Accept: application/vnd.github.raw+json" \
        -G --data-urlencode "ref=${download_ref}" \
        "https://api.github.com/repos/${REPO_SLUG}/contents/script.sh" \
        -o "$dest_file" 2>/dev/null; then
        downloaded=1
    elif curl -fsSL --connect-timeout 8 --max-time 25 \
        -H "Cache-Control: no-cache" \
        "https://raw.githubusercontent.com/${REPO_SLUG}/${download_ref}/script.sh?cb=$(date +%s)" \
        -o "$dest_file" 2>/dev/null; then
        downloaded=1
    fi

    if [[ "$downloaded" -ne 1 || ! -s "$dest_file" ]]; then
        rm -f "$dest_file"
        return 1
    fi

    if [[ "$(head -n 1 "$dest_file")" != "#!/bin/bash"* ]] || ! bash -n "$dest_file" 2>/dev/null; then
        rm -f "$dest_file"
        return 1
    fi

    echo "$download_ref"
    return 0
}

update_script() {
    print_header
    echo -e "${CYAN}=== Update Script from GitHub ===${NC}"
    sync_traffic_state >/dev/null 2>&1 || true

    local tmp_main="/usr/local/bin/pg-tunnel.main.tmp"
    local tmp_target="/usr/local/bin/pg-tunnel.tmp"
    rm -f "$tmp_main" "$tmp_target"

    echo -e "${YELLOW}Checking latest version on 'main' branch...${NC}"
    local main_ref="" main_ver="0.0"
    if main_ref=$(fetch_script_from_ref "main" "$tmp_main"); then
        main_ver=$(extract_script_version "$tmp_main")
        echo -e "  Current Installed Version : ${CYAN}v${SCRIPT_VERSION}${NC}"
        echo -e "  GitHub 'main' Version     : ${GREEN}v${main_ver}${NC} (${main_ref:0:7})"
    else
        echo -e "  Current Installed Version : ${CYAN}v${SCRIPT_VERSION}${NC}"
        echo -e "  GitHub 'main' Status      : ${YELLOW}Could not verify 'main' automatically${NC}"
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
    echo -e "${CYAN}=== Auto-Restart Cronjob Configuration ===${NC}"
    echo "  1) Every 1 Hour"
    echo "  2) Every 2 Hours"
    echo "  3) Every 3 Hours"
    echo "  4) Every 5 Hours"
    echo "  5) Every 12 Hours"
    echo "  6) Every 24 Hours (Daily)"
    echo "  7) Disable Cronjob"
    echo -e "------------------------------------------------------------"
    read -p "Select interval option [1-7]: " cron_choice

    local min_offset="0"
    if [[ -f "$FOREIGN_CONF" ]]; then
        min_offset="1"
    fi

    local schedule=""
    case $cron_choice in
        1) schedule="${min_offset} * * * *" ;;
        2) schedule="${min_offset} */2 * * *" ;;
        3) schedule="${min_offset} */3 * * *" ;;
        4) schedule="${min_offset} */5 * * *" ;;
        5) schedule="${min_offset} */12 * * *" ;;
        6) schedule="${min_offset} 0 * * *" ;;
        7)
            rm -f "$CRON_FILE"
            echo -e "${GREEN}[OK] Auto-restart cronjob disabled.${NC}"
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
    echo -e "${GREEN}[OK] Cronjob scheduled successfully: ($schedule)${NC}"
    echo
    read -p "Press Enter to return to menu..."
}

main_menu() {
    while true; do
        print_header
        echo "  1. Install / Configure Tunnel (TLS 1.3 Anti-DPI)"
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
