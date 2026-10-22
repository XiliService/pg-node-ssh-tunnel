#!/bin/bash

# ============================================================
# PG Node SSH Tunnel Manager v6.3
# GitHub: https://github.com/XiliService/pg-node-ssh-tunnel
# Script File: script.sh
# English Only | Production Ready | Auto-Updater & Cronjob
# ============================================================

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="6.3"
REPO_SLUG="XiliService/pg-node-ssh-tunnel"
REPO_URL="https://raw.githubusercontent.com/${REPO_SLUG}/main/script.sh"
CONF_DIR="/etc/pg-tunnel"
IRAN_CONF="${CONF_DIR}/iran.conf"
FOREIGN_CONF="${CONF_DIR}/foreign.conf"
UPDATE_REF_FILE="${CONF_DIR}/update_ref.conf"
TRAFFIC_STATE="${CONF_DIR}/traffic.state"
TRAFFIC_LOCK="${CONF_DIR}/traffic.lock"
CRON_FILE="/etc/cron.d/pg-tunnel-restart"
ACCT_CRON_FILE="/etc/cron.d/pg-tunnel-acct"
ACCT_SERVICE="/etc/systemd/system/pg-tunnel-acct.service"

trap '[[ -t 1 ]] && printf "\033[?25h" || true' EXIT

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root.${NC}"
        exit 1
    fi
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
        local OUT_IP="" DATA_PORTS="" SEC_SSH=""
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
        local IR_IP="" SEC_SSH="" NODE_PORT="" DATA_PORTS=""
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
Before=network-online.target ssh.service reverse-tunnel.service shutdown.target
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

bootstrap_existing_accounting() {
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
                systemctl restart ssh.service 2>/dev/null || true
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
    echo -e "${CYAN}       PG Node SSH Tunnel Manager v6.3${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

install_iran() {
    print_header
    echo -e "${CYAN}=== Configuring IRAN Server ===${NC}"
    echo

    read -p "Foreign Server IP (inside Pasarguard Outbounds): " OUT_IP
    read -p "Outbound ports (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
    read -p "Custom Secondary SSH Port to ADD (e.g. 8543 or 2222): " SEC_SSH
    SEC_SSH=${SEC_SSH:-2222}

    reset_traffic_accounting

    echo "OUT_IP=$OUT_IP" > "$IRAN_CONF"
    echo "DATA_PORTS=$DATA_PORTS" >> "$IRAN_CONF"
    echo "SEC_SSH=$SEC_SSH" >> "$IRAN_CONF"

    apply_iran_configs
}

apply_iran_configs() {
    if [[ ! -f "$IRAN_CONF" ]]; then
        echo -e "${RED}[ERROR] Configuration not found. Run installation first.${NC}"
        sleep 2; return
    fi
    source "$IRAN_CONF"

    echo -e "${YELLOW}Installing required packages...${NC}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent netfilter-persistent openssh-server

    echo -e "${YELLOW}Disabling ssh.socket and configuring ports...${NC}"
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    systemctl mask ssh.socket 2>/dev/null || true
    rm -rf /etc/systemd/system/ssh.socket.d/

    sed -i '/^Port /d' /etc/ssh/sshd_config
    echo "Port 22" >> /etc/ssh/sshd_config
    echo "Port ${SEC_SSH}" >> /etc/ssh/sshd_config

    systemctl daemon-reload
    systemctl unmask ssh.service 2>/dev/null || true
    systemctl enable ssh.service >/dev/null 2>&1
    systemctl restart ssh.service

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
    netfilter-persistent save >/dev/null 2>&1

    echo -e "${GREEN}[OK] Iran server configured successfully.${NC}"
    echo -e "SSH is listening on Port 22 and Custom Port: ${SEC_SSH}"
    echo
    read -p "Press Enter to return to menu..."
}

install_foreign() {
    print_header
    echo -e "${CYAN}=== Configuring FOREIGN Server ===${NC}"
    echo

    read -p "Iran Server IP: " IR_IP
    read -p "Custom Secondary SSH Port on Iran (e.g. 8543 or 2222): " SEC_SSH
    SEC_SSH=${SEC_SSH:-2222}
    read -p "Node management port (e.g. 62075): " NODE_PORT
    read -p "Outbound ports to tunnel (comma separated, e.g. 64483,26132): " DATA_PORTS

    reset_traffic_accounting

    echo "IR_IP=$IR_IP" > "$FOREIGN_CONF"
    echo "SEC_SSH=$SEC_SSH" >> "$FOREIGN_CONF"
    echo "NODE_PORT=$NODE_PORT" >> "$FOREIGN_CONF"
    echo "DATA_PORTS=$DATA_PORTS" >> "$FOREIGN_CONF"

    echo -e "${YELLOW}Generating SSH key...${NC}"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    if [[ ! -f /root/.ssh/tunnel_key ]]; then
        ssh-keygen -t ed25519 -f /root/.ssh/tunnel_key -N "" -q
    fi

    echo -e "${YELLOW}Copying public key to Iran server...${NC}"
    echo -e "${CYAN}Enter Iran Server root password when asked below:${NC}"
    ssh-copy-id -i /root/.ssh/tunnel_key.pub -p "$SEC_SSH" -o StrictHostKeyChecking=no root@"$IR_IP"

    apply_foreign_configs
}

apply_foreign_configs() {
    if [[ ! -f "$FOREIGN_CONF" ]]; then
        echo -e "${RED}[ERROR] Configuration not found. Run installation first.${NC}"
        sleep 2; return
    fi
    source "$FOREIGN_CONF"

    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing iptables package for traffic accounting...${NC}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables
    fi

    echo -e "${YELLOW}Enabling persistent tunnel traffic accounting...${NC}"
    setup_accounting_persistence

    echo -e "${YELLOW}Creating systemd reverse-tunnel service...${NC}"
    SSH_CMD="/usr/bin/ssh -R ${NODE_PORT}:localhost:${NODE_PORT}"
    IFS=',' read -ra PORTS <<< "$DATA_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        SSH_CMD+=" -R ${port}:localhost:${port}"
    done
    SSH_CMD+=" root@${IR_IP} -p ${SEC_SSH} -N -i /root/.ssh/tunnel_key"
    SSH_CMD+=" -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no"

    cat > /etc/systemd/system/reverse-tunnel.service <<EOF
[Unit]
Description=Reverse SSH Tunnel to Iran Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SSH_CMD}
Restart=always
RestartSec=8
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable reverse-tunnel >/dev/null 2>&1
    systemctl restart reverse-tunnel

    sleep 2
    if systemctl is-active --quiet reverse-tunnel; then
        echo -e "${GREEN}[OK] Foreign server configured. Tunnel is active via SSH Port ${SEC_SSH}.${NC}"
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

    printf '\033[2J\033[H\033[?25l'

    while [[ "$stop_live" -eq 0 ]]; do
        local now_ns cur_rx=0 cur_tx=0 total_bytes=0 delta_ns=1000000000 delta_rx=0 delta_tx=0
        now_ns=$(date +%s%N)
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
            cron_info="${c_green}Active Cron Schedule:${c_nc} $(cat "$CRON_FILE")"
        else
            cron_info="${c_yellow}Auto-Restart Cronjob is currently disabled.${c_nc}"
        fi

        local sys_details=""
        if [[ -f /etc/systemd/system/reverse-tunnel.service ]]; then
            sys_details+="${c_yellow}Foreign Reverse Tunnel Service Status:${c_nc}${nl}"
            sys_details+="$(systemctl status reverse-tunnel --no-pager -l 2>&1 || true)"
        elif [[ -f "$IRAN_CONF" ]]; then
            sys_details+="${c_yellow}Iran iptables NAT Rules (OUTPUT):${c_nc}${nl}"
            sys_details+="$(iptables -t nat -L OUTPUT -n -v --line-numbers 2>&1 || true)${nl}${nl}"
            sys_details+="${c_yellow}SSH Listening Ports:${c_nc}${nl}"
            sys_details+="$(ss -tlnp 2>/dev/null | grep ssh || true)"
        else
            sys_details+="${c_yellow}No tunnel configuration detected on this server yet.${c_nc}"
        fi

        local frame=""
        frame+="${c_green}============================================================${c_nc}${clr_eol}${nl}"
        frame+="${c_cyan}       PG Node SSH Tunnel Manager v6.3${c_nc}${clr_eol}${nl}"
        frame+="${c_green}============================================================${c_nc}${clr_eol}${nl}"
        frame+="${c_cyan}=== Tunnel Traffic & Live Speed (Since: ${created_at}) ===${c_nc}${clr_eol}${nl}"
        frame+=$(printf "  Download Used      : ${c_green}%-12s${c_nc} |  Live Download Speed : ${c_cyan}%s${c_nc}${clr_eol}" "$dl_used" "$dl_speed")$'\n'
        frame+=$(printf "  Upload Used        : ${c_green}%-12s${c_nc} |  Live Upload Speed   : ${c_cyan}%s${c_nc}${clr_eol}" "$ul_used" "$ul_speed")$'\n'
        frame+=$(printf "  Total Traffic Used : ${c_yellow}%s${c_nc}${clr_eol}" "$total_used")$'\n'
        frame+="------------------------------------------------------------${clr_eol}${nl}"
        frame+="${c_cyan}=== System Status ===${c_nc}${clr_eol}${nl}"
        while IFS= read -r line; do
            frame+="${line}${clr_eol}${nl}"
        done <<< "$sys_details"
        frame+="${clr_eol}${nl}${c_cyan}=== Auto-Restart Cronjob Status ===${c_nc}${clr_eol}${nl}"
        frame+="${cron_info}${clr_eol}${nl}"
        frame+="------------------------------------------------------------${clr_eol}${nl}"
        frame+="${c_yellow}Live updating every 1s... Press [Enter] or [q] to return to menu.${c_nc}${clr_eol}${nl}"

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
    printf '\033[?25h'
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
        rm -f /etc/systemd/system/reverse-tunnel.service
        systemctl daemon-reload
        rm -f "$FOREIGN_CONF"
        echo -e "${GREEN}[OK] Service and traffic counters removed from Foreign server.${NC}"
    elif [[ -f "$IRAN_CONF" ]]; then
        source "$IRAN_CONF"
        IFS=',' read -ra PORTS <<< "$DATA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            iptables -t nat -D OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        done
        netfilter-persistent save >/dev/null 2>&1 || true
        rm -f "$IRAN_CONF"
        echo -e "${GREEN}[OK] iptables rules and traffic counters removed from Iran server.${NC}"
    else
        echo -e "${YELLOW}No configuration found to uninstall.${NC}"
    fi
    read -p "Press Enter to return to menu..."
}

view_logs() {
    print_header
    if [[ -f /etc/systemd/system/reverse-tunnel.service ]]; then
        echo -e "${CYAN}Live Logs (Press Ctrl+C to exit)...${NC}"
        journalctl -u reverse-tunnel.service -f --no-pager
    else
        echo -e "${RED}Tunnel service not found here (Logs are on Foreign server).${NC}"
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
    echo -e "Enter a working branch name or commit SHA to fetch its latest version directly without PR/Merge."

    local saved_ref=""
    if [[ -f "$UPDATE_REF_FILE" ]]; then
        saved_ref=$(cat "$UPDATE_REF_FILE" 2>/dev/null | xargs || true)
    fi

    local input_ref=""
    if [[ -n "$saved_ref" ]]; then
        read -p "Branch name or commit SHA [Enter='${saved_ref}', 0=Cancel]: " input_ref
        input_ref=${input_ref:-$saved_ref}
    else
        read -p "Branch name or commit SHA (e.g. arena/... or commit hash, 0=Cancel): " input_ref
    fi

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
        mkdir -p "$CONF_DIR"
        echo "$input_ref" > "$UPDATE_REF_FILE"
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
        echo -e "${YELLOW}Restarting SSH and re-applying Iran iptables rules safely...${NC}"
        systemctl restart ssh.service
        apply_iran_configs
    elif [[ -f "$FOREIGN_CONF" ]]; then
        echo -e "${YELLOW}Restarting Reverse Tunnel service...${NC}"
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

    local schedule=""
    case $cron_choice in
        1) schedule="0 * * * *" ;;
        2) schedule="0 */2 * * *" ;;
        3) schedule="0 */3 * * *" ;;
        4) schedule="0 */5 * * *" ;;
        5) schedule="0 */12 * * *" ;;
        6) schedule="0 0 * * *" ;;
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
        echo "  1. Install / Configure Tunnel"
        echo "  2. Check Status / Rules"
        echo "  3. Uninstall Safely"
        echo "  4. View Tunnel Logs (Foreign)"
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
