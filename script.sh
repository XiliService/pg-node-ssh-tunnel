#!/bin/bash

# ============================================================
# PG Node SSH Tunnel Manager v6.2
# GitHub: https://github.com/XiliService/pg-node-ssh-tunnel
# Script File: script.sh
# English Only | Production Ready | Auto-Updater & Cronjob
# ============================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_URL="https://raw.githubusercontent.com/XiliService/pg-node-ssh-tunnel/main/script.sh"
CONF_DIR="/etc/pg-tunnel"
IRAN_CONF="${CONF_DIR}/iran.conf"
FOREIGN_CONF="${CONF_DIR}/foreign.conf"
CRON_FILE="/etc/cron.d/pg-tunnel-restart"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root.${NC}"
        exit 1
    fi
}

handle_cron_execution() {
    if [[ "${1:-}" == "cron-auto-repair" ]]; then
        check_root
        if [[ -f "$IRAN_CONF" ]]; then
            systemctl restart ssh.service 2>/dev/null || true
            source "$IRAN_CONF"
            IFS=',' read -ra PORTS <<< "$DATA_PORTS"
            for port in "${PORTS[@]}"; do
                port=$(echo "$port" | xargs)
                iptables -t nat -C OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || \
                iptables -t nat -A OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
            done
        elif [[ -f "$FOREIGN_CONF" ]]; then
            systemctl restart reverse-tunnel 2>/dev/null || true
        fi
        exit 0
    fi
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
    clear
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${CYAN}       PG Node SSH Tunnel Manager v6.2${NC}"
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
    print_header
    echo -e "${CYAN}=== System Status ===${NC}"
    if [[ -f /etc/systemd/system/reverse-tunnel.service ]]; then
        echo -e "${YELLOW}Foreign Reverse Tunnel Service Status:${NC}"
        systemctl status reverse-tunnel --no-pager -l || true
    else
        echo -e "${YELLOW}Iran iptables NAT Rules (OUTPUT):${NC}"
        iptables -t nat -L OUTPUT -n -v --line-numbers || true
        echo -e "\n${YELLOW}SSH Listening Ports:${NC}"
        ss -tlnp | grep ssh || true
    fi

    echo -e "\n${CYAN}=== Auto-Restart Cronjob Status ===${NC}"
    if [[ -f "$CRON_FILE" ]]; then
        echo -e "${GREEN}Active Cron Schedule:${NC} $(cat "$CRON_FILE")"
    else
        echo -e "${YELLOW}Auto-Restart Cronjob is currently disabled.${NC}"
    fi

    echo
    read -p "Press Enter to return to menu..."
}

uninstall_all() {
    print_header
    echo -e "${RED}=== Safe Uninstall ===${NC}"
    rm -f "$CRON_FILE"
    if [[ -f "$FOREIGN_CONF" ]]; then
        systemctl stop reverse-tunnel 2>/dev/null || true
        systemctl disable reverse-tunnel 2>/dev/null || true
        rm -f /etc/systemd/system/reverse-tunnel.service
        systemctl daemon-reload
        rm -f "$FOREIGN_CONF"
        echo -e "${GREEN}[OK] Service removed from Foreign server.${NC}"
    elif [[ -f "$IRAN_CONF" ]]; then
        source "$IRAN_CONF"
        IFS=',' read -ra PORTS <<< "$DATA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            iptables -t nat -D OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        done
        netfilter-persistent save >/dev/null 2>&1
        rm -f "$IRAN_CONF"
        echo -e "${GREEN}[OK] iptables rules removed from Iran server.${NC}"
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

update_script() {
    print_header
    echo -e "${CYAN}=== Update Script from GitHub ===${NC}"
    echo -e "${YELLOW}Fetching latest version...${NC}"
    if curl -s -f -o /usr/local/bin/pg-tunnel.tmp "$REPO_URL"; then
        mv /usr/local/bin/pg-tunnel.tmp /usr/local/bin/pg-tunnel
        chmod +x /usr/local/bin/pg-tunnel
        echo -e "${GREEN}[OK] pg-tunnel successfully updated!${NC}"
        echo -e "${YELLOW}Restarting manager...${NC}"
        sleep 2
        exec /usr/local/bin/pg-tunnel
    else
        echo -e "${RED}[ERROR] Failed to download update. Check network or repository URL.${NC}"
        rm -f /usr/local/bin/pg-tunnel.tmp
        read -p "Press Enter to return to menu..."
    fi
}

repair_tunnels() {
    print_header
    echo -e "${CYAN}=== Repair / Restart Tunnels ===${NC}"
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

handle_cron_execution "${1:-}"
check_root
self_install
main_menu
