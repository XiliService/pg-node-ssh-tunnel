#!/bin/bash

# ============================================================
# Auto Reverse SSH Tunnel Manager v5.2 (Custom Port & Optimizer)
# English Only | Production Ready | Flexible SSH Port
# ============================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    clear
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${CYAN}       Auto Reverse SSH Tunnel Manager v5.2${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

# ------------------------------------------------------------
# 1. INSTALL - IRAN SERVER
# ------------------------------------------------------------
install_iran() {
    print_header
    echo -e "${CYAN}=== Configuring IRAN Server ===${NC}"
    echo

    read -p "Foreign Server IP (inside Pasarguard Outbounds): " OUT_IP
    read -p "Outbound ports (comma separated, e.g. 64483,26132,22971): " DATA_PORTS
    read -p "Custom Secondary SSH Port to ADD (e.g. 8543 or 2222): " SEC_SSH
    SEC_SSH=${SEC_SSH:-2222}

    echo -e "${YELLOW}Installing required packages...${NC}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent netfilter-persistent openssh-server

    echo -e "${YELLOW}Disabling ssh.socket and enabling stable ssh.service...${NC}"
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    systemctl mask ssh.socket 2>/dev/null || true
    rm -rf /etc/systemd/system/ssh.socket.d/
    systemctl daemon-reload

    echo -e "${YELLOW}Configuring SSH ports (22 and ${SEC_SSH})...${NC}"
    sed -i '/^Port /d' /etc/ssh/sshd_config
    echo "Port 22" >> /etc/ssh/sshd_config
    echo "Port ${SEC_SSH}" >> /etc/ssh/sshd_config

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

    echo
    echo -e "${GREEN}[OK] Iran server configured successfully.${NC}"
    echo -e "SSH is listening on Port 22 and your Custom Port: ${SEC_SSH}"
    echo -e "${YELLOW}Now run Option 1 -> 2 on the FOREIGN server using SSH Port ${SEC_SSH}.${NC}"
    echo
    read -p "Press Enter to return to menu..."
}

# ------------------------------------------------------------
# 1. INSTALL - FOREIGN SERVER
# ------------------------------------------------------------
install_foreign() {
    print_header
    echo -e "${CYAN}=== Configuring FOREIGN Server ===${NC}"
    echo

    read -p "Iran Server IP: " IR_IP
    read -p "Custom Secondary SSH Port on Iran (e.g. 8543 or 2222): " SEC_SSH
    SEC_SSH=${SEC_SSH:-2222}
    read -p "Node management port (e.g. 62075): " NODE_PORT
    read -p "Outbound ports to tunnel (comma separated, e.g. 64483,26132,22971): " DATA_PORTS

    echo -e "${YELLOW}Generating SSH key (if not exists)...${NC}"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    if [[ ! -f /root/.ssh/tunnel_key ]]; then
        ssh-keygen -t ed25519 -f /root/.ssh/tunnel_key -N "" -q
    fi

    echo -e "${YELLOW}Copying public key to Iran server (port ${SEC_SSH})...${NC}"
    echo -e "${CYAN}Enter Iran Server root password when asked below:${NC}"
    ssh-copy-id -i /root/.ssh/tunnel_key.pub -p "$SEC_SSH" -o StrictHostKeyChecking=no root@"$IR_IP"

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

# ------------------------------------------------------------
# 2. STATUS CHECK
# ------------------------------------------------------------
manage_service() {
    print_header
    echo -e "${CYAN}=== System Status ===${NC}"
    echo
    if [[ -f /etc/systemd/system/reverse-tunnel.service ]]; then
        echo -e "${YELLOW}Foreign Reverse Tunnel Service Status:${NC}"
        systemctl status reverse-tunnel --no-pager -l || true
    else
        echo -e "${YELLOW}Iran iptables NAT Rules (OUTPUT):${NC}"
        iptables -t nat -L OUTPUT -n -v --line-numbers || true
        echo
        echo -e "${YELLOW}SSH Listening Ports:${NC}"
        ss -tlnp | grep ssh || true
    fi
    echo
    read -p "Press Enter to return to menu..."
}

# ------------------------------------------------------------
# 3. SAFE UNINSTALL
# ------------------------------------------------------------
uninstall_all() {
    print_header
    echo -e "${RED}=== Safe Uninstall ===${NC}"
    echo
    echo "1) Iran Server (remove iptables redirect rules)"
    echo "2) Foreign Server (delete reverse-tunnel service)"
    read -p "Select [1-2]: " serv

    if [[ "$serv" == "1" ]]; then
        read -p "Foreign Server IP used previously: " OUT_IP
        read -p "Outbound ports (comma separated): " DATA_PORTS
        IFS=',' read -ra PORTS <<< "$DATA_PORTS"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            iptables -t nat -D OUTPUT -p tcp -d "$OUT_IP" --dport "$port" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        done
        netfilter-persistent save >/dev/null 2>&1
        echo -e "${GREEN}[OK] iptables redirect rules removed from Iran server.${NC}"
        echo -e "${YELLOW}Note: SSH ports remain active for connectivity safety.${NC}"
    elif [[ "$serv" == "2" ]]; then
        systemctl stop reverse-tunnel 2>/dev/null || true
        systemctl disable reverse-tunnel 2>/dev/null || true
        rm -f /etc/systemd/system/reverse-tunnel.service
        systemctl daemon-reload
        echo -e "${GREEN}[OK] reverse-tunnel service removed from Foreign server.${NC}"
    else
        echo -e "${RED}Invalid selection.${NC}"
    fi
    echo
    read -p "Press Enter to return to menu..."
}

# ------------------------------------------------------------
# 4. VIEW LOGS
# ------------------------------------------------------------
view_logs() {
    print_header
    if [[ -f /etc/systemd/system/reverse-tunnel.service ]]; then
        echo -e "${CYAN}Showing reverse-tunnel live logs (Press Ctrl+C to exit)...${NC}"
        echo
        journalctl -u reverse-tunnel.service -f --no-pager
    else
        echo -e "${RED}Tunnel service not found on this server. (Logs exist on Foreign server only).${NC}"
        read -p "Press Enter to return to menu..."
    fi
}

# ------------------------------------------------------------
# 5. NETWORK OPTIMIZER (Global Kernel & TCP Buffer Tuning)
# ------------------------------------------------------------
optimizer() {
    print_header
    echo -e "${CYAN}=== Advanced Network Optimizer ===${NC}"
    echo -e "${YELLOW}Applying global kernel TCP tuning (applies to ALL ports & tunnels)...${NC}"
    echo

    cat > /etc/sysctl.d/99-xray-tunnel-optimize.conf <<'EOF'
# Global Network Optimization (System-Wide for All Ports & Services)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Buffer Optimization (Optimizes high-throughput TCP streams)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 4096

# Latency, Connection Reuse & Fast Open
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

# System Connection Tracking Limits
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

# File Descriptors & Limits
fs.file-max = 2097152
fs.nr_open = 2097152

# Security & Network Anti-Scan Hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# Disable IPv6 (Prevents leaks and improves IPv4 routing speed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Virtual Memory Swap Optimization
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

    # Load Kernel Modules
    modprobe tcp_bbr 2>/dev/null || true
    modprobe nf_conntrack 2>/dev/null || true
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true

    # System File Open Limits
    cat > /etc/security/limits.d/99-tunnel.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    sysctl --system >/dev/null 2>&1

    echo -e "${GREEN}[OK] Optimizations applied system-wide for ALL ports & interfaces.${NC}"
    echo
    echo "Active Tuning Status:"
    echo "  Congestion Control Algorithm : $(sysctl -n net.ipv4.tcp_congestion_control)"
    echo "  Queue Discipline Management : $(sysctl -n net.core.default_qdisc)"
    echo "  TCP Fast Open Protocol       : $(sysctl -n net.ipv4.tcp_fastopen)"
    echo "  System Open File Limit      : $(sysctl -n fs.file-max)"
    echo
    echo -e "${YELLOW}Note: Re-login or reboot for file limits to take full effect.${NC}"
    echo
    read -p "Press Enter to return to menu..."
}

# ------------------------------------------------------------
# MAIN MENU LOOP
# ------------------------------------------------------------
main_menu() {
    while true; do
        print_header
        echo "  1. Install / Configure Tunnel"
        echo "  2. Check Status / Rules"
        echo "  3. Uninstall Safely"
        echo "  4. View Tunnel Logs (Foreign)"
        echo "  5. Network Optimizer (BBR & System Tuning)"
        echo "  0. Exit"
        echo -e "------------------------------------------------------------"
        read -p "Select option [0-5]: " choice

        case $choice in
            1)
                echo
                echo "1) Iran Server"
                echo "2) Foreign Server"
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
            0) echo -e "${GREEN}Goodbye.${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

# Execute
check_root
main_menu