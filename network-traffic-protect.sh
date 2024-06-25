#!/bin/bash

# Function to detect the Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    else
        echo "Unable to detect the Linux distribution."
        exit 1
    fi
}

# Function to apply iptables rules
apply_iptables_rules() {
    # Flush all current rules from iptables
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # Set default chain policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow unlimited traffic on loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow incoming SSH connections
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Allow incoming HTTP/HTTPS connections
    iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # Allow outgoing HTTP/HTTPS connections
    iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Allow incoming DNS (UDP and TCP)
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT

    # Allow outgoing DNS (UDP and TCP)
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow ping
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

    # Allow established and related traffic
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

    # Log dropped packets (optional)
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables INPUT drop: " --log-level 7
    iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables FORWARD drop: " --log-level 7
}

# Function to save iptables rules
save_iptables_rules() {
    case $DISTRO in
        debian|ubuntu|linuxmint)
            apt-get install -y iptables-persistent
            netfilter-persistent save
            ;;
        centos|rhel|fedora)
            service iptables save
            ;;
        opensuse|suse)
            iptables-save > /etc/sysconfig/iptables
            ;;
        arch|manjaro)
            pacman -S --noconfirm iptables
            iptables-save > /etc/iptables/iptables.rules
            systemctl enable iptables
            systemctl start iptables
            ;;
        gentoo)
            emerge net-firewall/iptables
            /etc/init.d/iptables save
            rc-update add iptables default
            ;;
        *)
            echo "Unsupported Linux distribution."
            exit 1
            ;;
    esac
}

# Main script execution
detect_distro
apply_iptables_rules
save_iptables_rules

echo "Network traffic protection rules applied successfully on $DISTRO."
