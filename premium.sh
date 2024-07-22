#!/bin/bash


check_system_resources() {
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    TOTAL_CORES=$(nproc)
    echo "Total RAM: $TOTAL_MEM MB"
    echo "Total CPU Cores: $TOTAL_CORES"
}

get_resource_allocation() {
    read -p "Enter RAM to allocate (in MB, max 4096, or 'all' for max available up to 4096): " RAM_ALLOC
    if [ "$RAM_ALLOC" = "all" ]; then
        RAM_ALLOC=$((TOTAL_MEM < 4096 ? TOTAL_MEM : 4096))
    elif [ "$RAM_ALLOC" -gt 4096 ] || [ "$RAM_ALLOC" -gt "$TOTAL_MEM" ]; then
        RAM_ALLOC=$((TOTAL_MEM < 4096 ? TOTAL_MEM : 4096))
        echo "RAM allocation adjusted to $RAM_ALLOC MB"
    fi

    read -p "Enter number of CPU cores to use (max $TOTAL_CORES, or 'all' for all available): " CORE_ALLOC
    if [ "$CORE_ALLOC" = "all" ]; then
        CORE_ALLOC=$TOTAL_CORES
    elif [ "$CORE_ALLOC" -gt "$TOTAL_CORES" ]; then
        CORE_ALLOC=$TOTAL_CORES
        echo "CPU core allocation adjusted to $CORE_ALLOC"
    fi
}


check_system_resources


get_resource_allocation


sudo apt-get update
sudo apt-get install -y iptables-persistent fail2ban unbound haveged apparmor ufw crowdsec crowdsec-firewall-bouncer-iptables nftables conntrack suricata cgroup-tools


sudo cgcreate -g cpu,cpuset,memory:suricata


sudo cgset -r cpu.cfs_quota_us=$((CORE_ALLOC * 100000)) suricata
sudo cgset -r cpuset.cpus=0-$((CORE_ALLOC - 1)) suricata
sudo cgset -r memory.limit_in_bytes=$((RAM_ALLOC * 1024 * 1024)) suricata


cat <<EOF | sudo tee /etc/systemd/system/suricata.service
[Unit]
Description=Suricata Intrusion Detection Service
After=network.target

[Service]
ExecStart=/usr/bin/cgexec -g cpu,cpuset,memory:suricata /usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
EOF


sudo systemctl daemon-reload


read -p "Enter IP addresses to whitelist, separated by commas: " IP_WHITELIST
IFS=',' read -r -a WHITELIST_ARRAY <<< "$IP_WHITELIST"

# Configure iptables
iptables -F
iptables -X

for IP in "${WHITELIST_ARRAY[@]}"; do
    iptables -A INPUT -s "$IP" -j ACCEPT
done

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


iptables -A INPUT -p icmp --icmp-type echo-request -j DROP


iptables -N PORT_PROTECT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 -j PORT_PROTECT
iptables -A PORT_PROTECT -j LOG --log-prefix "Port DDoS attempt: " --log-level 7
iptables -A PORT_PROTECT -j DROP


iptables -N RATE_LIMIT
iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 -j RATE_LIMIT
iptables -A RATE_LIMIT -j LOG --log-prefix "Rate Limit: " --log-level 7
iptables -A RATE_LIMIT -j DROP


iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j LOG --log-prefix "New Connection: " --log-level 7

# Protect all ports (0-65535)
iptables -A INPUT -p tcp --match multiport --dports 0:65535 -m limit --limit 50/sec --limit-burst 100 -j ACCEPT
iptables -A INPUT -p udp --match multiport --dports 0:65535 -m limit --limit 50/sec --limit-burst 100 -j ACCEPT


iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Final rule: drop all other incoming traffic
iptables -A INPUT -j DROP

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Enable netfilter-persistent
sudo systemctl enable netfilter-persistent

# Configure fail2ban
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 300
maxretry = 3

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

cat <<EOF > /etc/unbound/unbound.conf
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    verbosity: 1
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: $CORE_ALLOC

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 1.0.0.1
EOF

# Restart and enable services
sudo systemctl restart unbound
sudo systemctl enable unbound
sudo systemctl enable crowdsec
sudo systemctl start crowdsec
sudo systemctl enable crowdsec-firewall-bouncer
sudo systemctl start crowdsec-firewall-bouncer


echo "Configuring Advanced Kill Switch..."


sudo nft add table ip killswitch


sudo nft add chain ip killswitch monitor { type filter hook prerouting priority -300 \; policy accept \; }


sudo nft add rule ip killswitch monitor ct state new counter
sudo nft add rule ip killswitch monitor ip saddr @blacklist counter drop


sudo nft add set ip killswitch blacklist { type ipv4_addr \; flags dynamic,timeout \; timeout 1h \; }

sudo sed -i "s/^#run-as:/run-as:\n  user: suricata\n  group: suricata\nmax-pending-packets: 1024\ndetection:\n  threads: $CORE_ALLOC/" /etc/suricata/suricata.yaml

SURICATA_MEM="${RAM_ALLOC}mb"
sudo sed -i "s/^#memory:/memory:\n  memcap: $SURICATA_MEM\n  max-packet-mem: 256mb/" /etc/suricata/suricata.yaml

# Create a script for dynamic IP blocking
cat <<EOF > /usr/local/bin/dynamic_block.sh
#!/bin/bash
while read line; do
    IP=\$(echo \$line | cut -d' ' -f3)
    sudo nft add element ip killswitch blacklist { \$IP }
done
EOF

chmod +x /usr/local/bin/dynamic_block.sh

# Configure Suricata to call the dynamic blocking script
echo "alert http any any -> any any (msg:\"Potential DDoS Attempt\"; flow:established; threshold: type both, track by_src, count 100, seconds 60; sid:1000001; rev:1;)" | sudo tee -a /etc/suricata/rules/local.rules
echo "output: fast: /var/log/suricata/fast.log" | sudo tee -a /etc/suricata/suricata.yaml

suspicious IPs
(crontab -l 2>/dev/null; echo "* * * * * tail -n1000 /var/log/suricata/fast.log | /usr/local/bin/dynamic_block.sh") | crontab -

# Configure sysctl for improved network performance
cat <<EOF | sudo tee -a /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
EOF

sudo sysctl -p


sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl restart fail2ban

echo "Advanced Kill Switch configuration complete."


save_config() {
    echo "RAM_ALLOC=$RAM_ALLOC" > /etc/suricata_config
    echo "CORE_ALLOC=$CORE_ALLOC" >> /etc/suricata_config
}


load_config() {
    if [ -f /etc/suricata_config ]; then
        source /etc/suricata_config
    fi
}


save_config

echo "Configuration complete. Your server has been optimized and secured with an advanced kill switch."
echo "To reconfigure, simply run this script again."


read -p "Do you want to reboot now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    sudo reboot
fi
