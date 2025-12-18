#!/bin/bash

echo "Setting up sandbox network environment..."

# 配置防火墙规则，阻止所有外部通信
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 允许内部环回通信
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 允许沙箱网络内部通信
iptables -A INPUT -s 172.20.0.0/16 -j ACCEPT
iptables -A OUTPUT -d 172.20.0.0/16 -j ACCEPT

echo "Sandbox network isolation configured successfully"
echo "Network rules:"
iptables -L -v
