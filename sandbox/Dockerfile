FROM ubuntu:22.04

# 安装必要工具
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    wireshark-common \
    iptables \
    iproute2 \
    net-tools \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 安装Python包
RUN pip3 install scapy

# 创建工作目录
WORKDIR /sandbox

# 配置网络隔离规则
COPY setup-network.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup-network.sh

# 启动脚本
CMD ["/bin/bash", "-c", "/usr/local/bin/setup-network.sh && tail -f /dev/null"]
