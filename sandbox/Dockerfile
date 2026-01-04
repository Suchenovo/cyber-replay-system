FROM ubuntu:22.04

# [新增] 设置环境变量，禁止安装过程中的交互式弹窗
ENV DEBIAN_FRONTEND=noninteractive

# 安装必要工具
# [新增] echo 语句是为了预先回答 wireshark 的特定问题（虽然 noninteractive 通常够用了，加这个更保险）
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    apt-get update && apt-get install -y \
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
