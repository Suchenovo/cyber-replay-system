# 快速启动指南

## 方式一：使用Docker Compose（推荐）

### 启动所有服务
```bash
docker-compose up -d
```

### 查看服务状态
```bash
docker-compose ps
```

### 查看日志
```bash
docker-compose logs -f
```

### 停止服务
```bash
docker-compose down
```

---

## 方式二：本地开发模式

### 启动后端

1. 进入后端目录
```bash
cd backend
```

2. 创建虚拟环境（可选）
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 启动服务
```bash
python main.py
```

后端将运行在: http://localhost:8000

### 启动前端

1. 打开新终端，进入前端目录
```bash
cd frontend
```

2. 安装依赖
```bash
npm install
```

3. 启动开发服务器
```bash
npm run dev
```

前端将运行在: http://localhost:3000

---

## 访问地址

- **前端界面**: http://localhost:3000
- **后端API文档**: http://localhost:8000/docs
- **API ReDoc**: http://localhost:8000/redoc

---

## 首次使用步骤

1. 打开浏览器访问 http://localhost:3000
2. 点击"上传PCAP"菜单
3. 拖拽或选择一个PCAP文件上传
4. 上传成功后，点击"分析"按钮查看流量分析
5. 在"流量分析"页面可以看到：
   - 攻击路径可视化图
   - 协议分布饼图
   - 流量时间线
   - Top流量会话
6. 在"流量重放"页面可以启动流量重放任务

---

## 测试PCAP文件获取

如果没有现成的PCAP文件，可以：

1. 使用Wireshark捕获本地流量
2. 使用tcpdump命令：
   ```bash
   sudo tcpdump -i eth0 -w test.pcap
   ```
3. 下载示例PCAP文件：
   - https://wiki.wireshark.org/SampleCaptures
   - https://www.netresec.com/?page=PcapFiles

---

## 常见问题

### Q: Docker容器启动失败？
A: 检查端口是否被占用（3000, 8000），确保Docker服务正常运行

### Q: 前端无法连接后端？
A: 确认后端服务已启动，检查 http://localhost:8000/health

### Q: PCAP文件上传失败？
A: 确认文件格式正确，大小不超过500MB

### Q: 在Windows上使用沙箱功能？
A: 需要Docker Desktop并启用WSL2后端
