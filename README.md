# 网络攻击复现与分析系统

基于流量重放的网络攻击复现与分析系统，支持PCAP文件上传、流量分析和沙箱重放功能。

## 功能特性

- 📦 **PCAP文件上传**: 支持.pcap、.pcapng等格式的流量包文件
- 🔍 **流量分析**: 深度分析网络流量，识别攻击特征和异常行为
- 🎨 **可视化展示**: 使用ECharts展示攻击路径、协议分布、流量时间线
- 🔄 **流量重放**: 在隔离的沙箱环境中安全重放网络流量
- 🛡️ **安全隔离**: Docker容器化部署，网络完全隔离

## 技术栈

### 后端
- **FastAPI**: 高性能Python Web框架
- **Scapy**: 强大的数据包操作库
- **Pandas**: 数据分析工具
- **Docker**: 容器化和沙箱隔离

### 前端
- **Vue 3**: 现代化前端框架
- **Element Plus**: UI组件库
- **ECharts**: 数据可视化图表库
- **Axios**: HTTP客户端

## 项目结构

```
cyber-replay-system/
├── backend/                 # 后端服务
│   ├── main.py             # FastAPI应用主文件
│   ├── routers/            # API路由
│   │   ├── pcap_router.py      # PCAP文件管理
│   │   ├── replay_router.py    # 流量重放
│   │   └── analysis_router.py  # 流量分析
│   ├── services/           # 业务逻辑
│   │   ├── pcap_parser.py      # PCAP解析
│   │   ├── traffic_replayer.py # 流量重放器
│   │   └── traffic_analyzer.py # 流量分析器
│   ├── requirements.txt    # Python依赖
│   └── Dockerfile         # 后端Docker镜像
├── frontend/              # 前端应用
│   ├── src/
│   │   ├── views/         # 页面组件
│   │   │   ├── Home.vue       # 首页
│   │   │   ├── Upload.vue     # 上传页面
│   │   │   ├── Analysis.vue   # 分析页面
│   │   │   └── Replay.vue     # 重放页面
│   │   ├── api/           # API接口
│   │   ├── router/        # 路由配置
│   │   └── App.vue        # 根组件
│   ├── package.json       # Node依赖
│   └── Dockerfile         # 前端Docker镜像
├── sandbox/               # 沙箱环境
│   ├── Dockerfile         # 沙箱Docker镜像
│   └── setup-network.sh   # 网络隔离脚本
└── docker-compose.yaml    # Docker编排配置
```

## 快速开始

### 前提条件

- Docker >= 20.10
- Docker Compose >= 2.0

### 启动系统

1. 克隆项目（如果适用）
```bash
cd cyber-replay-system
```

2. 使用Docker Compose启动所有服务
```bash
docker-compose up -d
```

3. 等待服务启动完成后，访问：
   - 前端界面: http://localhost:3000
   - 后端API文档: http://localhost:8000/docs

### 停止系统

```bash
docker-compose down
```

### 查看日志

```bash
# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f sandbox
```

## 本地开发

### 后端开发

```bash
cd backend

# 安装依赖
pip install -r requirements.txt

# 启动开发服务器
python main.py
```

后端将运行在 http://localhost:8000

### 前端开发

```bash
cd frontend

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

前端将运行在 http://localhost:3000

## API文档

启动后端服务后，访问以下地址查看完整API文档：
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 主要功能说明

### 1. PCAP文件上传
- 支持拖拽上传或点击选择
- 自动解析文件基本信息
- 文件大小限制: 500MB

### 2. 流量分析
- **协议分布**: 饼图展示各协议占比
- **攻击路径**: 力导向图展示主机间通信关系
- **流量时间线**: 折线图展示流量随时间的变化
- **Top会话**: 表格展示流量最大的会话

### 3. 流量重放
- 支持自定义目标IP
- 可调节重放速度（0.1x - 10x）
- 沙箱环境隔离，确保安全
- 实时显示重放进度

### 4. 沙箱隔离
- Docker容器完全隔离
- 内部网络（172.20.0.0/16）
- iptables规则限制外部通信
- 防止重放流量影响生产环境

## 注意事项

1. **权限要求**: 沙箱容器需要 NET_ADMIN 和 NET_RAW 权限用于流量操作
2. **资源占用**: 大型PCAP文件可能占用较多内存，建议系统内存≥4GB
3. **安全警告**: 流量重放功能仅用于研究和测试，请在隔离环境中使用
4. **文件存储**: 上传的PCAP文件存储在 `backend/uploads` 目录

## 故障排除

### 容器启动失败
```bash
# 检查Docker服务状态
docker ps -a

# 查看详细日志
docker-compose logs
```

### 前端无法连接后端
- 检查后端服务是否正常运行
- 确认端口8000未被占用
- 查看浏览器控制台错误信息

### PCAP上传失败
- 确认文件格式正确（.pcap, .pcapng, .cap）
- 检查文件大小是否超过限制
- 确认 `backend/uploads` 目录权限正常

## 许可证

本项目仅供学习和研究使用。

## 贡献

欢迎提交Issue和Pull Request。
