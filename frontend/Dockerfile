# [Stage 1: Builder]
FROM node:18-alpine as builder

WORKDIR /app

# 1. 修复：同时拷贝 lock 文件，锁定依赖版本
COPY package.json package-lock.json ./

# 2. 修复：使用 npm ci 代替 npm install
# npm ci 会删除 node_modules 并严格按照 package-lock.json 安装
RUN npm ci

# 3. 拷贝源代码 (配合 .dockerignore 使用)
COPY . .

# 内存优化配置 (保留你原有的)
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN npm run build

# [Stage 2: Production]
FROM nginx:alpine

# 4. 安全建议：生产环境建议替换默认的 nginx 配置
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]