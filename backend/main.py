from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from pathlib import Path
import os

from routers import pcap_router, replay_router, analysis_router
from database import Base, engine

app = FastAPI(title="网络攻击复现与分析系统", version="1.0.0")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 创建必要的目录
UPLOAD_DIR = Path("uploads")
RESULTS_DIR = Path("results")
UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# 初始化数据库表
Base.metadata.create_all(bind=engine)

# 注册路由
app.include_router(pcap_router.router, prefix="/api/pcap", tags=["PCAP管理"])
app.include_router(replay_router.router, prefix="/api/replay", tags=["流量重放"])
app.include_router(analysis_router.router, prefix="/api/analysis", tags=["数据分析"])


@app.get("/")
async def root():
    return {
        "message": "网络攻击复现与分析系统 API",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
