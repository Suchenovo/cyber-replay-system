from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from pathlib import Path
import shutil
import os
import uuid
import time
import json
import redis
import logging

# 业务逻辑引用
from services.traffic_analyzer import TrafficAnalyzer

# 如果你需要保留原有数据库记录逻辑（可选），可以保留下面两行，否则可以忽略
# from database import get_db
# from models import AnalysisSnapshot

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
UPLOAD_DIR = Path("uploads")

# --- Redis 配置 ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
except Exception as e:
    logger.error(f"Redis init failed: {e}")
    redis_client = None

# --- Redis 辅助函数 ---
def save_analysis_task(task_id, data):
    """将任务状态写入 Redis"""
    if redis_client:
        redis_client.set(f"analysis_task:{task_id}", json.dumps(data))

def get_analysis_task(task_id):
    """从 Redis 读取任务状态"""
    if redis_client:
        data = redis_client.get(f"analysis_task:{task_id}")
        return json.loads(data) if data else None
    return None

# --- 后台任务逻辑 ---
def _run_analysis_task(task_id: str, file_path: str):
    """
    后台执行流量分析
    """
    try:
        # 1. 获取并更新状态：分析中
        task = get_analysis_task(task_id)
        if not task: return
        
        task["status"] = "analyzing"
        save_analysis_task(task_id, task)

        # 2. 执行全量分析 (耗时操作)
        # 注意：TrafficAnalyzer 已经优化为流式读取，但全量分析仍需遍历文件
        analyzer = TrafficAnalyzer(file_path)
        result = analyzer.full_analysis()

        # 3. 更新状态：完成
        task["status"] = "completed"
        task["result"] = result
        task["end_time"] = time.time()
        save_analysis_task(task_id, task)

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        task = get_analysis_task(task_id) or {}
        task["status"] = "failed"
        task["error"] = str(e)
        save_analysis_task(task_id, task)

# --- 路由接口 ---

@router.post("/analyze")
async def analyze_traffic(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    提交分析任务 (异步 + Redis持久化)
    """
    task_id = str(uuid.uuid4())
    
    # 确保上传目录存在
    if not UPLOAD_DIR.exists():
        UPLOAD_DIR.mkdir(parents=True)

    # 保存文件
    # 使用 file_id 或 task_id 作为文件名前缀均可，这里为了兼容旧逻辑，
    # 我们尽量保留原文件名，但建议重命名以防冲突
    file_location = UPLOAD_DIR / f"{task_id}_{file.filename}"
    
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 初始化任务状态到 Redis
    task_info = {
        "task_id": task_id,
        "filename": file.filename,
        "status": "pending",
        "submit_time": time.time(),
        "file_path": str(file_location)
    }
    save_analysis_task(task_id, task_info)

    # 启动后台任务
    background_tasks.add_task(_run_analysis_task, task_id, str(file_location))

    return {"task_id": task_id, "message": "Analysis started"}


@router.get("/status/{task_id}")
async def get_status(task_id: str):
    """
    查询任务状态 (从 Redis)
    """
    task = get_analysis_task(task_id)
    if not task:
        # 如果 Redis 里没有，可能是过期的任务或者 task_id 错误
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task


# --- 以下是补全的兼容接口 (Synchronous Helpers) ---
# 这些接口根据 file_id 直接读取文件进行计算，主要用于旧的前端组件
# 注意：这部分效率较低，因为每次调用都会重新解析文件

def _find_file_by_id(file_id: str) -> Path:
    """辅助函数：根据 file_id 查找文件"""
    # 这里的 file_id 在新逻辑中可能对应 task_id，或者原始文件名
    # 我们尝试模糊匹配：目录下包含 file_id 的文件
    if not UPLOAD_DIR.exists():
        return None
        
    for file_path in UPLOAD_DIR.iterdir():
        if file_id in file_path.name:
            return file_path
    return None

@router.get("/{file_id}/attack-path")
async def get_attack_path(file_id: str):
    """[兼容接口] 获取攻击路径图"""
    file_path = _find_file_by_id(file_id)
    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    try:
        analyzer = TrafficAnalyzer(str(file_path))
        return analyzer.get_attack_path_graph()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{file_id}/statistics")
async def get_statistics(file_id: str):
    """[兼容接口] 获取统计信息"""
    file_path = _find_file_by_id(file_id)
    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    try:
        analyzer = TrafficAnalyzer(str(file_path))
        return analyzer.get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{file_id}/timeline")
async def get_timeline(file_id: str):
    """[兼容接口] 获取时间线"""
    file_path = _find_file_by_id(file_id)
    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    try:
        analyzer = TrafficAnalyzer(str(file_path))
        return analyzer.get_timeline_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))