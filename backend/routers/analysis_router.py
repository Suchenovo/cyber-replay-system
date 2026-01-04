from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel
from pathlib import Path
import os
import uuid
import time
import json
import redis
import logging

# 业务逻辑引用
from services.traffic_analyzer import TrafficAnalyzer

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

# --- 定义请求模型 (关键修复：恢复对 JSON Body 的支持) ---
class AnalysisRequest(BaseModel):
    file_id: str
    analysis_type: str = "full"

# --- 后台任务逻辑 ---
def _run_analysis_task(task_id: str, file_path: str, analysis_type: str):
    """
    后台执行流量分析
    """
    try:
        # 1. 获取并更新状态：分析中
        task = get_analysis_task(task_id)
        if not task: return
        
        task["status"] = "analyzing"
        save_analysis_task(task_id, task)

        # 2. 执行分析
        # 注意：TrafficAnalyzer 已经优化为流式读取
        analyzer = TrafficAnalyzer(file_path)
        
        result = None
        if analysis_type == "full":
            result = analyzer.full_analysis()
        elif analysis_type == "attack_path":
            result = analyzer.get_attack_path_graph() # 适配 analyzer 的新旧方法名
        elif analysis_type == "protocol":
            result = analyzer.analyze_protocols()
        elif analysis_type == "flow":
            result = analyzer.analyze_flows()
        else:
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
async def analyze_traffic(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    提交分析任务 (接收 file_id，异步处理)
    """
    # 1. 根据 file_id 查找文件
    # 前端上传时可能保存为 {file_id}.pcap 或 {file_id}.pcapng
    file_path = None
    if UPLOAD_DIR.exists():
        # 尝试直接匹配 ID
        for ext in [".pcap", ".pcapng", ".cap"]:
            possible_path = UPLOAD_DIR / f"{request.file_id}{ext}"
            if possible_path.exists():
                file_path = possible_path
                break
        
        # 如果找不到，尝试模糊匹配 (防止上传时加了前缀)
        if not file_path:
            for f in UPLOAD_DIR.iterdir():
                if request.file_id in f.name:
                    file_path = f
                    break

    if not file_path:
        raise HTTPException(status_code=404, detail=f"PCAP file not found for ID: {request.file_id}")

    # 2. 生成任务 ID
    task_id = str(uuid.uuid4())
    
    # 3. 初始化任务状态到 Redis
    task_info = {
        "task_id": task_id,
        "file_id": request.file_id,
        "status": "pending",
        "submit_time": time.time(),
        "file_path": str(file_path)
    }
    save_analysis_task(task_id, task_info)

    # 4. 启动后台任务
    background_tasks.add_task(_run_analysis_task, task_id, str(file_path), request.analysis_type)

    # 5. 返回 task_id 给前端
    return {"task_id": task_id, "status": "pending", "message": "Analysis started"}


@router.get("/status/{task_id}")
async def get_status(task_id: str):
    """
    查询任务状态 (从 Redis)
    """
    task = get_analysis_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task


# --- 兼容接口 ---

def _find_file_by_id(file_id: str) -> Path:
    if not UPLOAD_DIR.exists(): return None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{file_id}{ext}"
        if path.exists(): return path
    for f in UPLOAD_DIR.iterdir():
        if file_id in f.name: return f
    return None

@router.get("/{file_id}/attack-path")
async def get_attack_path(file_id: str):
    file_path = _find_file_by_id(file_id)
    if not file_path: raise HTTPException(status_code=404, detail="File not found")
    try:
        return TrafficAnalyzer(str(file_path)).get_attack_path_graph()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{file_id}/statistics")
async def get_statistics(file_id: str):
    file_path = _find_file_by_id(file_id)
    if not file_path: raise HTTPException(status_code=404, detail="File not found")
    try:
        return TrafficAnalyzer(str(file_path)).get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{file_id}/timeline")
async def get_timeline(file_id: str):
    file_path = _find_file_by_id(file_id)
    if not file_path: raise HTTPException(status_code=404, detail="File not found")
    try:
        return TrafficAnalyzer(str(file_path)).get_timeline_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))