from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session
import json
import uuid

# 引入你的业务逻辑
from services.traffic_analyzer import TrafficAnalyzer
from database import get_db
from models import AnalysisSnapshot

router = APIRouter()

UPLOAD_DIR = Path("uploads")

# --- 全局变量：暂存正在运行的任务状态 ---
# 注意：在生产环境中，这应该存放在 Redis 里，否则重启服务器任务状态会丢失
# 但对于演示/开发环境，用全局字典没问题
ANALYSIS_TASKS = {}

class AnalysisRequest(BaseModel):
    file_id: str
    analysis_type: str = "full"  # full, attack_path, protocol, flow

# --- 内部函数：后台实际执行任务的函数 ---
def _run_analysis_task(task_id: str, file_path: Path, analysis_type: str, db: Session):
    try:
        # 1. 执行耗时分析
        analyzer = TrafficAnalyzer(str(file_path))
        
        result = None
        if analysis_type == "full":
            result = analyzer.full_analysis()
        elif analysis_type == "attack_path":
            result = analyzer.analyze_attack_path()
        elif analysis_type == "protocol":
            result = analyzer.analyze_protocols()
        elif analysis_type == "flow":
            result = analyzer.analyze_flows()
        
        # 2. 存入数据库 (保留你原有的逻辑)
        # 注意：这里我们尝试使用传入的 db session
        # 在极长任务中，建议新建 session，但此处为了简化代码先复用
        try:
            snapshot = AnalysisSnapshot(
                file_id=str(file_path.stem), # 获取文件名（无后缀）即 file_id
                analysis_type=analysis_type,
                payload=json.dumps(result, ensure_ascii=False),
            )
            db.add(snapshot)
            db.commit()
        except Exception as e:
            print(f"数据库保存失败: {e}")
            db.rollback()

        # 3. 更新任务状态为完成
        ANALYSIS_TASKS[task_id]["status"] = "completed"
        ANALYSIS_TASKS[task_id]["result"] = result
        
    except Exception as e:
        # 4. 记录失败状态
        ANALYSIS_TASKS[task_id]["status"] = "failed"
        ANALYSIS_TASKS[task_id]["error"] = str(e)


@router.post("/analyze")
async def analyze_traffic(
    request: AnalysisRequest, 
    background_tasks: BackgroundTasks, # 注入 FastAPI 的后台任务管理器
    db: Session = Depends(get_db)
):
    """
    提交流量分析任务（异步模式）
    """
    # 1. 查找文件是否存在
    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{request.file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    # 2. 生成任务 ID
    task_id = str(uuid.uuid4())
    
    # 3. 初始化任务状态
    ANALYSIS_TASKS[task_id] = {
        "status": "running", 
        "file_id": request.file_id,
        "type": request.analysis_type
    }
    
    # 4. 将任务丢给后台执行
    # 注意：这里我们将 db 传进去。FastAPI 的 BackgroundTasks 会在响应发送后执行
    background_tasks.add_task(_run_analysis_task, task_id, file_path, request.analysis_type, db)
    
    # 5. 立刻返回 Task ID，不用等待分析完成
    return {"task_id": task_id, "status": "pending", "message": "分析任务已提交后台"}


@router.get("/status/{task_id}")
async def get_analysis_status(task_id: str):
    """
    前端轮询此接口获取任务状态
    """
    task = ANALYSIS_TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    # 如果任务失败，返回错误信息
    if task["status"] == "failed":
        return {"status": "failed", "error": task.get("error")}
        
    # 如果任务完成，返回结果
    if task["status"] == "completed":
        return {"status": "completed", "result": task.get("result")}
        
    # 否则返回运行中
    return {"status": "running"}


@router.get("/{file_id}/attack-path")
async def get_attack_path(file_id: str):
    """获取攻击路径图数据（用于ECharts可视化）"""
    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    analyzer = TrafficAnalyzer(str(file_path))

    try:
        attack_path = analyzer.get_attack_path_graph()
        return attack_path
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"生成攻击路径失败: {str(e)}")


@router.get("/{file_id}/statistics")
async def get_statistics(file_id: str):
    """获取流量统计信息"""
    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    analyzer = TrafficAnalyzer(str(file_path))

    try:
        stats = analyzer.get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"统计分析失败: {str(e)}")


@router.get("/{file_id}/timeline")
async def get_timeline(file_id: str):
    """获取流量时间线数据"""
    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    analyzer = TrafficAnalyzer(str(file_path))

    try:
        timeline = analyzer.get_timeline_data()
        return timeline
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"时间线生成失败: {str(e)}")
