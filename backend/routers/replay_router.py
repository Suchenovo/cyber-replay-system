from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import Optional

from services.traffic_replayer import TrafficReplayer

router = APIRouter()

UPLOAD_DIR = Path("uploads")


class ReplayRequest(BaseModel):
    file_id: str
    target_ip: Optional[str] = None
    speed_multiplier: float = 1.0
    use_sandbox: bool = True


class ReplayStatusRequest(BaseModel):
    task_id: str


@router.post("/start")
async def start_replay(request: ReplayRequest):
    """启动流量重放"""
    # 查找文件
    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{request.file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    # 创建重放器
    replayer = TrafficReplayer(str(file_path))

    try:
        task_id = replayer.start_replay(
            target_ip=request.target_ip,
            speed_multiplier=request.speed_multiplier,
            use_sandbox=request.use_sandbox,
        )

        return {"task_id": task_id, "status": "started", "message": "流量重放已启动"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"重放失败: {str(e)}")


@router.post("/status")
async def get_replay_status(request: ReplayStatusRequest):
    """获取重放任务状态"""
    replayer = TrafficReplayer()

    try:
        status = replayer.get_status(request.task_id)
        return status
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"任务不存在: {str(e)}")


@router.post("/stop")
async def stop_replay(request: ReplayStatusRequest):
    """停止流量重放"""
    replayer = TrafficReplayer()

    try:
        result = replayer.stop_replay(request.task_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"停止失败: {str(e)}")


@router.get("/tasks")
async def list_replay_tasks():
    """列出所有重放任务"""
    replayer = TrafficReplayer()
    tasks = replayer.list_tasks()
    return {"tasks": tasks}


@router.delete("/{task_id}")
async def delete_replay_task(task_id: str):
    """删除重放任务"""
    replayer = TrafficReplayer()
    result = replayer.delete_task(task_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result
