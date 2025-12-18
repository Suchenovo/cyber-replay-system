from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import Optional

from services.traffic_analyzer import TrafficAnalyzer

router = APIRouter()

UPLOAD_DIR = Path("uploads")


class AnalysisRequest(BaseModel):
    file_id: str
    analysis_type: str = "full"  # full, attack_path, protocol, flow


@router.post("/analyze")
async def analyze_traffic(request: AnalysisRequest):
    """分析流量数据"""
    # 查找文件
    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{request.file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="PCAP文件不存在")

    analyzer = TrafficAnalyzer(str(file_path))

    try:
        if request.analysis_type == "full":
            result = analyzer.full_analysis()
        elif request.analysis_type == "attack_path":
            result = analyzer.analyze_attack_path()
        elif request.analysis_type == "protocol":
            result = analyzer.analyze_protocols()
        elif request.analysis_type == "flow":
            result = analyzer.analyze_flows()
        else:
            raise HTTPException(status_code=400, detail="不支持的分析类型")

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")


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
