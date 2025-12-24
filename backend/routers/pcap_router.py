from fastapi import APIRouter, File, UploadFile, HTTPException, Depends
from fastapi.responses import JSONResponse
from pathlib import Path
import uuid
import os
import json
from datetime import datetime
from sqlalchemy.orm import Session

# 确保引入了 DB 相关依赖
from services.pcap_parser import PCAPParser
from database import get_db
from models import PcapFile

router = APIRouter()

UPLOAD_DIR = Path("uploads")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)  # 确保上传目录存在


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """上传PCAP文件"""
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="只支持PCAP格式文件")

    # 生成唯一文件ID
    file_id = str(uuid.uuid4())
    file_extension = Path(file.filename).suffix
    save_path = UPLOAD_DIR / f"{file_id}{file_extension}"

    # 保存文件
    try:
        content = await file.read()
        with open(save_path, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"文件保存失败: {str(e)}")

    # 解析基本信息
    parser = PCAPParser(str(save_path))
    try:
        basic_info = parser.get_basic_info()
        # 写入数据库
        db_obj = PcapFile(
            file_id=file_id,
            filename=file.filename,  # 存入原始文件名
            path=str(save_path),
            size=len(content),
            total_packets=basic_info.get("total_packets", 0),
            duration=basic_info.get("duration", 0.0),
        )
        db.add(db_obj)
        db.commit()
        return {
            "file_id": file_id,
            "filename": file.filename,
            "size": len(content),
            "info": basic_info,
        }
    except Exception as e:
        # 出错清理文件
        if save_path.exists():
            os.remove(save_path)
        raise HTTPException(status_code=500, detail=f"PCAP解析失败: {str(e)}")


@router.get("/list")
async def list_pcap_files(db: Session = Depends(get_db)):
    """
    列出所有已上传的PCAP文件
    (从数据库读取，以获取原始文件名和时间)
    """
    # 查询数据库所有记录
    records = db.query(PcapFile).all()

    files = []
    for row in records:
        # 获取文件上传时间 (如果没有数据库时间字段，则读取物理文件的修改时间)
        upload_time_str = "未知"
        if os.path.exists(row.path):
            timestamp = os.path.getmtime(row.path)
            upload_time_str = datetime.fromtimestamp(timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        files.append(
            {
                "file_id": row.file_id,
                "filename": row.filename,  # 这里返回的是数据库里存的原始文件名
                "size": row.size,
                "upload_time": upload_time_str,  # 新增的时间字段
            }
        )

    # 按时间倒序排列（最新的在最前）
    files.sort(key=lambda x: x["upload_time"], reverse=True)

    return {"files": files}


@router.get("/{file_id}/info")
async def get_pcap_info(file_id: str):
    """获取PCAP文件详细信息"""
    # 1. 尝试从缓存读取分析结果
    result_path = RESULTS_DIR / f"{file_id}.json"
    if result_path.exists():
        try:
            with open(result_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    file_path = None
    for ext in [".pcap", ".pcapng", ".cap"]:
        path = UPLOAD_DIR / f"{file_id}{ext}"
        if path.exists():
            file_path = path
            break

    if not file_path:
        raise HTTPException(status_code=404, detail="文件不存在")

    parser = PCAPParser(str(file_path))
    try:
        info = parser.get_detailed_info()

        # 2. 保存分析结果到文件
        try:
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(info, f, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Failed to save analysis result: {e}")

        return info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"解析失败: {str(e)}")


@router.delete("/{file_id}")
async def delete_pcap(file_id: str, db: Session = Depends(get_db)):
    """删除PCAP文件"""
    # 1. 删除物理文件
    deleted = False
    for ext in [".pcap", ".pcapng", ".cap"]:
        file_path = UPLOAD_DIR / f"{file_id}{ext}"
        if file_path.exists():
            os.remove(file_path)
            deleted = True
            break

    # 2. 删除缓存文件
    result_path = RESULTS_DIR / f"{file_id}.json"
    if result_path.exists():
        os.remove(result_path)

    # 3. 删除数据库记录 (可选，建议加上以保持数据一致性)
    db_record = db.query(PcapFile).filter(PcapFile.file_id == file_id).first()
    if db_record:
        db.delete(db_record)
        db.commit()

    if not deleted and not db_record:
        # 如果文件和数据库都没找到
        raise HTTPException(status_code=404, detail="文件不存在")

    return {"message": "文件已删除", "file_id": file_id}
