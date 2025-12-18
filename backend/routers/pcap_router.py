from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import uuid
import os

from services.pcap_parser import PCAPParser

router = APIRouter()

UPLOAD_DIR = Path("uploads")


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
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
        return {
            "file_id": file_id,
            "filename": file.filename,
            "size": len(content),
            "info": basic_info,
        }
    except Exception as e:
        # 清理文件
        os.remove(save_path)
        raise HTTPException(status_code=500, detail=f"PCAP解析失败: {str(e)}")


@router.get("/list")
async def list_pcap_files():
    """列出所有已上传的PCAP文件"""
    files = []
    for file_path in UPLOAD_DIR.glob("*"):
        if file_path.suffix in [".pcap", ".pcapng", ".cap"]:
            files.append(
                {
                    "file_id": file_path.stem,
                    "filename": file_path.name,
                    "size": file_path.stat().st_size,
                }
            )
    return {"files": files}


@router.get("/{file_id}/info")
async def get_pcap_info(file_id: str):
    """获取PCAP文件详细信息"""
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
        return info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"解析失败: {str(e)}")


@router.delete("/{file_id}")
async def delete_pcap(file_id: str):
    """删除PCAP文件"""
    deleted = False
    for ext in [".pcap", ".pcapng", ".cap"]:
        file_path = UPLOAD_DIR / f"{file_id}{ext}"
        if file_path.exists():
            os.remove(file_path)
            deleted = True
            break

    if not deleted:
        raise HTTPException(status_code=404, detail="文件不存在")

    return {"message": "文件已删除", "file_id": file_id}
