from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Form
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session
from sqlalchemy import desc
import hashlib
import os
import uuid
import aiofiles

from backend.database import get_db
from backend.models.task import AnalysisTask
from backend.worker.worker import worker

router = APIRouter()

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(ROOT_DIR, "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_UPLOAD_BYTES = int(os.getenv("PTW_MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))  # 200MB default

def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

@router.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    sha256: str | None = Form(None),
    db: Session = Depends(get_db),
):
    # Validate optional client-provided sha256, but always compute server-side.
    client_sha256 = None
    if sha256 is not None:
        sha256 = sha256.strip().lower()
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise HTTPException(status_code=400, detail="Invalid sha256 format")
        client_sha256 = sha256

    # Stream upload: write temp file + compute sha256 incrementally.
    tmp_name = f".tmp_{uuid.uuid4().hex}"
    tmp_path = os.path.normpath(os.path.join(UPLOAD_DIR, tmp_name))
    if os.path.commonpath([UPLOAD_DIR, tmp_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid upload path")

    hasher = hashlib.sha256()
    total = 0
    async with aiofiles.open(tmp_path, "wb") as out_file:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                try:
                    await out_file.close()
                finally:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                raise HTTPException(status_code=413, detail="File too large")
            hasher.update(chunk)
            await out_file.write(chunk)

    sha256 = hasher.hexdigest()
    if client_sha256 and client_sha256 != sha256:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=400, detail="sha256 mismatch")

    # Check if exists (any active or completed task)
    existing_task = db.query(AnalysisTask).filter(
        AnalysisTask.sha256 == sha256,
        AnalysisTask.status.in_(["completed", "pending", "processing"])
    ).first()

    if existing_task:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return {
            "task_id": existing_task.task_id,
            "status": existing_task.status,
            "message": f"Analysis already {existing_task.status}.",
            "sha256": sha256,
        }

    # Save file by sha256 (stable + safe filename)
    final_name = sha256
    file_path = os.path.normpath(os.path.join(UPLOAD_DIR, final_name))
    if os.path.commonpath([UPLOAD_DIR, file_path]) != UPLOAD_DIR:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=400, detail="Invalid filename")

    try:
        if os.path.exists(file_path):
            os.remove(tmp_path)
        else:
            os.replace(tmp_path, file_path)
    except OSError as e:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to store upload: {e}")
        
    # Create Task
    task_uuid = str(uuid.uuid4())
    new_task = AnalysisTask(
        task_id=task_uuid,
        sha256=sha256,
        filename=file.filename,
        file_path=file_path,
        status="pending"
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    
    # Enqueue
    worker.add_task(new_task.id)
    
    return {
        "task_id": task_uuid,
        "status": "pending",
        "message": "Analysis queued.",
        "sha256": sha256
    }

@router.get("/tasks/{task_id}")
def get_task_status(task_id: str, db: Session = Depends(get_db)):
    task = db.query(AnalysisTask).filter(AnalysisTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return {
        "task_id": task.task_id,
        "status": task.status,
        "sha256": task.sha256,
        "filename": task.filename,
        "metadata": task.metadata_info,
        "functions": task.functions,
        "strings": task.strings,
        "decompiled_code": task.decompiled_code,
        "function_analyses": task.function_analyses,
        "malware_report": task.malware_report,
        "error": task.error_message,
        "created_at": task.created_at,
        "finished_at": task.finished_at
    }

@router.get("/result/{sha256}")
def get_result_by_hash(sha256: str, db: Session = Depends(get_db)):
    task = db.query(AnalysisTask).filter(AnalysisTask.sha256 == sha256).order_by(desc(AnalysisTask.created_at)).first()
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return {
        "task_id": task.task_id,
        "status": task.status,
        "sha256": task.sha256,
        "filename": task.filename,
        "metadata": task.metadata_info,
        "functions": task.functions,
        "strings": task.strings,
        "decompiled_code": task.decompiled_code,
        "function_analyses": task.function_analyses,
        "malware_report": task.malware_report,
        "error": task.error_message,
    }

@router.get("/history")
def get_recent_history(limit: int = 10, db: Session = Depends(get_db)):
    tasks = db.query(AnalysisTask).order_by(desc(AnalysisTask.created_at)).limit(limit).all()
    # Return a JSON-serializable summary (avoid leaking internal fields/paths).
    payload = [
        {
            "task_id": t.task_id,
            "status": t.status,
            "sha256": t.sha256,
            "filename": t.filename,
            "created_at": t.created_at,
            "finished_at": t.finished_at,
            "error": t.error_message,
        }
        for t in tasks
    ]
    return jsonable_encoder(payload)
