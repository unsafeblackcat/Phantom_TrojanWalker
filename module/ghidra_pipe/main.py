"""
Ghidra Pipe FastAPI Service

Provides HTTP endpoints for binary analysis using Ghidra/pyghidra.
API is compatible with the previous rz_pipe service for seamless migration.
"""
import os
import uuid
import threading
import logging
import hashlib
from typing import List

from fastapi import FastAPI, UploadFile, File, HTTPException
from analyzer import GhidraAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Ghidra Pipe Service", version="1.0.0")

# Global analyzer state (single instance, similar to previous rz_pipe design)
analyzer = None
analyzer_lock = threading.RLock()

# Upload directory setup
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(ROOT_DIR, "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _safe_tmp_upload_path() -> str:
    """Create a temp upload path guarded against path traversal."""
    tmp_name = f".tmp_{uuid.uuid4().hex}"
    tmp_path = os.path.normpath(os.path.join(UPLOAD_DIR, tmp_name))
    if os.path.commonpath([UPLOAD_DIR, tmp_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    return tmp_path


def _resolve_final_upload_path(sha256: str) -> str:
    """Resolve final upload path by sha256 with path traversal guard."""
    file_path = os.path.normpath(os.path.join(UPLOAD_DIR, sha256))
    if os.path.commonpath([UPLOAD_DIR, file_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid filename")
    return file_path


def _remove_file_quietly(path: str) -> None:
    """Best-effort file deletion to avoid masking primary errors."""
    try:
        os.remove(path)
    except OSError:
        pass


async def _stream_to_temp_file(file: UploadFile, tmp_path: str) -> str:
    """Stream upload to temp file while computing sha256."""
    hasher = hashlib.sha256()
    with open(tmp_path, "wb") as out_file:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            out_file.write(chunk)
    return hasher.hexdigest()


def _persist_upload(tmp_path: str, sha256: str) -> str:
    """Move temp file into final path, handling collisions safely."""
    file_path = _resolve_final_upload_path(sha256)
    try:
        if os.path.exists(file_path):
            _remove_file_quietly(tmp_path)
        else:
            os.replace(tmp_path, file_path)
    except OSError as e:
        _remove_file_quietly(tmp_path)
        raise HTTPException(status_code=500, detail=f"Failed to store upload: {e}")
    return file_path


def require_analyzer() -> GhidraAnalyzer:
    """Get the current analyzer or raise 409 if not initialized."""
    global analyzer
    if analyzer is None:
        raise HTTPException(status_code=409, detail="No binary uploaded. POST /upload first.")
    return analyzer


def _close_analyzer() -> None:
    """Close the current analyzer and clear global state."""
    global analyzer
    if analyzer is None:
        return
    try:
        analyzer.close()
    finally:
        analyzer = None


@app.get("/health_check")
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """
    Upload a binary file for analysis.
    This will close any previously opened analyzer and open the new file.
    """
    global analyzer
    
    tmp_path = _safe_tmp_upload_path()
    sha256 = await _stream_to_temp_file(file, tmp_path)
    path = _persist_upload(tmp_path, sha256)
    
    with analyzer_lock:
        # Close existing analyzer if any
        try:
            _close_analyzer()
        except Exception as e:
            logger.warning(f"Error closing previous analyzer: {e}")
        
        # Create new analyzer and open the file
        analyzer = GhidraAnalyzer(path)
        if not analyzer.open():
            analyzer = None
            raise HTTPException(500, "Ghidra open failed")
    
    return {"status": "ok"}


@app.post("/close")
def close_analyzer():
    """Explicitly release Ghidra resources for the current binary."""
    with analyzer_lock:
        _close_analyzer()
    return {"status": "closed"}


@app.get("/analyze")
def do_analyze(level: str = "full"):
    """
    Trigger analysis on the uploaded binary.
    The 'level' parameter is kept for API compatibility.
    """
    with analyzer_lock:
        return require_analyzer().analyze(level)


@app.get("/metadata")
def get_meta():
    """Get binary metadata/info."""
    with analyzer_lock:
        return require_analyzer().get_info()


@app.get("/functions")
def get_funcs():
    """Get list of functions in the binary."""
    with analyzer_lock:
        return require_analyzer().get_functions()


@app.get("/strings")
def get_strs():
    """Get strings from the binary."""
    with analyzer_lock:
        return require_analyzer().get_strings()


@app.get("/decompile")
def decompile(addr: str):
    """Decompile a single function by address or name."""
    with analyzer_lock:
        result = require_analyzer().get_decompiled_code(addr)
        if result is None:
            raise HTTPException(404, f"Function not found or decompilation failed: {addr}")
        return result


@app.get("/callgraph")
def get_callgraph():
    """Get global call graph."""
    with analyzer_lock:
        return require_analyzer().get_global_call_graph()


@app.post("/decompile_batch")
def decompile_batch(addresses: List[str]):
    """
    Batch decompile multiple functions.
    Request body: JSON array of function names or addresses.
    Returns: list of {address, code} objects.
    """
    with analyzer_lock:
        return require_analyzer().get_decompiled_code_batch(addresses)


@app.get("/xrefs")
def get_xrefs(addr: str):
    """
    Get cross-references for a single function by address or name.
    Returns: {name, offset, callers, callees}.
    """
    with analyzer_lock:
        result = require_analyzer().get_function_xrefs(addr)
        if result is None:
            raise HTTPException(404, f"Function not found: {addr}")
        return result


@app.post("/xrefs_batch")
def get_xrefs_batch(addresses: List[str]):
    """
    Batch get cross-references for multiple functions.
    Request body: JSON array of function names or addresses.
    Returns: list of {name, offset, callers, callees} objects.
    """
    with analyzer_lock:
        return require_analyzer().get_function_xrefs_batch(addresses)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
