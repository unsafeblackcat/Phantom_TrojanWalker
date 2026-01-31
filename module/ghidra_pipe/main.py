"""
Ghidra Pipe FastAPI Service

Provides HTTP endpoints for binary analysis using Ghidra/pyghidra.
API is compatible with the previous rz_pipe service for seamless migration.
"""
import os
import shutil
import uuid
import re
import threading
import logging
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


def require_analyzer() -> GhidraAnalyzer:
    """Get the current analyzer or raise 409 if not initialized."""
    global analyzer
    if analyzer is None:
        raise HTTPException(status_code=409, detail="No binary uploaded. POST /upload first.")
    return analyzer


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
    
    original_name = file.filename or ""
    base_name = os.path.basename(original_name)
    if not base_name:
        base_name = "upload"
    
    # Keep a conservative filename charset
    base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", base_name)
    safe_name = f"{uuid.uuid4().hex}_{base_name}"
    path = os.path.join(UPLOAD_DIR, safe_name)
    
    # Save uploaded file
    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    
    with analyzer_lock:
        # Close existing analyzer if any
        if analyzer:
            try:
                analyzer.close()
            except Exception as e:
                logger.warning(f"Error closing previous analyzer: {e}")
        
        # Create new analyzer and open the file
        analyzer = GhidraAnalyzer(path)
        if not analyzer.open():
            analyzer = None
            raise HTTPException(500, "Ghidra open failed")
    
    return {"status": "ok"}


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
