import os, shutil, uuid, re
from typing import List
from fastapi import FastAPI, UploadFile, File, HTTPException
from analyzer import RizinAnalyzer

app = FastAPI()
analyzer = None
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(ROOT_DIR, "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/health_check")
def health_check(): return {"status": "ok"}

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    global analyzer

    original_name = file.filename or ""
    base_name = os.path.basename(original_name)
    if not base_name:
        base_name = "upload"
    # Keep a conservative filename charset to avoid filesystem/path issues.
    base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", base_name)
    safe_name = f"{uuid.uuid4().hex}_{base_name}"
    path = os.path.join(UPLOAD_DIR, safe_name)
    
    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)
        
    if analyzer:
        analyzer.close()
    
    analyzer = RizinAnalyzer(path)
    if not analyzer.open():
        raise HTTPException(500, "Rizin open failed")
        
    return {"status": "ok", "path": path}

@app.get("/analyze")
def do_analyze(level: str = "aaa"): return analyzer.analyze(level)

@app.get("/metadata")
def get_meta(): return analyzer.get_info()

@app.get("/functions")
def get_funcs(): return analyzer.get_functions()

@app.get("/strings")
def get_strs(): return analyzer.get_strings()

@app.get("/decompile")
def decompile(addr: str): return analyzer.get_decompiled_code(addr)

@app.get("/callgraph")
def get_callgraph(): return analyzer.get_global_call_graph()

@app.post("/decompile_batch")
def decompile_batch(addresses: List[str]):
    return analyzer.get_decompiled_code_batch(addresses)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
