import uuid
import shutil
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse

from services.runner import run_analysis
from services.parser import load_stats

app = FastAPI(title="Trinetra Platform")

JOBS_DIR = Path("jobs")
JOBS_DIR.mkdir(exist_ok=True)


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> JSONResponse:
    # Validate file type
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are accepted.")

    # Create unique job directory
    job_dir = JOBS_DIR / uuid.uuid4().hex
    job_dir.mkdir(parents=True)

    input_pcap = job_dir / "input.pcap"
    output_pcap = job_dir / "output.pcap"
    stats_json = job_dir / "stats.json"

    # Save uploaded file
    with input_pcap.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    # Run the C++ binary
    try:
        run_analysis(input_pcap, output_pcap, stats_json)
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Read and return stats
    try:
        result = load_stats(stats_json)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Binary ran but stats.json was not produced.")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return JSONResponse(content=result)
