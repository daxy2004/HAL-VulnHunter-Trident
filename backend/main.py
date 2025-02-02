from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.scanner import WebScanner
from backend.schemas import ScanRequest, ScanResponse, ScanStatus
import uuid
from typing import Dict
import logging  # Added for error logging

app = FastAPI()

# Configure CORS - Add your frontend port here
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],  # Add actual frontend ports
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store scan results in memory
scan_results: Dict[str, Dict] = {}

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {"status": "pending", "results": None}
    
    logger.info(f"Starting new scan with ID: {scan_id}")  # Added logging
    background_tasks.add_task(run_scan, scan_id, scan_request.url, 
                            scan_request.max_pages, scan_request.threads)
    
    return {"scan_id": scan_id, "status": "pending"}

@app.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    if scan_id not in scan_results:
        logger.warning(f"Scan ID not found: {scan_id}")  # Added logging
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results[scan_id]

def run_scan(scan_id: str, url: str, max_pages: int, threads: int):
    try:
        logger.info(f"Starting scan for {url} (ID: {scan_id})")
        scanner = WebScanner(url, max_pages, threads)
        scanner.scan()
        
        # Convert objects to dictionaries safely
        scan_results[scan_id] = {
            "status": "completed",
            "results": {
                "vulnerabilities": [v.__dict__ for v in scanner.vulnerabilities],
                "subdomains": [s.__dict__ for s in scanner.subdomains],
                "forms_found": len(scanner.forms),
                "pages_scanned": len(scanner.visited_urls)
            }
        }
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan failed {scan_id}: {str(e)}", exc_info=True)
        scan_results[scan_id] = {
            "status": "failed",
            "error": str(e)
        }