from pydantic import BaseModel
from typing import Optional, List, Dict

class ScanRequest(BaseModel):
    url: str
    max_pages: int = 10
    threads: int = 5

class ScanResponse(BaseModel):
    scan_id: str
    status: str

class ScanStatus(BaseModel):
    status: str
    results: Optional[Dict] = None
    error: Optional[str] = None