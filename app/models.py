from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class Timeframe(BaseModel):
    hours: int = Field(ge=1, le=48, default=1)

class VulnerabilityFinding(BaseModel):
    name: str
    severity: str
    description: Optional[str] = None
    uri: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    cvss_score: Optional[float] = None
    # NVD enriched fields
    cve_id: Optional[str] = None
    nvd_description: Optional[str] = None
    nvd_cvss_v3_score: Optional[float] = None
    nvd_cvss_v3_vector: Optional[str] = None
    nvd_cvss_v2_score: Optional[float] = None
    nvd_cvss_v2_vector: Optional[str] = None
    nvd_published_date: Optional[str] = None
    nvd_last_modified: Optional[str] = None
    nvd_vendor_comments: Optional[str] = None
    nvd_references: Optional[list] = None

class VulnerabilityInput(BaseModel):
    name: str
    severity: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None

class SuggestionResponse(BaseModel):
    suggestion: str

class LogEntry(BaseModel):
    timestamp: datetime
    message: str
    log_stream: Optional[str] = None
    log_group: Optional[str] = None

class ExceptionsResponse(BaseModel):
    count: int
    exceptions: List[LogEntry]
    summary: Optional[str] = None

class NLQueryRequest(BaseModel):
    query: str
    timeframe: Timeframe = Field(default_factory=Timeframe)

class NLQueryResponse(BaseModel):
    answer: str
    used_logs: int
