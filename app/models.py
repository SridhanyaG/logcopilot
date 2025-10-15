from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class Timeframe(BaseModel):
    hours: Optional[int] = Field(default=None, ge=0, le=48)
    minutes: Optional[int] = Field(default=None, ge=0, le=2880)  # Max 48 hours in minutes
    
    def get_total_minutes(self) -> int:
        """Convert timeframe to total minutes"""
        if self.minutes is not None:
            return self.minutes
        elif self.hours is not None:
            return self.hours * 60
        else:
            return 60  # Default to 1 hour
    
    def get_total_hours(self) -> float:
        """Convert timeframe to total hours (as float for precision)"""
        if self.minutes is not None:
            return self.minutes / 60.0
        elif self.hours is not None:
            return self.hours
        else:
            return 1.0  # Default to 1 hour

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
    repo: Optional[str] = None
    image: Optional[str] = None
    release_id: Optional[str] = None
    first_seen_build: Optional[str] = None
    first_seen_time: Optional[str] = None  # ISO string (UTC is fine)
    fixed_version: Optional[str] = None
    class Config:
        extra = "ignore"

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
    start_time: Optional[str] = Field(default=None, description="Start time in ISO format")
    end_time: Optional[str] = Field(default=None, description="End time in ISO format")
    podname: Optional[str] = Field(default=None, description="Pod/workload name to filter by")

class NLQueryResponse(BaseModel):
    answer: str
    used_logs: int
