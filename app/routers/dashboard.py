from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel

from ..database import get_db, LogException, LogSummary, MonitoringConfig
from ..scheduler import scheduler

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

class ExceptionResponse(BaseModel):
    id: int
    timestamp: datetime
    log_group: str
    log_stream: Optional[str]
    message: str
    severity: Optional[str]
    service: Optional[str]
    environment: Optional[str]
    exception_type: Optional[str]
    frequency: int
    last_seen: datetime
    created_at: datetime

class DashboardStats(BaseModel):
    total_exceptions: int
    critical_count: int
    error_count: int
    warning_count: int
    unique_exceptions: int
    top_exception_types: List[dict]
    recent_exceptions: List[ExceptionResponse]
    time_range: str

class TimeRangeFilter(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    hours: Optional[int] = None

@router.get("/exceptions", response_model=List[ExceptionResponse])
def get_exceptions(
    log_group: Optional[str] = Query(None, description="Filter by log group"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    hours: Optional[int] = Query(24, description="Last N hours"),
    limit: int = Query(100, description="Maximum number of results"),
    db: Session = Depends(get_db)
):
    """Get exceptions from the database with filtering"""
    query = db.query(LogException)
    
    # Time filter
    if hours:
        start_time = datetime.utcnow() - timedelta(hours=hours)
        query = query.filter(LogException.timestamp >= start_time)
    
    # Log group filter
    if log_group:
        query = query.filter(LogException.log_group == log_group)
    
    # Severity filter
    if severity:
        query = query.filter(LogException.severity == severity.upper())
    
    # Order by timestamp desc and limit
    exceptions = query.order_by(desc(LogException.timestamp)).limit(limit).all()
    
    return [
        ExceptionResponse(
            id=exc.id,
            timestamp=exc.timestamp,
            log_group=exc.log_group,
            log_stream=exc.log_stream,
            message=exc.message,
            severity=exc.severity,
            service=exc.service,
            environment=exc.environment,
            exception_type=exc.exception_type,
            frequency=exc.frequency,
            last_seen=exc.last_seen,
            created_at=exc.created_at
        )
        for exc in exceptions
    ]

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    hours: int = Query(default=None, ge=1, le=48, description="Statistics for last N hours"),
    minutes: int = Query(default=None, ge=1, le=2880, description="Statistics for last N minutes"),
    log_group: Optional[str] = Query(None, description="Filter by log group"),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""
    # Handle both hours and minutes parameters
    if minutes is not None:
        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        time_range_desc = f"Last {minutes} minutes"
    elif hours is not None:
        start_time = datetime.utcnow() - timedelta(hours=hours)
        time_range_desc = f"Last {hours} hours"
    else:
        # Default to 24 hours
        start_time = datetime.utcnow() - timedelta(hours=24)
        time_range_desc = "Last 24 hours"
    
    # Base query
    query = db.query(LogException).filter(LogException.timestamp >= start_time)
    if log_group:
        query = query.filter(LogException.log_group == log_group)
    
    # Total exceptions
    total_exceptions = query.count()
    
    # Severity counts
    critical_count = query.filter(LogException.severity == 'CRITICAL').count()
    error_count = query.filter(LogException.severity == 'ERROR').count()
    warning_count = query.filter(LogException.severity == 'WARNING').count()
    
    # Unique exceptions (by message)
    unique_exceptions = query.distinct(LogException.message).count()
    
    # Top exception types
    top_exception_types = db.query(
        LogException.exception_type,
        func.count(LogException.id).label('count')
    ).filter(
        LogException.timestamp >= start_time,
        LogException.exception_type.isnot(None)
    ).group_by(
        LogException.exception_type
    ).order_by(desc('count')).limit(10).all()
    
    # Recent exceptions
    recent_exceptions = query.order_by(desc(LogException.timestamp)).limit(10).all()
    
    return DashboardStats(
        total_exceptions=total_exceptions,
        critical_count=critical_count,
        error_count=error_count,
        warning_count=warning_count,
        unique_exceptions=unique_exceptions,
        top_exception_types=[
            {"type": exc_type, "count": count}
            for exc_type, count in top_exception_types
        ],
        recent_exceptions=[
            ExceptionResponse(
                id=exc.id,
                timestamp=exc.timestamp,
                log_group=exc.log_group,
                log_stream=exc.log_stream,
                message=exc.message,
                severity=exc.severity,
                service=exc.service,
                environment=exc.environment,
                exception_type=exc.exception_type,
                frequency=exc.frequency,
                last_seen=exc.last_seen,
                created_at=exc.created_at
            )
            for exc in recent_exceptions
        ],
        time_range=time_range_desc
    )

@router.get("/trends")
def get_trends(
    hours: int = Query(default=None, ge=1, le=48, description="Trend data for last N hours"),
    minutes: int = Query(default=None, ge=1, le=2880, description="Trend data for last N minutes"),
    log_group: Optional[str] = Query(None, description="Filter by log group"),
    db: Session = Depends(get_db)
):
    """Get exception trends over time"""
    # Handle both hours and minutes parameters
    if minutes is not None:
        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        time_range_desc = f"Last {minutes} minutes"
    elif hours is not None:
        start_time = datetime.utcnow() - timedelta(hours=hours)
        time_range_desc = f"Last {hours} hours"
    else:
        # Default to 24 hours
        start_time = datetime.utcnow() - timedelta(hours=24)
        time_range_desc = "Last 24 hours"
    
    query = db.query(LogException).filter(LogException.timestamp >= start_time)
    if log_group:
        query = query.filter(LogException.log_group == log_group)
    
    # Group by hour
    hourly_trends = db.query(
        func.date_trunc('hour', LogException.timestamp).label('hour'),
        func.count(LogException.id).label('count'),
        func.count(func.distinct(LogException.message)).label('unique_count')
    ).filter(
        LogException.timestamp >= start_time
    ).group_by(
        func.date_trunc('hour', LogException.timestamp)
    ).order_by('hour').all()
    
    return {
        "hourly_trends": [
            {
                "hour": trend.hour.isoformat(),
                "total_exceptions": trend.count,
                "unique_exceptions": trend.unique_count
            }
            for trend in hourly_trends
        ],
        "time_range": time_range_desc
    }

@router.get("/scheduler/status")
def get_scheduler_status():
    """Get scheduler status"""
    return scheduler.get_status()

@router.post("/scheduler/restart")
def restart_scheduler():
    """Restart the scheduler (stop and start)"""
    try:
        scheduler.stop()
        scheduler.start()
        return {"status": "success", "message": "Scheduler restarted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scheduler/stop")
def stop_scheduler():
    """Stop the scheduler (for maintenance)"""
    try:
        scheduler.stop()
        return {"status": "success", "message": "Scheduler stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scheduler/start")
def start_scheduler():
    """Start the scheduler (if manually stopped)"""
    try:
        scheduler.start()
        return {"status": "success", "message": "Scheduler started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/environments", response_model=List[str])
def get_environments():
    """Get list of available environments"""
    return [
        "dev-blue",
        "dev-green", 
        "dev-experiment",
        "uat-blue",
        "uat-green"
    ]

@router.get("/repositories", response_model=List[str])
def get_repositories():
    """Get list of available repositories"""
    return [
        "https://github.com/SridhanyaG/samplecontentgenerator",
        "https://github.com/SridhanyaG/copilotdashboard"
    ]

@router.get("/log-groups", response_model=List[str])
def get_log_groups(environment: str = Query(..., description="Environment name")):
    """Get list of available log groups for a specific environment"""
    # Environment to log groups mapping
    environment_log_groups = {
        "dev-experiment": ["/ecs/crocin-backend"],
        "dev-blue": ["/ecs/crocin-backend"],
        "dev-green": ["/ecs/crocin-backend"]
    }
    
    if environment not in environment_log_groups:
        valid_environments = list(environment_log_groups.keys())
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid environment. Valid environments are: {', '.join(valid_environments)}"
        )
    
    return environment_log_groups[environment]

@router.get("/releases", response_model=dict)
def get_releases():
    """Get release mapping for all environments"""
    return {
        "dev-experiment": "R24",
        "dev-blue": "R24",
        "dev-green": "R24",
        "uat-blue": "R24",
        "uat-green": "R24"
    }

@router.get("/pods", response_model=List[str])
def get_pods(environment: str = Query(..., description="Environment name")):
    """Get list of pods for a specific environment"""
    # Valid environments
    valid_environments = ["dev-experiment", "dev-blue", "dev-green", "uat-blue", "uat-green"]
    
    if environment not in valid_environments:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid environment. Valid environments are: {', '.join(valid_environments)}"
        )
    
    # Same workload (crocin-backend) for all environments
    return ["crocin-backend"]

@router.get("/configs", response_model=List[dict])
def get_monitoring_configs(db: Session = Depends(get_db)):
    """Get monitoring configurations"""
    configs = db.query(MonitoringConfig).all()
    return [
        {
            "id": config.id,
            "log_group": config.log_group,
            "enabled": config.enabled,
            "inclusion_patterns": config.inclusion_patterns,
            "exclusion_patterns": config.exclusion_patterns,
            "last_scan": config.last_scan.isoformat() if config.last_scan else None,
            "next_scan": config.next_scan.isoformat() if config.next_scan else None,
            "created_at": config.created_at.isoformat()
        }
        for config in configs
    ]
