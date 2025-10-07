from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# Database configuration
DATABASE_URL = f"sqlite:///./logcopilot.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class LogException(Base):
    __tablename__ = "log_exceptions"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    log_group = Column(String(255), nullable=False, index=True)
    log_stream = Column(String(255), nullable=True)
    message = Column(Text, nullable=False)
    severity = Column(String(50), nullable=True, index=True)  # ERROR, CRITICAL, FATAL, etc.
    service = Column(String(100), nullable=True)  # crocin-backend
    environment = Column(String(50), nullable=True)  # production, staging, etc.
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Additional metadata
    exception_type = Column(String(100), nullable=True)  # Python exception class
    stack_trace = Column(Text, nullable=True)
    user_id = Column(String(100), nullable=True)
    request_id = Column(String(100), nullable=True)
    
    # Metrics
    frequency = Column(Integer, default=1)  # How many times this exception occurred
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<LogException(id={self.id}, timestamp={self.timestamp}, severity={self.severity})>"

class LogSummary(Base):
    __tablename__ = "log_summaries"
    
    id = Column(Integer, primary_key=True, index=True)
    log_group = Column(String(255), nullable=False, index=True)
    date = Column(DateTime, nullable=False, index=True)  # Date (YYYY-MM-DD)
    hour = Column(Integer, nullable=False, index=True)  # Hour (0-23)
    
    # Counts
    total_exceptions = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    fatal_count = Column(Integer, default=0)
    
    # Top exceptions
    top_exception_types = Column(Text, nullable=True)  # JSON string of top exception types
    top_services = Column(Text, nullable=True)  # JSON string of top services
    
    # Metrics
    avg_frequency = Column(Float, default=0.0)
    unique_exceptions = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<LogSummary(log_group={self.log_group}, date={self.date}, hour={self.hour})>"

class MonitoringConfig(Base):
    __tablename__ = "monitoring_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    log_group = Column(String(255), nullable=False, unique=True, index=True)
    enabled = Column(Boolean, default=True)
    inclusion_patterns = Column(Text, nullable=True)  # JSON string of patterns
    exclusion_patterns = Column(Text, nullable=True)  # JSON string of patterns
    last_scan = Column(DateTime, nullable=True)
    next_scan = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<MonitoringConfig(log_group={self.log_group}, enabled={self.enabled})>"

# Create tables
def create_tables():
    Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
