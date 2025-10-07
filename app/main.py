from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .config import settings
from .routers.vulns import router as vulns_router
from .routers.logs import router as logs_router
from .routers.dashboard import router as dashboard_router
from .database import create_tables
from .scheduler import scheduler
from .utils import get_logger

logger = get_logger(__name__)

# ------------------------------------------------------------
# ✅ Enable CORS (for frontend running on localhost:5173/5175)
# ------------------------------------------------------------
ALLOWED_ORIGINS = [
    "http://localhost:5173",   # Vite default
    "http://localhost:5174",
    "http://localhost:5175",   # your current dev port
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting LogCopilot API")
    logger.info(f"Application version: 0.1.0")
    logger.info(f"Configuration loaded from: config.yaml")
    
    # Create database tables
    logger.info("Creating database tables")
    create_tables()
    logger.info("Database tables created successfully")
    
    # Initialize monitoring configurations
    logger.info("Initializing monitoring configurations")
    from .services.scheduler import monitoring_service
    from .database import SessionLocal, MonitoringConfig
    import json
    
    db = SessionLocal()
    try:
        # Initialize monitoring configs from YAML if they don't exist
        if settings.monitoring.get('log_groups'):
            logger.info(f"Found {len(settings.monitoring['log_groups'])} log groups in configuration")
            for log_group_config in settings.monitoring['log_groups']:
                logger.info(f"Processing log group: {log_group_config['name']}")
                existing = db.query(MonitoringConfig).filter(
                    MonitoringConfig.log_group == log_group_config['name']
                ).first()
                
                if not existing:
                    logger.info(f"Creating new monitoring config for {log_group_config['name']}")
                    config = MonitoringConfig(
                        log_group=log_group_config['name'],
                        enabled=log_group_config.get('enabled', True),
                        inclusion_patterns=json.dumps(log_group_config.get('inclusion_patterns', [])),
                        exclusion_patterns=json.dumps(log_group_config.get('exclusion_patterns', []))
                    )
                    db.add(config)
                    logger.info(f"Created monitoring config for {log_group_config['name']}")
                else:
                    logger.info(f"Monitoring config already exists for {log_group_config['name']}")
        
        db.commit()
        logger.info("Monitoring configurations initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing monitoring configs: {e}")
    finally:
        db.close()
        logger.info("Database connection closed")
    
    # Start scheduler if enabled
    if settings.scheduler.get('enabled', True):
        logger.info("Starting scheduler service")
        scheduler.start()
        logger.info("Scheduler started successfully")
    else:
        logger.info("Scheduler disabled in configuration")
    
    logger.info("LogCopilot API startup completed successfully")
    yield
    
    # Shutdown
    logger.info("Starting LogCopilot API shutdown")
    logger.info("Stopping scheduler service")
    scheduler.stop()
    logger.info("Scheduler stopped successfully")
    logger.info("LogCopilot API shutdown completed")

app = FastAPI(
    title="LogCopilot API", 
    version="0.1.0",
    description="Log Analytics Dashboard with Vulnerability Scanning and AI Insights",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],   # or restrict to ["GET", "POST"]
    allow_headers=["*"],
)

# Include routers
app.include_router(vulns_router, prefix="/v1")
app.include_router(logs_router, prefix="/v1")
app.include_router(dashboard_router, prefix="/v1")

@app.get("/healthz")
def healthz():
    return {"status": "ok", "scheduler": scheduler.is_running}

@app.get("/")
def root():
    return {
        "message": "LogCopilot API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/healthz"
    }
