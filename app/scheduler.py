from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging
import atexit
from datetime import datetime

from .services.scheduler import monitoring_service
from .config import settings

logger = logging.getLogger(__name__)

class LogCopilotScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.is_running = False
    
    def start(self):
        """Start the scheduler"""
        if not settings.scheduler.get('enabled', True):
            logger.info("Scheduler is disabled in configuration")
            return
        
        if self.is_running:
            logger.warning("Scheduler is already running")
            return
        
        # Add the log monitoring job
        interval_minutes = settings.scheduler.get('interval_minutes', 60)
        self.scheduler.add_job(
            self.monitor_logs,
            trigger=IntervalTrigger(minutes=interval_minutes),
            id='log_monitoring',
            name='Log Monitoring Job',
            replace_existing=True
        )
        
        # Add cleanup job (daily)
        self.scheduler.add_job(
            self.cleanup_old_data,
            trigger=IntervalTrigger(days=1),
            id='data_cleanup',
            name='Data Cleanup Job',
            replace_existing=True
        )
        
        self.scheduler.start()
        self.is_running = True
        logger.info(f"Scheduler started with {interval_minutes} minute intervals")
    
    def stop(self):
        """Stop the scheduler"""
        if self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Scheduler stopped")
    
    def monitor_logs(self):
        """Main monitoring job - scans all log groups"""
        logger.info("Starting scheduled log monitoring")
        try:
            results = monitoring_service.scan_all_log_groups()
            for result in results:
                if 'error' in result:
                    logger.error(f"Error monitoring {result['log_group']}: {result['error']}")
                else:
                    logger.info(f"Scanned {result['log_group']}: {result['exceptions_processed']} new exceptions")
        except Exception as e:
            logger.error(f"Error in scheduled log monitoring: {e}")
    
    def cleanup_old_data(self):
        """Cleanup job - removes old data based on retention policy"""
        logger.info("Starting scheduled data cleanup")
        try:
            retention_days = settings.monitoring.get('retention_days', 30)
            result = monitoring_service.cleanup_old_data(retention_days)
            logger.info(f"Cleanup completed: {result}")
        except Exception as e:
            logger.error(f"Error in scheduled cleanup: {e}")
    
    def get_status(self):
        """Get scheduler status"""
        return {
            'running': self.is_running,
            'jobs': [
                {
                    'id': job.id,
                    'name': job.name,
                    'next_run': job.next_run_time.isoformat() if job.next_run_time else None
                }
                for job in self.scheduler.get_jobs()
            ]
        }

# Global scheduler instance
scheduler = LogCopilotScheduler()

# Register shutdown handler
@atexit.register
def shutdown_scheduler():
    scheduler.stop()
