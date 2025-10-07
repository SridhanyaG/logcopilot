from __future__ import annotations
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from ..database import SessionLocal, LogException, LogSummary, MonitoringConfig
from ..services.aws import get_logs_exceptions
from ..config import settings

logger = logging.getLogger(__name__)

class LogMonitoringService:
    def __init__(self):
        self.db = SessionLocal()
    
    def __del__(self):
        if hasattr(self, 'db'):
            self.db.close()
    
    def get_monitoring_configs(self) -> List[MonitoringConfig]:
        """Get all enabled monitoring configurations"""
        return self.db.query(MonitoringConfig).filter(MonitoringConfig.enabled == True).all()
    
    def update_last_scan(self, log_group: str):
        """Update the last scan timestamp for a log group"""
        config = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.log_group == log_group
        ).first()
        if config:
            config.last_scan = datetime.utcnow()
            config.next_scan = datetime.utcnow() + timedelta(minutes=settings.scheduler.get('interval_minutes', 60))
            self.db.commit()
    
    def should_include_message(self, message: str, config: MonitoringConfig) -> bool:
        """Check if a log message should be included based on patterns"""
        if not config.inclusion_patterns:
            return True
        
        inclusion_patterns = json.loads(config.inclusion_patterns) if isinstance(config.inclusion_patterns, str) else config.inclusion_patterns
        exclusion_patterns = json.loads(config.exclusion_patterns) if isinstance(config.exclusion_patterns, str) else config.exclusion_patterns
        
        # Check inclusion patterns (at least one must match)
        matches_inclusion = any(pattern.lower() in message.lower() for pattern in inclusion_patterns)
        
        # Check exclusion patterns (none should match)
        matches_exclusion = any(pattern.lower() in message.lower() for pattern in exclusion_patterns) if exclusion_patterns else False
        
        return matches_inclusion and not matches_exclusion
    
    def extract_exception_metadata(self, message: str) -> Dict[str, Any]:
        """Extract metadata from log message"""
        metadata = {
            'severity': 'ERROR',
            'exception_type': None,
            'stack_trace': None,
            'user_id': None,
            'request_id': None
        }
        
        # Determine severity
        message_upper = message.upper()
        if 'FATAL' in message_upper or 'CRITICAL' in message_upper:
            metadata['severity'] = 'CRITICAL'
        elif 'ERROR' in message_upper:
            metadata['severity'] = 'ERROR'
        elif 'WARN' in message_upper or 'WARNING' in message_upper:
            metadata['severity'] = 'WARNING'
        
        # Extract exception type (Python style)
        if 'Exception:' in message or 'Error:' in message:
            lines = message.split('\n')
            for line in lines:
                if 'Exception:' in line or 'Error:' in line:
                    parts = line.split(':')
                    if len(parts) > 0:
                        metadata['exception_type'] = parts[0].strip()
                    break
        
        # Extract stack trace
        if 'Traceback' in message:
            metadata['stack_trace'] = message
        
        # Extract request ID (common patterns)
        import re
        request_id_match = re.search(r'request[_-]?id["\']?\s*[:=]\s*["\']?([a-f0-9-]+)', message, re.IGNORECASE)
        if request_id_match:
            metadata['request_id'] = request_id_match.group(1)
        
        return metadata
    
    def process_log_entries(self, log_group: str, entries: List[Dict]) -> int:
        """Process log entries and store exceptions in database"""
        config = self.db.query(MonitoringConfig).filter(
            MonitoringConfig.log_group == log_group
        ).first()
        
        if not config:
            logger.warning(f"No monitoring config found for log group: {log_group}")
            return 0
        
        processed_count = 0
        
        for entry in entries:
            message = entry.get('message', '')
            timestamp = entry.get('timestamp')
            log_stream = entry.get('log_stream')
            
            # Check if message should be included
            if not self.should_include_message(message, config):
                continue
            
            # Extract metadata
            metadata = self.extract_exception_metadata(message)
            
            # Check if similar exception already exists
            existing = self.db.query(LogException).filter(
                LogException.log_group == log_group,
                LogException.message == message,
                LogException.severity == metadata['severity']
            ).first()
            
            if existing:
                # Update frequency and last_seen
                existing.frequency += 1
                existing.last_seen = datetime.utcnow()
                self.db.commit()
            else:
                # Create new exception record
                exception = LogException(
                    timestamp=timestamp or datetime.utcnow(),
                    log_group=log_group,
                    log_stream=log_stream,
                    message=message,
                    severity=metadata['severity'],
                    service='crocin-backend',  # From config
                    environment='production',  # Could be from config
                    exception_type=metadata['exception_type'],
                    stack_trace=metadata['stack_trace'],
                    request_id=metadata['request_id'],
                    frequency=1,
                    last_seen=datetime.utcnow()
                )
                self.db.add(exception)
                processed_count += 1
        
        self.db.commit()
        return processed_count
    
    def scan_log_group(self, log_group: str, hours: int = 1) -> Dict[str, Any]:
        """Scan a specific log group for exceptions"""
        logger.info(f"Scanning log group: {log_group} for the last {hours} hours")
        
        try:
            # Get log entries from CloudWatch
            entries = get_logs_exceptions(hours)
            
            # Process and store exceptions
            processed_count = self.process_log_entries(log_group, [
                {
                    'message': entry.message,
                    'timestamp': entry.timestamp,
                    'log_stream': entry.log_stream
                }
                for entry in entries
            ])
            
            # Update scan timestamp
            self.update_last_scan(log_group)
            
            return {
                'log_group': log_group,
                'hours_scanned': hours,
                'exceptions_found': len(entries),
                'exceptions_processed': processed_count,
                'scan_time': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error scanning log group {log_group}: {e}")
            return {
                'log_group': log_group,
                'error': str(e),
                'scan_time': datetime.utcnow().isoformat()
            }
    
    def scan_all_log_groups(self) -> List[Dict[str, Any]]:
        """Scan all configured log groups"""
        results = []
        configs = self.get_monitoring_configs()
        
        for config in configs:
            result = self.scan_log_group(config.log_group, hours=1)
            results.append(result)
        
        return results
    
    def cleanup_old_data(self, retention_days: int = 30):
        """Clean up old log data based on retention policy"""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Delete old exceptions
        old_exceptions = self.db.query(LogException).filter(
            LogException.created_at < cutoff_date
        ).delete()
        
        # Delete old summaries
        old_summaries = self.db.query(LogSummary).filter(
            LogSummary.created_at < cutoff_date
        ).delete()
        
        self.db.commit()
        
        logger.info(f"Cleaned up {old_exceptions} old exceptions and {old_summaries} old summaries")
        return {'exceptions_deleted': old_exceptions, 'summaries_deleted': old_summaries}

# Global service instance
monitoring_service = LogMonitoringService()
