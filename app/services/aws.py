from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import List

import boto3

from ..config import settings
from ..models import LogEntry, VulnerabilityFinding
from ..utils import get_logger
from .nvd import nvd_service
from .llm import _generate_cloudwatch_query

logger = get_logger(__name__)


def _ecr_client():
    return boto3.client("ecr", region_name=settings.aws_region)


def _logs_client():
    return boto3.client("logs", region_name=settings.aws_region)


def get_critical_high_vulnerabilities() -> List[VulnerabilityFinding]:
    if not settings.ecr_repository or not (settings.ecr_image_tag or settings.ecr_image_digest):
        return []

    client = _ecr_client()

    image_id: dict
    if settings.ecr_image_digest:
        image_id = {"imageDigest": settings.ecr_image_digest}
    else:
        image_id = {"imageTag": settings.ecr_image_tag}

    resp = client.describe_image_scan_findings(
        repositoryName=settings.ecr_repository,
        imageId=image_id,
        maxResults=1000,
    )

    findings = resp.get("imageScanFindings", {}).get("findings", [])
    results: List[VulnerabilityFinding] = []
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev not in {"HIGH", "CRITICAL"}:
            continue
        attrs = {a.get("key"): a.get("value") for a in f.get("attributes", [])}
        pkg = attrs.get("package_name") or attrs.get("packageName")
        ver = attrs.get("package_version") or attrs.get("packageVersion")
        
        # Create base vulnerability finding
        vuln = VulnerabilityFinding(
            name=f.get("name") or f.get("title") or "Unknown",
            severity=sev,
            description=f.get("description"),
            uri=f.get("uri"),
            package_name=pkg,
            package_version=ver,
            cvss_score=(f.get("cvss") or {}).get("baseScore"),
        )
        
        # Enrich with NVD data
        enriched_vuln = nvd_service.enrich_vulnerability(vuln)
        results.append(enriched_vuln)
    
    return results


def get_logs_exceptions(hours: int) -> List[LogEntry]:
    logger.info(f"Starting exception retrieval for {hours} hours")
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    end = datetime.now(timezone.utc)
    logger.info(f"Query time range: {start} to {end}")

    # Get inclusion and exclusion patterns from config
    inclusion_patterns = []
    exclusion_patterns = []
    
    if settings.monitoring.get('log_groups'):
        for log_group in settings.monitoring['log_groups']:
            if log_group.get('name') == settings.log_group_name:
                inclusion_patterns = log_group.get('inclusion_patterns', [])
                exclusion_patterns = log_group.get('exclusion_patterns', [])
                break

    logger.info(f"Using inclusion patterns: {inclusion_patterns}")
    logger.info(f"Using exclusion patterns: {exclusion_patterns}")

    # Generate CloudWatch query using LLM
    query = _generate_cloudwatch_query(inclusion_patterns, exclusion_patterns)
    logger.info(f"Generated CloudWatch query: {query}")

    client = _logs_client()
    logger.info(f"Querying log group: {settings.log_group_name}")

    try:
        start_query_resp = client.start_query(
            logGroupName=settings.log_group_name,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=query,
            limit=10000,
        )
    except Exception as e:
        if "MalformedQueryException" in str(e):
            logger.warning(f"Complex query failed with MalformedQueryException: {e}")
            logger.info("Attempting fallback to simple query generation")
            # Try with a simple query
            from app.services.llm import _generate_simple_cloudwatch_query
            simple_query = _generate_simple_cloudwatch_query(inclusion_patterns, exclusion_patterns)
            logger.info(f"Generated fallback simple query: {simple_query}")
            
            try:
                start_query_resp = client.start_query(
                    logGroupName=settings.log_group_name,
                    startTime=int(start.timestamp()),
                    endTime=int(end.timestamp()),
                    queryString=simple_query,
                    limit=10000,
                )
                logger.info("Fallback simple query started successfully")
            except Exception as fallback_error:
                logger.error(f"Fallback simple query also failed: {fallback_error}")
                raise fallback_error
        else:
            logger.error(f"Non-MalformedQueryException error occurred: {e}")
            raise e

    query_id = start_query_resp["queryId"]
    logger.info(f"Started CloudWatch query with ID: {query_id}")

    # Poll for results
    status = "Running"
    results = []
    for attempt in range(30):
        resp = client.get_query_results(queryId=query_id)
        status = resp.get("status")
        logger.info(f"Query status check {attempt + 1}: {status}")
        if status in {"Complete", "Failed", "Cancelled"}:
            results = resp.get("results", [])
            logger.info(f"Query completed with status: {status}, found {len(results)} raw log entries")
            break
        import time
        time.sleep(1)

    entries: List[LogEntry] = []
    for row in results:
        row_map = {c["field"]: c["value"] for c in row}
        msg = row_map.get("@message") or ""
        
        logger.debug(f"Processing log entry: {msg[:100]}...")
        ts_raw = row_map.get("@timestamp")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else end
        except Exception:
            ts = end
        entries.append(
            LogEntry(
                timestamp=ts,
                message=msg,
                log_stream=row_map.get("@logStream"),
                log_group=row_map.get("@log"),
            )
        )

    logger.info(f"Retrieved {len(entries)} exceptions from CloudWatch query")
    return entries
