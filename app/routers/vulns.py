from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from ..services.aws import get_critical_high_vulnerabilities
from ..services.llm import suggest_remediation
from ..services.nvd import nvd_service
from ..config import settings
from ..models import VulnerabilityFinding, VulnerabilityInput, SuggestionResponse
from ..utils import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/", response_model=List[VulnerabilityFinding])
def list_vulnerabilities(
    severity: Optional[List[str]] = Query(
        None,
        description="List or comma-separated severities to include (e.g. severity=HIGH or severity=HIGH,CRITICAL). Case-insensitive."
    ),
    env: Optional[str] = Query(None, description="Environment filter (currently informational)"),
    release_id: Optional[str] = Query(None, description="Release/build filter (currently informational)"),
    timeframe: Optional[str] = Query(None, description="Timeframe filter (currently informational)"),
    repo: Optional[str] = Query(None, description="Repository filter (currently informational)"),
    image: Optional[str] = Query(None, description="Image filter (currently informational)"),
):
    """
    List vulnerabilities. Supports severity filtering via a comma-separated string.
    Other filters are accepted for forward-compatibility but not yet applied here.
    """
    logger.info(
        "GET /vulnerabilities called with params: severity=%s, env=%s, release_id=%s, timeframe=%s, repo=%s, image=%s",
        severity, env, release_id, timeframe, repo, image
    )

    # Fetch current findings (service currently returns CRITICAL/HIGH only)
    vulnerabilities = get_critical_high_vulnerabilities()
    logger.info("Retrieved %d vulnerabilities before filtering", len(vulnerabilities))

    logger.info(f"Incoming query raw severity={severity}")

    # Apply severity filtering if provided
    if severity:
        try:
            requested = set()
            for s in severity:
                requested.update([part.strip().upper() for part in s.split(",") if part.strip()])

            before = len(vulnerabilities)
            vulnerabilities = [
                v for v in vulnerabilities
                if (v.severity or "").upper() in requested
            ]
            logger.info("Applied severity filter %s: %d → %d", requested, before, len(vulnerabilities))
        except Exception as e:
            logger.warning("Failed to parse/apply severity filter '%s': %s", severity, e)

    return vulnerabilities


@router.post("/suggest", response_model=SuggestionResponse)
def suggest(vuln: VulnerabilityInput):
    logger.info("POST /vulnerabilities/suggest endpoint called for vulnerability: %s", vuln.name)
    
    # load requirements if available
    req_text = None
    if settings.requirements_path:
        try:
            with open(settings.requirements_path, "r", encoding="utf-8") as f:
                req_text = f.read()[:5000]
            logger.info("Loaded requirements from %s", settings.requirements_path)
        except FileNotFoundError:
            logger.info("Requirements file not found at %s", settings.requirements_path)
            req_text = None
    
    # Get NVD data for enhanced suggestions
    nvd_data = None
    try:
        logger.info("Fetching NVD data for vulnerability enrichment")
        # Create a temporary vulnerability finding for NVD lookup
        temp_vuln = VulnerabilityFinding(
            name=vuln.name,
            severity=vuln.severity,
            description=vuln.description,
            package_name=vuln.package_name,
            package_version=vuln.package_version
        )
        enriched_vuln = nvd_service.enrich_vulnerability(temp_vuln)
        
        # Extract NVD data for LLM
        nvd_data = {
            "cve_id": enriched_vuln.cve_id,
            "nvd_description": enriched_vuln.nvd_description,
            "nvd_cvss_v3_score": enriched_vuln.nvd_cvss_v3_score,
            "nvd_cvss_v3_vector": enriched_vuln.nvd_cvss_v3_vector,
            "nvd_published_date": enriched_vuln.nvd_published_date,
            "nvd_vendor_comments": enriched_vuln.nvd_vendor_comments,
            "nvd_references": enriched_vuln.nvd_references
        }
        logger.info("NVD data retrieved successfully")
    except Exception as e:
        logger.warning("NVD data lookup failed: %s, continuing without NVD data", str(e))
        # Continue without NVD data if lookup fails
        pass
    
    try:
        logger.info("Generating remediation suggestion")
        suggestion = suggest_remediation(
            vuln,
            repo=settings.github_repo,
            branch=settings.github_branch,
            release=settings.release_version,
            requirements_text=req_text,
            nvd_data=nvd_data
        )
        logger.info("Remediation suggestion generated successfully, length: %d characters", len(suggestion))
        return SuggestionResponse(suggestion=suggestion)
    except Exception as e:
        logger.error("Error generating remediation suggestion: %s", str(e))
        raise HTTPException(status_code=500, detail=str(e))
