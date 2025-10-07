from fastapi import APIRouter, HTTPException
from typing import List

from ..services.aws import get_critical_high_vulnerabilities
from ..services.llm import suggest_remediation
from ..services.nvd import nvd_service
from ..config import settings
from ..models import VulnerabilityFinding, VulnerabilityInput, SuggestionResponse
from ..utils import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/", response_model=List[VulnerabilityFinding])
def list_vulnerabilities():
    logger.info("GET /vulnerabilities endpoint called")
    vulnerabilities = get_critical_high_vulnerabilities()
    logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities")
    return vulnerabilities


@router.post("/suggest", response_model=SuggestionResponse)
def suggest(vuln: VulnerabilityInput):
    logger.info(f"POST /vulnerabilities/suggest endpoint called for vulnerability: {vuln.name}")
    
    # load requirements if available
    req_text = None
    if settings.requirements_path:
        try:
            with open(settings.requirements_path, "r", encoding="utf-8") as f:
                req_text = f.read()[:5000]
            logger.info(f"Loaded requirements from {settings.requirements_path}")
        except FileNotFoundError:
            logger.info(f"Requirements file not found at {settings.requirements_path}")
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
        logger.warning(f"NVD data lookup failed: {str(e)}, continuing without NVD data")
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
        logger.info(f"Remediation suggestion generated successfully, length: {len(suggestion)} characters")
        return SuggestionResponse(suggestion=suggestion)
    except Exception as e:
        logger.error(f"Error generating remediation suggestion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
