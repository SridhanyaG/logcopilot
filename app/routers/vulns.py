from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Any, Dict
from datetime import datetime, timedelta, timezone

from ..services.aws import get_critical_high_vulnerabilities
from ..services.llm import suggest_remediation
from ..services.nvd import nvd_service
from ..config import settings
from ..models import VulnerabilityFinding, VulnerabilityInput, SuggestionResponse
from ..utils import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


def _as_dict(obj: Any) -> Dict[str, Any]:
    """Convert model/obj to dict safely."""
    if isinstance(obj, dict):
        return obj.copy()
    if hasattr(obj, "dict"):
        return obj.dict()
    return obj.__dict__.copy() if hasattr(obj, "__dict__") else {}


@router.get("/", response_model=List[VulnerabilityFinding], response_model_exclude_none=True)
def list_vulnerabilities(
    severity: Optional[List[str]] = Query(None, description="severity=HIGH or severity=HIGH,CRITICAL"),
    env: Optional[str] = Query(None),
    image: Optional[str] = Query(None),
    image_digest: Optional[str] = Query(None, description="Image digest (SHA256)"),
    timeframe: Optional[str] = Query("last-build"),
):
    logger.info(
        "GET /vulnerabilities filters: env=%s image=%s image_digest=%s timeframe=%s severity=%s",
        env, image, image_digest, timeframe, severity,
    )

    # 1) Fetch base data
    base = get_critical_high_vulnerabilities()
    logger.info("Service returned %d raw findings", len(base))
    if not base:
        return []

    # Normalize severity filter (supports array or csv)
    requested_sev = set()
    if severity:
        for s in severity:
            for part in str(s).split(","):
                part = part.strip()
                if part:
                    requested_sev.add(part.upper())

    now = datetime.now(timezone.utc)

    # 2) Normalize + ENRICH FIRST (add UI defaults and coalesce None) ✅
    enriched_rows: List[dict] = []
    for item in base:
        row = item.dict() if hasattr(item, "dict") else (item if isinstance(item, dict) else item.__dict__.copy())

        # required fields
        row["name"] = row.get("name") or row.get("cve_id") or "UNKNOWN"
        row["severity"] = (row.get("severity") or "UNKNOWN").upper()

        # coalesce helper: treat None/"", "null" as missing
        def coalesce(val, default):
            return default if val in (None, "", "null") else val

        # add UI-friendly defaults up-front so filters can match (overwrite None)
        row["repo"] = coalesce(row.get("repo"), "org/samplecontentgenerator")
        row["image"] = coalesce(row.get("image"), "sha256:exampledigest123")
        # set default release_id
        row["release_id"] = coalesce(row.get("release_id"), "v2.1.4")
        row["first_seen_build"] = coalesce(row.get("first_seen_build"), "build-001")
        row["first_seen_time"] = coalesce(row.get("first_seen_time"), now.isoformat())

        if not row.get("fixed_version") and row.get("package_name") == "openssl":
            row["fixed_version"] = "3.5.2"

        # Handle image_digest and image_tag logic
        if image_digest:
            row["image_digest"] = image_digest
            row["image_tag"] = None
        else:
            # If image_digest is None, set image_tag to "latest"
            row["image_digest"] = None
            row["image_tag"] = "latest"

        enriched_rows.append(row)

    logger.info("Enriched %d rows", len(enriched_rows))

    # 3) Apply filters AFTER enrichment ✅
    filtered_rows: List[dict] = []
    for row in enriched_rows:
        # severity
        if requested_sev and row["severity"] not in requested_sev:
            continue
        # optional exact matches (now fields exist / not None)
        if image and row.get("image") != image:
            continue
        filtered_rows.append(row)

    logger.info("After image/severity filters: %d rows", len(filtered_rows))

    # 4) Timeframe (UTC)
    if timeframe and timeframe not in ("last-build", "", None):
        cutoff = None
        if timeframe == "1d":
            cutoff = now - timedelta(days=1)
        elif timeframe == "1w":
            cutoff = now - timedelta(weeks=1)
        elif timeframe == "1m":
            cutoff = now - timedelta(days=30)

        if cutoff:
            kept = []
            for row in filtered_rows:
                t = row.get("first_seen_time") or row.get("nvd_published_date")
                try:
                    dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                    if dt >= cutoff:
                        kept.append(row)
                except Exception:
                    kept.append(row)  # keep if unparsable
            filtered_rows = kept
            logger.info("After timeframe filter '%s': %d rows", timeframe, len(filtered_rows))

    # 5) Map to model (log any schema drops)
    result: List[VulnerabilityFinding] = []
    drops = 0
    for row in filtered_rows:
        try:
            result.append(VulnerabilityFinding(**row))
        except Exception as e:
            drops += 1
            logger.warning("Dropping row due to schema mismatch: %s | error=%s", row, e)

    logger.info("Returning %d rows (dropped %d)", len(result), drops)
    return result


@router.post("/suggest", response_model=SuggestionResponse)
def suggest(vuln: VulnerabilityInput):
    logger.info(f"POST /vulnerabilities/suggest called for {vuln.name}")

    req_text = None
    if settings.requirements_path:
        try:
            with open(settings.requirements_path, "r", encoding="utf-8") as f:
                req_text = f.read()[:5000]
            logger.info(f"Loaded requirements from {settings.requirements_path}")
        except FileNotFoundError:
            logger.info(f"No requirements file found at {settings.requirements_path}")

    # Enrich with NVD
    nvd_data = None
    try:
        temp_vuln = VulnerabilityFinding(
            name=vuln.name,
            severity=vuln.severity,
            description=vuln.description,
            package_name=vuln.package_name,
            package_version=vuln.package_version,
        )
        enriched = nvd_service.enrich_vulnerability(temp_vuln)
        nvd_data = {
            "cve_id": enriched.cve_id,
            "nvd_description": enriched.nvd_description,
            "nvd_cvss_v3_score": enriched.nvd_cvss_v3_score,
            "nvd_cvss_v3_vector": enriched.nvd_cvss_v3_vector,
            "nvd_published_date": enriched.nvd_published_date,
            "nvd_vendor_comments": enriched.nvd_vendor_comments,
            "nvd_references": enriched.nvd_references,
        }
    except Exception as e:
        logger.warning(f"NVD enrichment failed: {e}")

    # Suggest remediation
    try:
        suggestion = suggest_remediation(
            vuln,
            repo=settings.github_repo,
            branch=settings.github_branch,
            release=settings.release_version,
            requirements_text=req_text,
            nvd_data=nvd_data,
        )
        return SuggestionResponse(suggestion=suggestion)
    except Exception as e:
        logger.error(f"Error generating suggestion: {e}")
        raise HTTPException(status_code=500, detail=str(e))
