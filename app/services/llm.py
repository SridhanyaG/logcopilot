from __future__ import annotations
from typing import List
from openai import OpenAI

from ..config import settings
from ..models import VulnerabilityInput, LogEntry
from ..utils import get_logger

logger = get_logger(__name__)


def _client() -> OpenAI:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY not configured")
    return OpenAI(api_key=settings.openai_api_key)


def suggest_remediation(vuln: VulnerabilityInput, repo: str | None, branch: str | None,
                        release: str | None, requirements_text: str | None, 
                        nvd_data: dict | None = None) -> str:
    logger.info(f"Generating remediation suggestion for vulnerability: {vuln.name}")
    client = _client()
    logger.info(f"Using OpenAI model: {settings.openai_model}")
    
    # Build enhanced prompt with NVD data
    nvd_context = ""
    if nvd_data:
        logger.info("Including NVD data in remediation prompt")
        nvd_context = f"""
NVD Data:
- CVE ID: {nvd_data.get('cve_id', 'N/A')}
- NVD Description: {nvd_data.get('nvd_description', 'N/A')}
- CVSS v3 Score: {nvd_data.get('nvd_cvss_v3_score', 'N/A')}
- CVSS v3 Vector: {nvd_data.get('nvd_cvss_v3_vector', 'N/A')}
- Published: {nvd_data.get('nvd_published_date', 'N/A')}
- Vendor Comments: {nvd_data.get('nvd_vendor_comments', 'N/A')}
- References: {', '.join(nvd_data.get('nvd_references', [])[:3]) if nvd_data.get('nvd_references') else 'N/A'}
"""
    else:
        logger.info("No NVD data available for remediation")
    
    prompt = (
        "You are a senior security engineer. Given a vulnerability and project context, "
        "propose concrete remediation steps. Prefer actionable version bumps or code fixes.\n\n"
        f"Vulnerability: name={vuln.name}, severity={vuln.severity}, package={vuln.package_name} "
        f"version={vuln.package_version}\nDescription: {vuln.description or 'n/a'}\n\n"
        f"Repo: {repo or 'n/a'}\nBranch: {branch or 'n/a'}\nRelease: {release or 'n/a'}\n"
        "requirements.txt (if provided):\n"
        f"{requirements_text or 'n/a'}\n\n"
        f"{nvd_context}\n"
        "Return concise steps and suggested versions. If NVD data is available, use it to provide more accurate remediation advice."
    )
    logger.info(f"Prompt length: {len(prompt)} characters")
    
    logger.info("Sending request to OpenAI API")
    resp = client.chat.completions.create(
        model=settings.openai_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=600,
    )
    
    result = resp.choices[0].message.content.strip()
    logger.info(f"Received remediation suggestion, length: {len(result)} characters")
    return result


def summarize_exceptions(entries: List[LogEntry]) -> str:
    logger.info(f"Starting exception summarization for {len(entries)} entries")
    if not entries:
        logger.info("No entries to summarize, returning default message")
        return "No exceptions found in the selected timeframe."
    
    client = _client()
    logger.info(f"Using OpenAI model: {settings.openai_model}")
    
    # Limit to first 1000 entries to avoid token limits
    entries_to_process = entries[:1000]
    logger.info(f"Processing {len(entries_to_process)} entries for summarization")
    
    joined = "\n\n".join(
        f"[{e.timestamp.isoformat()}] {e.message[:2000]}" for e in entries_to_process
    )
    logger.info(f"Joined log entries, total length: {len(joined)} characters")
    
    prompt = (
        "Summarize the exceptions below. Group by root cause, list affected components, and propose fixes.\n\n"
        f"Logs:\n{joined}"
    )
    logger.info(f"Prompt length: {len(prompt)} characters")
    
    logger.info("Sending request to OpenAI API for exception summarization")
    resp = client.chat.completions.create(
        model=settings.openai_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=600,
    )
    
    result = resp.choices[0].message.content.strip()
    logger.info(f"Exception summarization completed, result length: {len(result)} characters")
    return result


def _generate_cloudwatch_query(inclusion_patterns: List[str], exclusion_patterns: List[str]) -> str:
    """
    Generate a CloudWatch Insights query using LLM based on inclusion and exclusion patterns.
    
    Args:
        inclusion_patterns: List of patterns to include in the query
        exclusion_patterns: List of patterns to exclude from the query
    
    Returns:
        CloudWatch Insights query string
    """
    logger.info(f"Generating CloudWatch query with inclusion: {inclusion_patterns}, exclusion: {exclusion_patterns}")
    
    client = _client()
    
    # Build the prompt for query generation
    inclusion_text = ", ".join(inclusion_patterns) if inclusion_patterns else "Exception, ERROR, Error, FATAL, CRITICAL"
    exclusion_text = ", ".join(exclusion_patterns) if exclusion_patterns else "DEBUG, health, WARN"
    
    prompt = f"""
You are an expert in AWS CloudWatch Insights queries. Generate a CloudWatch Insights query that:

1. Returns fields: @timestamp, @message, @logStream, @log
2. Filters for log messages that contain ANY of these inclusion patterns: {inclusion_text}
3. EXCLUDES log messages that contain ANY of these exclusion patterns: {exclusion_text}
4. Sorts by @timestamp in descending order
5. Limits results to 10000

The query should use CloudWatch Insights syntax with proper filtering using the | filter command.

IMPORTANT: Return ONLY the raw query string without any markdown formatting, code blocks, or explanations.
"""

    logger.info(f"Prompt for query generation: {prompt}")
    
    try:
        resp = client.chat.completions.create(
            model=settings.openai_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,  # Low temperature for consistent query generation
            max_tokens=200,
        )
        
        query = resp.choices[0].message.content.strip()
        
        # Clean up the query - remove markdown code blocks if present
        if query.startswith("```"):
            # Remove markdown code blocks
            lines = query.split('\n')
            query_lines = []
            in_code_block = False
            for line in lines:
                if line.strip().startswith("```"):
                    in_code_block = not in_code_block
                    continue
                if in_code_block:
                    query_lines.append(line)
            query = '\n'.join(query_lines).strip()
        
        logger.info(f"Generated CloudWatch query: {query}")
        return query
        
    except Exception as e:
        logger.error(f"Error generating CloudWatch query: {str(e)}")
        # Fallback to basic query if LLM fails
        fallback_query = "fields @timestamp, @message, @logStream, @log | sort @timestamp desc | limit 10000"
        logger.warning(f"Using fallback query: {fallback_query}")
        return fallback_query
