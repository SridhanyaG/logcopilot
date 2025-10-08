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


def _should_use_strcontains(pattern: str) -> bool:
    """
    Determine if a pattern should use strcontains instead of like.
    
    Args:
        pattern: The pattern to analyze
    
    Returns:
        True if strcontains should be used, False for like
    """
    # Use strcontains for simple words/phrases without special regex characters
    special_chars = ['*', '+', '?', '[', ']', '(', ')', '{', '}', '^', '$', '|', '\\']
    has_special_chars = any(char in pattern for char in special_chars)
    is_simple_phrase = len(pattern.split()) <= 3
    
    should_use_strcontains = not has_special_chars and is_simple_phrase
    logger.info(f"Pattern '{pattern}' analysis: has_special_chars={has_special_chars}, is_simple_phrase={is_simple_phrase}, use_strcontains={should_use_strcontains}")
    
    return should_use_strcontains


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

CRITICAL SYNTAX RULES FOR CLOUDWATCH INSIGHTS:
- Use the EXACT format shown below
- For inclusion: use "or" to combine multiple patterns on separate lines
- For exclusion: use "and" with not() functions on separate lines
- Each pattern should be on its own line with proper indentation
- Choose the right function based on pattern type:
  * Use "strcontains" for simple words/phrases (e.g., "vyudra", "Request data", "user_id")
  * Use "like" with regex for complex patterns (e.g., "Exception", "ERROR", "FATAL")
- For simple patterns without special characters, prefer strcontains
- For error/exception patterns, use like with regex

EXAMPLE FORMATS TO FOLLOW:

1. Error/Exception Detection (using like with regex):
  fields @timestamp, @message, @logStream, @log
  | filter @message like /Exception/ 
    or @message like /ERROR/ 
    or @message like /Error/ 
    or @message like /FATAL/
    or @message like /CRITICAL/
  | filter not(@message like /DEBUG/) 
    and not(@message like /health/) 
    and not(@message like /WARN/)
  | sort @timestamp desc
  | limit 10000

2. NLP/Text Analysis (using strcontains for exact matches):
  fields @timestamp, @message, @logStream, @log
  | filter strcontains(@message, "vyudra")
  | sort @timestamp desc
  | limit 10000

3. Request Data Analysis:
  fields @timestamp, @message, @logStream, @log
  | filter strcontains(@message, "Request data")
  | sort @timestamp desc
  | limit 10000

4. Multiple String Contains:
  fields @timestamp, @message, @logStream, @log
  | filter strcontains(@message, "pattern1") 
    or strcontains(@message, "pattern2")
    or strcontains(@message, "pattern3")
  | filter not strcontains(@message, "exclude1")
    and not strcontains(@message, "exclude2")
  | sort @timestamp desc
  | limit 10000

IMPORTANT: Return ONLY the raw query string without any markdown formatting, code blocks, or explanations. Choose the appropriate format based on the patterns provided.
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
        
        # Additional cleanup - remove any remaining markdown or extra text
        lines = query.split('\n')
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                cleaned_lines.append(line)
        query = '\n'.join(cleaned_lines)
        
        # Validate and potentially fix the query
        # validated_query = _validate_cloudwatch_query(query)
        # logger.info(f"Generated CloudWatch query: {validated_query}")
        return query
        
    except Exception as e:
        logger.error(f"Error generating CloudWatch query: {str(e)}")
        # Fallback to hardcoded query if LLM fails
        fallback_query = """fields @timestamp, @message, @logStream, @log
| filter @message like /Exception/ 
  or @message like /ERROR/ 
  or @message like /Error/ 
  or @message like /FATAL/
  or @message like /CRITICAL/
| filter not(@message like /DEBUG/) 
  and not(@message like /health/) 
  and not(@message like /WARN/)
| sort @timestamp desc
| limit 10000"""
        logger.warning(f"Using hardcoded fallback query: {fallback_query}")
        return fallback_query


def _validate_cloudwatch_query(query: str) -> str:
    """
    Validate and fix common CloudWatch Insights query issues.
    
    Args:
        query: The generated query string
    
    Returns:
        Validated and potentially fixed query string
    """
    logger.info(f"Validating CloudWatch query: {query}")
    
    # If the query is too complex, simplify it
    if "or" in query and query.count("or") > 3:
        logger.warning(f"Query too complex with {query.count('or')} 'or' clauses, simplifying to hardcoded format")
        simplified_query = """fields @timestamp, @message, @logStream, @log
| filter @message like /Exception/ 
  or @message like /ERROR/ 
  or @message like /Error/ 
  or @message like /FATAL/
  or @message like /CRITICAL/
| filter not(@message like /DEBUG/) 
  and not(@message like /health/) 
  and not(@message like /WARN/)
| sort @timestamp desc
| limit 10000"""
        logger.info(f"Using simplified hardcoded query: {simplified_query}")
        return simplified_query
    
    # Ensure proper line breaks
    original_query = query
    query = query.replace(" | ", "\n| ")
    
    if original_query != query:
        logger.info("Fixed line breaks in query")
        logger.info(f"Original: {original_query}")
        logger.info(f"Fixed: {query}")
    
    logger.info(f"Query validation completed: {query}")
    return query


def _generate_simple_cloudwatch_query(inclusion_patterns: List[str], exclusion_patterns: List[str]) -> str:
    """
    Generate a simple, reliable CloudWatch Insights query that's more likely to work.
    
    Args:
        inclusion_patterns: List of patterns to include in the query
        exclusion_patterns: List of patterns to exclude from the query
    
    Returns:
        Simple CloudWatch Insights query string
    """
    logger.info(f"Generating simple CloudWatch query with inclusion: {inclusion_patterns}, exclusion: {exclusion_patterns}")
    
    # Use the most important patterns for error detection
    primary_patterns = ["ERROR", "Exception"]
    logger.info(f"Default primary patterns: {primary_patterns}")
    
    if inclusion_patterns:
        # Use the first two patterns from the list, or fall back to defaults
        if len(inclusion_patterns) >= 2:
            primary_patterns = inclusion_patterns[:2]
            logger.info(f"Using first two inclusion patterns: {primary_patterns}")
        else:
            primary_patterns = inclusion_patterns + ["ERROR"]
            logger.info(f"Using single inclusion pattern plus ERROR: {primary_patterns}")
    else:
        logger.info(f"No inclusion patterns provided, using defaults: {primary_patterns}")
    
    # Build a simple query using the hardcoded format
    logger.info("Building hardcoded simple query with ERROR and Exception patterns")
    query = """fields @timestamp, @message, @logStream, @log
| filter @message like /Exception/ 
  or @message like /ERROR/ 
  or @message like /Error/ 
  or @message like /FATAL/
  or @message like /CRITICAL/
| filter not(@message like /DEBUG/) 
  and not(@message like /health/) 
  and not(@message like /WARN/)
| sort @timestamp desc
| limit 10000"""
    
    logger.info(f"Generated simple CloudWatch query: {query}")
    return query
