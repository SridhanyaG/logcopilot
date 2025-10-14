from __future__ import annotations
from typing import List
from datetime import datetime
from openai import OpenAI
import requests
import json
import asyncio
import tiktoken

from ..config import settings
from ..models import VulnerabilityInput, LogEntry
from ..utils import get_logger

logger = get_logger(__name__)


def _count_tokens(text: str, model: str = "gpt-3.5-turbo") -> int:
    """
    Count tokens in text using tiktoken.
    
    Args:
        text: The text to count tokens for
        model: The model to use for token counting (default: gpt-3.5-turbo)
    
    Returns:
        Number of tokens in the text
    """
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except KeyError:
        # Fallback to cl100k_base encoding if model not found
        encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(text))


def _chunk_logs_by_tokens(entries: List[LogEntry], max_tokens: int = 3000) -> List[List[LogEntry]]:
    """
    Chunk log entries based on token count to stay within LLM limits.
    
    Args:
        entries: List of log entries to chunk
        max_tokens: Maximum tokens per chunk (default: 3000, leaving room for prompt)
    
    Returns:
        List of chunks, each containing log entries that fit within token limit
    """
    logger.info(f"Chunking {len(entries)} log entries with max_tokens={max_tokens}")
    
    if not entries:
        return []
    
    chunks = []
    current_chunk = []
    current_tokens = 0
    
    # Base prompt tokens (approximate)
    base_prompt_tokens = 500
    
    for entry in entries:
        # Format entry for token counting
        entry_text = f"[{entry.timestamp.isoformat()}] {entry.message[:2000]}"
        entry_tokens = _count_tokens(entry_text)
        
        # Check if adding this entry would exceed the limit
        if current_tokens + entry_tokens + base_prompt_tokens > max_tokens and current_chunk:
            # Start a new chunk
            chunks.append(current_chunk)
            current_chunk = [entry]
            current_tokens = entry_tokens
        else:
            # Add to current chunk
            current_chunk.append(entry)
            current_tokens += entry_tokens
    
    # Add the last chunk if it has entries
    if current_chunk:
        chunks.append(current_chunk)
    
    logger.info(f"Created {len(chunks)} chunks from {len(entries)} entries")
    for i, chunk in enumerate(chunks):
        logger.info(f"Chunk {i+1}: {len(chunk)} entries")
    
    return chunks


def _client() -> OpenAI:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY not configured")
    return OpenAI(api_key=settings.openai_api_key)


def _call_openai_llm(prompt: str, temperature: float = 0.2, max_tokens: int = 600, operation_name: str = "OpenAI LLM call") -> str:
    """
    Make OpenAI API calls with consistent error handling and logging.
    
    Args:
        prompt: The prompt to send to the LLM
        temperature: Temperature for response generation (default: 0.2)
        max_tokens: Maximum tokens in response (default: 600)
        operation_name: Name of the operation for logging (default: "OpenAI LLM call")
    
    Returns:
        The LLM response content as a string
    
    Raises:
        RuntimeError: If LLM call fails
    """
    logger.info(f"Starting {operation_name}")
    logger.info(f"OpenAI model: {settings.openai_model}")
    logger.info(f"Temperature: {temperature}, Max tokens: {max_tokens}")
    logger.info(f"Prompt length: {len(prompt)} characters")
    
    logger.info("Creating OpenAI client")
    client = _client()
    logger.info("OpenAI client created successfully")
    
    try:
        logger.info("Sending request to OpenAI API")
        resp = client.chat.completions.create(
            model=settings.openai_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        logger.info("Received response from OpenAI API")
        
        logger.info("Extracting content from OpenAI response")
        result = resp.choices[0].message.content.strip()
        logger.info(f"{operation_name} completed successfully, result length: {len(result)} characters")
        logger.info(f"OpenAI response preview: {result[:200]}...")
        return result
        
    except Exception as e:
        logger.error(f"Error in {operation_name}: {str(e)}")
        logger.error(f"OpenAI API call failed with exception type: {type(e).__name__}")
        raise RuntimeError(f"OpenAI LLM call failed for {operation_name}: {str(e)}")


def _call_llm_core_ai(prompt: str, temperature: float = 0.2, max_tokens: int = 600, operation_name: str = "Core AI LLM call") -> str:
    """
    Make Core AI API calls with consistent error handling and logging.
    
    Args:
        prompt: The prompt to send to the LLM
        temperature: Temperature for response generation (default: 0.2)
        max_tokens: Maximum tokens in response (default: 600)
        operation_name: Name of the operation for logging (default: "Core AI LLM call")
    
    Returns:
        The LLM response content as a string
    
    Raises:
        RuntimeError: If LLM call fails
    """
    logger.info(f"Starting {operation_name}")
    logger.info(f"Core AI model: {settings.openai_model}")
    logger.info(f"Temperature: {temperature}, Max tokens: {max_tokens}")
    logger.info(f"Prompt length: {len(prompt)} characters")
    logger.info(f"Core AI URL: {settings.core_ai_url}")
    
    logger.info("Validating Core AI configuration")
    if not settings.core_ai_token or not settings.core_ai_client_id:
        logger.error("Core AI token and client_id not configured")
        logger.error(f"Token present: {bool(settings.core_ai_token)}")
        logger.error(f"Client ID present: {bool(settings.core_ai_client_id)}")
        raise RuntimeError("Core AI token and client_id not configured")
    logger.info("Core AI configuration validation passed")
    
    logger.info("Preparing Core AI request headers")
    headers = {
        "Authorization": f"Bearer {settings.core_ai_token}",
        "x-client-id": settings.core_ai_client_id,
        "Content-Type": "application/json",
    }
    logger.info("Core AI request headers prepared")
    logger.info(f"Authorization header present: {bool(headers.get('Authorization'))}")
    logger.info(f"Client ID header present: {bool(headers.get('x-client-id'))}")
    
    logger.info("Preparing Core AI request data")
    data = {
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "model": settings.openai_model,  # Use the same model setting
        "temperature": temperature,
        "max_tokens": max_tokens
    }
    logger.info("Core AI request data prepared")
    logger.info(f"Request data keys: {list(data.keys())}")
    logger.info(f"Number of messages: {len(data['messages'])}")
    
    try:
        logger.info(f"Calling Core AI API at {settings.core_ai_url}")
        logger.info("Sending POST request to Core AI")
        response = requests.post(settings.core_ai_url, headers=headers, data=json.dumps(data))
        logger.info(f"Received response from Core AI API with status code: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Core AI API returned status {response.status_code}")
            logger.error(f"Response headers: {dict(response.headers)}")
            logger.error(f"Response text: {response.text}")
            raise RuntimeError(f"Core AI API call failed with status {response.status_code}")
        
        logger.info("Core AI API call successful, parsing JSON response")
        result_data = response.json()
        logger.info("JSON response parsed successfully")
        logger.info(f"Response data keys: {list(result_data.keys())}")
        
        # Extract the content from Core AI response format
        logger.info("Extracting content from Core AI response")
        if 'choices' in result_data and len(result_data['choices']) > 0:
            logger.info(f"Found {len(result_data['choices'])} choices in response")
            result = result_data['choices'][0]['message']['content'].strip()
            logger.info("Content extracted successfully from Core AI response")
        else:
            logger.error(f"Unexpected Core AI response format: {result_data}")
            logger.error("No choices found in Core AI response")
            raise RuntimeError("Unexpected Core AI response format")
        
        logger.info(f"{operation_name} completed successfully, result length: {len(result)} characters")
        logger.info(f"Core AI response preview: {result[:200]}...")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error in {operation_name}: {str(e)}")
        logger.error(f"Request exception type: {type(e).__name__}")
        raise RuntimeError(f"Core AI network error for {operation_name}: {str(e)}")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {operation_name}: {str(e)}")
        logger.error(f"Response text that failed to decode: {response.text if 'response' in locals() else 'No response available'}")
        raise RuntimeError(f"Core AI JSON decode error for {operation_name}: {str(e)}")
    except Exception as e:
        logger.error(f"Error in {operation_name}: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        raise RuntimeError(f"Core AI call failed for {operation_name}: {str(e)}")


async def _call_llm_async(prompt: str, temperature: float = 0.2, max_tokens: int = 4096, operation_name: str = "Async LLM call") -> str:
    """
    Async version of LLM call for parallel processing.
    
    Args:
        prompt: The prompt to send to the LLM
        temperature: Temperature for response generation (default: 0.2)
        max_tokens: Maximum tokens in response (default: 4096)
        operation_name: Name of the operation for logging (default: "Async LLM call")
    
    Returns:
        The LLM response content as a string
    
    Raises:
        RuntimeError: If LLM call fails
    """
    logger.info(f"Starting async {operation_name}")
    logger.info(f"LLM provider configured: {settings.llm_provider}")
    logger.info(f"Temperature: {temperature}, Max tokens: {max_tokens}")
    logger.info(f"Prompt length: {len(prompt)} characters")
    
    if settings.llm_provider == "core_ai":
        logger.info("Routing to Core AI provider (async)")
        # For Core AI, we'll run the sync function in a thread pool
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _call_llm_core_ai, prompt, temperature, max_tokens, operation_name)
        logger.info("Async Core AI call completed successfully")
        return result
    else:
        logger.info("Routing to OpenAI provider (async)")
        # For OpenAI, we'll run the sync function in a thread pool
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _call_openai_llm, prompt, temperature, max_tokens, operation_name)
        logger.info("Async OpenAI call completed successfully")
        return result


def _call_llm(prompt: str, temperature: float = 0.2, max_tokens: int = 4096, operation_name: str = "LLM call") -> str:
    """
    Common function to make LLM API calls with feature switch between OpenAI and Core AI.
    
    Args:
        prompt: The prompt to send to the LLM
        temperature: Temperature for response generation (default: 0.2)
        max_tokens: Maximum tokens in response (default: 600)
        operation_name: Name of the operation for logging (default: "LLM call")
    
    Returns:
        The LLM response content as a string
    
    Raises:
        RuntimeError: If LLM call fails
    """
    logger.info(f"Starting LLM call routing for operation: {operation_name}")
    logger.info(f"LLM provider configured: {settings.llm_provider}")
    logger.info(f"Available providers: ['openai', 'core_ai']")
    logger.info(f"Temperature: {temperature}, Max tokens: {max_tokens}")
    logger.info(f"Prompt length: {len(prompt)} characters")
    
    if settings.llm_provider == "core_ai":
        logger.info("Routing to Core AI provider")
        logger.info("Calling _call_llm_core_ai function")
        result = _call_llm_core_ai(prompt, temperature, max_tokens, operation_name)
        logger.info("Core AI call completed successfully")
        return result
    else:
        logger.info("Routing to OpenAI provider (default)")
        logger.info("Calling _call_openai_llm function")
        result = _call_openai_llm(prompt, temperature, max_tokens, operation_name)
        logger.info("OpenAI call completed successfully")
        return result


def suggest_remediation(vuln: VulnerabilityInput, repo: str | None, branch: str | None,
                        release: str | None, requirements_text: str | None, 
                        nvd_data: dict | None = None) -> str:
    logger.info(f"Generating remediation suggestion for vulnerability: {vuln.name}")
    
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
    
    return _call_llm(prompt, temperature=0.2, max_tokens=600, operation_name="remediation suggestion generation")


async def _summarize_chunk_async(chunk: List[LogEntry], chunk_index: int) -> str:
    """
    Summarize a single chunk of log entries asynchronously.
    
    Args:
        chunk: List of log entries to summarize
        chunk_index: Index of the chunk for logging purposes
    
    Returns:
        Summary of the chunk
    """
    logger.info(f"Starting async summarization for chunk {chunk_index} with {len(chunk)} entries")
    
    if not chunk:
        return "No entries in this chunk."
    
    joined = "\n\n".join(
        f"[{e.timestamp.isoformat()}] {e.message[:2000]}" for e in chunk
    )
    logger.info(f"Chunk {chunk_index} joined log entries, total length: {len(joined)} characters")
    
    prompt = f"""Analyze the log entries below and provide a comprehensive summary in markdown format. The logs may contain exceptions, errors, INFO messages, API responses, or other types of entries.

REQUIRED OUTPUT FORMAT (return as a single markdown string):

## Summary
Provide a brief overview of what was found in the logs.

## Log Entry Types
List the different types of log entries found (e.g., exceptions, INFO messages, API responses, etc.) with their counts.

## Exception Analysis (if any exceptions found)
If exceptions or errors are present, create a table grouping them:

| Exception Type | Count | Root Cause | Affected Components |
|---|---|---|---|
| [Exception name] | [count] | [brief cause] | [components] |

## API Endpoint Performance (if API calls found)
If API endpoints are mentioned, create a table showing performance:

| Endpoint | Method | Response Time | Status | Count |
|---|---|---|---|---|
| [endpoint] | [GET/POST/etc] | [time] | [status] | [count] |

## Key Findings
- List important observations
- Performance issues
- Error patterns
- Success patterns

## Recommendations
- Immediate actions needed
- Monitoring suggestions
- Performance optimizations

Logs to analyze:
{joined}

CRITICAL REQUIREMENTS:
- Return the entire response as a single markdown-formatted string
- Use proper markdown syntax for headers (##), tables (|), and lists (-)
- Do NOT include any code blocks, backticks, or special formatting markers
- If no exceptions are found, focus on other log types (INFO, API responses, etc.)
- Extract actual endpoint URLs, response times, and status codes when available
- Group similar exceptions together
- Provide actionable recommendations
- Ensure the output is a clean markdown string that can be directly rendered
"""
    
    try:
        result = await _call_llm_async(prompt, temperature=0.2, max_tokens=1200, operation_name=f"chunk {chunk_index} analysis")
        logger.info(f"Chunk {chunk_index} analysis completed successfully, result length: {len(result)} characters")
        return result
    except Exception as e:
        logger.error(f"Error analyzing chunk {chunk_index}: {str(e)}")
        return f"Error analyzing chunk {chunk_index}: {str(e)}"


async def summarize_exceptions_async(entries: List[LogEntry], max_tokens: int = 3000) -> str:
    """
    Summarize exceptions using async processing with token-based chunking.
    
    Args:
        entries: List of log entries to summarize
        max_tokens: Maximum tokens per chunk (default: 3000)
    
    Returns:
        Combined summary of all chunks
    """
    logger.info(f"Starting async log analysis for {len(entries)} entries with max_tokens={max_tokens}")
    
    if not entries:
        logger.info("No entries to summarize, returning default message")
        return "No log entries found in the selected timeframe."
    
    # Chunk the entries based on token count
    chunks = _chunk_logs_by_tokens(entries, max_tokens)
    
    if len(chunks) == 1:
        logger.info("Single chunk detected, processing directly")
        return await _summarize_chunk_async(chunks[0], 0)
    
    logger.info(f"Processing {len(chunks)} chunks in parallel")
    
    # Process all chunks in parallel
    chunk_tasks = [
        _summarize_chunk_async(chunk, i) 
        for i, chunk in enumerate(chunks)
    ]
    
    try:
        chunk_summaries = await asyncio.gather(*chunk_tasks, return_exceptions=True)
        logger.info(f"All {len(chunk_summaries)} chunks processed")
        
        # Filter out any exceptions and log them
        valid_summaries = []
        for i, summary in enumerate(chunk_summaries):
            if isinstance(summary, Exception):
                logger.error(f"Chunk {i} failed with exception: {str(summary)}")
                valid_summaries.append(f"Chunk {i} processing failed: {str(summary)}")
            else:
                valid_summaries.append(summary)
        
        if not valid_summaries:
            logger.error("All chunks failed to process")
            return "Error: All log chunks failed to process."
        
        # Combine chunk summaries
        logger.info(f"Combining {len(valid_summaries)} chunk summaries")
        combined_summary = await _combine_chunk_summaries(valid_summaries)
        
        logger.info(f"Async log analysis completed successfully, final summary length: {len(combined_summary)} characters")
        return combined_summary
        
    except Exception as e:
        logger.error(f"Error in async chunk processing: {str(e)}")
        return f"Error processing log chunks: {str(e)}"


async def _combine_chunk_summaries(chunk_summaries: List[str]) -> str:
    """
    Combine multiple chunk summaries into a final comprehensive summary.
    
    Args:
        chunk_summaries: List of summaries from individual chunks
    
    Returns:
        Combined summary
    """
    logger.info(f"Combining {len(chunk_summaries)} chunk summaries")
    
    if len(chunk_summaries) == 1:
        return chunk_summaries[0]
    
    # Join all chunk summaries
    combined_text = "\n\n--- CHUNK SEPARATOR ---\n\n".join(chunk_summaries)
    logger.info(f"Combined text length: {len(combined_text)} characters")
    
    prompt = f"""You are analyzing multiple summaries of log entries that were processed in chunks. Combine these summaries into a single, comprehensive analysis.

REQUIRED OUTPUT FORMAT (return as a single markdown string):

## Overall Summary
Provide a high-level overview combining insights from all chunks.

## Log Entry Types (Combined)
Aggregate the different types of log entries found across all chunks with their total counts.

## Exception Analysis (Combined)
If exceptions or errors are present across chunks, create a unified table:

| Exception Type | Total Count | Root Cause | Affected Components |
|---|---|---|---|
| [Exception name] | [total count] | [brief cause] | [components] |

## API Endpoint Performance (Combined)
If API endpoints are mentioned across chunks, create a unified performance table:

| Endpoint | Method | Avg Response Time | Status Distribution | Total Count |
|---|---|---|---|---|
| [endpoint] | [GET/POST/etc] | [avg time] | [status breakdown] | [total count] |

## Key Findings (Combined)
- Aggregate important observations from all chunks
- Cross-chunk patterns and trends
- Performance issues identified
- Error patterns and frequency
- Success patterns

## Recommendations (Prioritized)
- Immediate actions needed (based on severity across chunks)
- Monitoring suggestions
- Performance optimizations
- System-wide improvements

Chunk summaries to combine:
{combined_text}

CRITICAL REQUIREMENTS:
- Return the entire response as a single markdown-formatted string
- Use proper markdown syntax for headers (##), tables (|), and lists (-)
- Do NOT include any code blocks, backticks, or special formatting markers
- Aggregate counts and metrics across all chunks
- Identify patterns that span multiple chunks
- Prioritize recommendations based on frequency and severity
- Ensure the output is a clean markdown string that can be directly rendered
"""
    
    try:
        result = await _call_llm_async(prompt, temperature=0.2, max_tokens=2000, operation_name="chunk summary combination")
        logger.info(f"Chunk combination completed successfully, result length: {len(result)} characters")
        return result
    except Exception as e:
        logger.error(f"Error combining chunk summaries: {str(e)}")
        # Fallback: return a simple combination
        return f"## Combined Analysis\n\n" + "\n\n".join(f"### Chunk {i+1}\n{summary}" for i, summary in enumerate(chunk_summaries))


def summarize_exceptions(entries: List[LogEntry]) -> str:
    """
    Synchronous wrapper for the async summarization function.
    This maintains backward compatibility while providing the new async functionality.
    """
    logger.info(f"Starting synchronous log analysis for {len(entries)} entries")
    
    if not entries:
        logger.info("No entries to summarize, returning default message")
        return "No log entries found in the selected timeframe."
    
    # Check if we need chunking by estimating token count
    total_text = "\n\n".join(f"[{e.timestamp.isoformat()}] {e.message[:2000]}" for e in entries[:100])  # Sample first 100
    estimated_tokens = _count_tokens(total_text) * (len(entries) / min(100, len(entries)))
    
    if estimated_tokens > 3000:
        logger.info(f"Large log set detected (estimated {estimated_tokens} tokens), using async chunking")
        # Use async processing for large logs
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(summarize_exceptions_async(entries))
            return result
        finally:
            loop.close()
    else:
        logger.info(f"Small log set detected (estimated {estimated_tokens} tokens), using direct processing")
        # Use original processing for small logs
        entries_to_process = entries[:1000]
        logger.info(f"Processing {len(entries_to_process)} entries for analysis")
        
        joined = "\n\n".join(
            f"[{e.timestamp.isoformat()}] {e.message[:2000]}" for e in entries_to_process
        )
        logger.info(f"Joined log entries, total length: {len(joined)} characters")
        
        prompt = f"""Analyze the log entries below and provide a comprehensive summary in markdown format. The logs may contain exceptions, errors, INFO messages, API responses, or other types of entries.

REQUIRED OUTPUT FORMAT (return as a single markdown string):

## Summary
Provide a brief overview of what was found in the logs.

## Log Entry Types
List the different types of log entries found (e.g., exceptions, INFO messages, API responses, etc.) with their counts.

## Exception Analysis (if any exceptions found)
If exceptions or errors are present, create a table grouping them:

| Exception Type | Count | Root Cause | Affected Components |
|---|---|---|---|
| [Exception name] | [count] | [brief cause] | [components] |

## API Endpoint Performance (if API calls found)
If API endpoints are mentioned, create a table showing performance:

| Endpoint | Method | Response Time | Status | Count |
|---|---|---|---|---|
| [endpoint] | [GET/POST/etc] | [time] | [status] | [count] |

## Key Findings
- List important observations
- Performance issues
- Error patterns
- Success patterns

## Recommendations
- Immediate actions needed
- Monitoring suggestions
- Performance optimizations

Logs to analyze:
{joined}

CRITICAL REQUIREMENTS:
- Return the entire response as a single markdown-formatted string
- Use proper markdown syntax for headers (##), tables (|), and lists (-)
- Do NOT include any code blocks, backticks, or special formatting markers
- If no exceptions are found, focus on other log types (INFO, API responses, etc.)
- Extract actual endpoint URLs, response times, and status codes when available
- Group similar exceptions together
- Provide actionable recommendations
- Ensure the output is a clean markdown string that can be directly rendered
"""
        
        result = _call_llm(prompt, temperature=0.2, max_tokens=1200, operation_name="log analysis")
        logger.info(f"Log analysis result:\n{result}")
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


def _generate_cloudwatch_query(inclusion_patterns: List[str], exclusion_patterns: List[str], user_query: str = None, start_time: datetime = None, end_time: datetime = None) -> str:
    """
    Generate a CloudWatch Insights query using LLM based on inclusion and exclusion patterns.
    
    Args:
        inclusion_patterns: List of patterns to include in the query
        exclusion_patterns: List of patterns to exclude from the query
        user_query: Optional user natural language query for additional context
        start_time: Optional start time for time range filtering
        end_time: Optional end time for time range filtering
    
    Returns:
        CloudWatch Insights query string
    """
    logger.info(f"Generating CloudWatch query with inclusion: {inclusion_patterns}, exclusion: {exclusion_patterns}")
    if user_query:
        logger.info(f"User query provided: '{user_query}'")
    
    # Build the prompt for query generation
    inclusion_text = ", ".join(inclusion_patterns) if inclusion_patterns else "Exception, ERROR, Error, FATAL, CRITICAL"
    exclusion_text = ", ".join(exclusion_patterns) if exclusion_patterns else "DEBUG, health, WARN"
    
    # Add user query context to the prompt
    user_query_context = ""
    if user_query:
        user_query_context = f"""
IMPORTANT: The user has asked: "{user_query}"

Based on this user query, you should:
1. Include the base patterns: {inclusion_text}
2. Additionally include patterns relevant to the user's intent 
3. Consider what the user is specifically looking for and add relevant patterns

"""
    
    # Add time range filter if provided
    time_filter = ""
    if start_time and end_time:
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        time_filter = f"| filter @timestamp >= fromMillis({start_ms}) and @timestamp <= fromMillis({end_ms})"
    
    prompt = f"""
You are an expert in AWS CloudWatch Insights queries. Generate a CloudWatch Insights query that:

1. Returns fields: @timestamp, @message, @logStream, @log
2. MUST include ALL of these inclusion patterns: {inclusion_text}
3. EXCLUDES log messages that contain ANY of these exclusion patterns: {exclusion_text}
4. Filters by K8s workload: @entity.Attributes.K8s.Workload = 'gen-ai-bodhi-content-experiment'
5. Sorts by @timestamp in descending order
6. Limits results to 10000
{f"7. Filters by time range: {start_time} to {end_time}" if start_time and end_time else ""}

{user_query_context}

CRITICAL REQUIREMENTS:
- You MUST include ALL provided inclusion patterns in the query
- Do NOT skip or omit any inclusion patterns
- For each inclusion pattern, choose the appropriate function:
  * Use "strcontains" for simple words/phrases without special regex characters (e.g., "INFO", "200 ok", "user_id")
  * Use "like" with regex for patterns with special characters or error patterns (e.g., "Exception", "ERROR", "FATAL")
- Combine all inclusion patterns with "or" on separate lines
- Combine all exclusion patterns with "and" on separate lines
{f"- MUST include time range filter using fromMillis() and epoch milliseconds: @timestamp >= fromMillis({int(start_time.timestamp() * 1000)}) and @timestamp <= fromMillis({int(end_time.timestamp() * 1000)})" if start_time and end_time else ""}

REQUIRED FORMAT:
fields @timestamp, @message, @logStream, @log
{time_filter}
| filter [ALL INCLUSION PATTERNS HERE - ONE PER LINE WITH "or"]
| filter [ALL EXCLUSION PATTERNS HERE - ONE PER LINE WITH "and"]
| sort @timestamp desc
| limit 10000

EXAMPLE with your exact patterns{f" and time range {start_time} to {end_time}" if start_time and end_time else ""}:
fields @timestamp, @message, @logStream, @log
{time_filter}
| filter @message like /Exception/
  or @message like /ERROR/
  or @message like /Error/
  or @message like /FATAL/
  or @message like /CRITICAL/
  or strcontains(@message, "INFO")
  or strcontains(@message, "200 ok")
| filter not(@message like /DEBUG/)
  and not(@message like /health/)
  and not(@message like /WARN/)
| sort @timestamp desc
| limit 10000

IMPORTANT: 
- Include ALL inclusion patterns: {inclusion_text}
- Add the user query phrase if relevant: "{user_query}"
- Return ONLY the raw query string without any markdown formatting, code blocks, or explanations
"""

    try:
        query = _call_llm(prompt, temperature=0.1, max_tokens=200, operation_name="CloudWatch query generation")
        
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
        
        return query
        
    except Exception as e:
        logger.error(f"Error generating CloudWatch query: {str(e)}")
        # Fallback to hardcoded query if LLM fails
        fallback_query = f"""fields @timestamp, @message, @logStream, @log
{time_filter}
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


def _generate_simple_cloudwatch_query(inclusion_patterns: List[str], exclusion_patterns: List[str], start_time: datetime = None, end_time: datetime = None) -> str:
    """
    Generate a simple, reliable CloudWatch Insights query that's more likely to work.
    
    Args:
        inclusion_patterns: List of patterns to include in the query
        exclusion_patterns: List of patterns to exclude from the query
        start_time: Optional start time for time range filtering
        end_time: Optional end time for time range filtering
    
    Returns:
        Simple CloudWatch Insights query string
    """
    logger.info(f"Generating simple CloudWatch query with inclusion: {inclusion_patterns}, exclusion: {exclusion_patterns}")
    
    # Use provided patterns or fall back to defaults
    if inclusion_patterns:
        logger.info(f"Using provided inclusion patterns: {inclusion_patterns}")
        use_patterns = inclusion_patterns
    else:
        use_patterns = ["ERROR", "Exception"]
        logger.info(f"No inclusion patterns provided, using defaults: {use_patterns}")
    
    # Build inclusion filter
    inclusion_filters = []
    for pattern in use_patterns:
        if _should_use_strcontains(pattern):
            inclusion_filters.append(f'strcontains(@message, "{pattern}")')
        else:
            inclusion_filters.append(f'@message like /{pattern}/')
    
    inclusion_filter_str = "\n  or ".join(inclusion_filters)
    
    # Build exclusion filter
    exclusion_filters = []
    if exclusion_patterns:
        for pattern in exclusion_patterns:
            if _should_use_strcontains(pattern):
                exclusion_filters.append(f'not strcontains(@message, "{pattern}")')
            else:
                exclusion_filters.append(f'not(@message like /{pattern}/)')
    
    if exclusion_filters:
        exclusion_filter_str = "\n  and ".join(exclusion_filters)
    else:
        # Default exclusions if none provided
        exclusion_filter_str = """not(@message like /DEBUG/) 
  and not(@message like /health/) 
  and not(@message like /WARN/)"""
    
    # Add time range filter if provided
    time_filter = ""
    if start_time and end_time:
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        time_filter = f"| filter @timestamp >= fromMillis({start_ms}) and @timestamp <= fromMillis({end_ms})\n"
    
    # Build the complete query
    query = f"""fields @timestamp, @message, @logStream, @log
{time_filter}| filter {inclusion_filter_str}
| filter {exclusion_filter_str}
| sort @timestamp desc
| limit 10000"""
    
    logger.info(f"Generated simple CloudWatch query: {query}")
    return query
