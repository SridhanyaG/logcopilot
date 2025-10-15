from fastapi import APIRouter, Query, HTTPException
import asyncio

from ..models import ExceptionsResponse, NLQueryRequest, NLQueryResponse, Timeframe
from ..services.aws import get_logs_exceptions
from ..services.llm import summarize_exceptions, summarize_exceptions_async
from ..utils import get_logger

def log_markdown_red(markdown_text: str):
    """Log markdown text in red color for better visibility"""
    # ANSI escape codes for red color
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Format the markdown text with red color and bold
    formatted_text = f"{RED}{BOLD}{markdown_text}{RESET}"
    logger.info(f"\n{formatted_text}\n")

logger = get_logger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/exceptions", response_model=ExceptionsResponse)
def exceptions(
    hours: int = Query(default=None, ge=1, le=48), 
    minutes: int = Query(default=None, ge=1, le=2880),
    start_time: str = Query(default=None, description="Start time in ISO format"),
    end_time: str = Query(default=None, description="End time in ISO format"),
    podname: str = Query(default=None, description="Pod/workload name to filter by")
):
    # Validate mutual exclusivity
    # Check if any of the individual time parameters are provided
    has_hours = hours is not None
    has_minutes = minutes is not None
    has_start_time = start_time is not None
    has_end_time = end_time is not None
    
    # Count how many different time parameter types are provided
    time_param_count = sum([has_hours, has_minutes, has_start_time or has_end_time])
    
    if time_param_count > 1:
        raise HTTPException(
            status_code=400,
            detail="Only one time parameter can be provided: hours, minutes, or start_time/end_time pair"
        )
    
    if start_time and not end_time:
        raise HTTPException(
            status_code=400,
            detail="Both start_time and end_time must be provided together"
        )
    
    if end_time and not start_time:
        raise HTTPException(
            status_code=400,
            detail="Both start_time and end_time must be provided together"
        )

    logger.info(f"GET /exceptions endpoint called with hours={hours}, minutes={minutes}, start_time={start_time}, end_time={end_time}, podname={podname}")
    try:
        entries = get_logs_exceptions(hours=hours, minutes=minutes, start_time=start_time, end_time=end_time, podname=podname)
    except Exception as e:
        logger.error(f"Error in get_logs_exceptions: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    logger.info(f"Retrieved {len(entries)} exceptions from CloudWatch")
    
    # Generate AI summary if there are exceptions
    summary = ""
    if entries:
        logger.info("Generating AI summary for exceptions using async processing")
        try:
            # Use async processing for better performance with large logs
            summary = asyncio.run(summarize_exceptions_async(entries, max_tokens=3000))
            logger.info(f"AI summary generated successfully, length: {len(summary)} characters")
            # Display the markdown summary in red color
            log_markdown_red(summary)
        except Exception as e:
            logger.error(f"Error generating AI summary: {str(e)}")
            summary = f"Error generating summary: {str(e)}"
    else:
        logger.info("No exceptions found, skipping AI summary generation")
    
    # Create response with count, exceptions, and summary
    logger.info(f"Returning response with count={len(entries)}, summary_length={len(summary)}")
    return ExceptionsResponse(count=len(entries), exceptions=entries, summary=summary)


@router.post("/nlp", response_model=NLQueryResponse)
def nlp_summarize(req: NLQueryRequest):
    # Validate mutual exclusivity for time parameters
    has_hours = req.timeframe.hours is not None and req.timeframe.hours > 0
    has_minutes = req.timeframe.minutes is not None and req.timeframe.minutes > 0
    has_start_time = req.start_time is not None
    has_end_time = req.end_time is not None
    
    # Count how many different time parameter types are provided
    time_param_count = sum([has_hours, has_minutes, has_start_time or has_end_time])
    
    if time_param_count > 1:
        raise HTTPException(
            status_code=400,
            detail="Only one time parameter can be provided: hours, minutes, or start_time/end_time pair"
        )
    
    if req.start_time and not req.end_time:
        raise HTTPException(
            status_code=400,
            detail="Both start_time and end_time must be provided together"
        )
    
    if req.end_time and not req.start_time:
        raise HTTPException(
            status_code=400,
            detail="Both start_time and end_time must be provided together"
        )

    logger.info(f"POST /nlp endpoint called with query='{req.query}', hours={req.timeframe.hours}, minutes={req.timeframe.minutes}, start_time={req.start_time}, end_time={req.end_time}, podname={req.podname}")
    
    # Use enhanced query system that considers user intent in CloudWatch query generation
    # Use NLP-specific patterns for better analysis
    entries = get_logs_exceptions(
        hours=req.timeframe.hours, 
        minutes=req.timeframe.minutes, 
        start_time=req.start_time,
        end_time=req.end_time,
        podname=req.podname,
        user_query=req.query, 
        use_nlp_patterns=True
    )
    logger.info(f"Retrieved {len(entries)} logs for NLP analysis using user intent and NLP patterns")
    
    logger.info("Generating NLP response for logs using async processing")
    try:
        # Use async processing for better performance with large logs
        answer = asyncio.run(summarize_exceptions_async(entries, max_tokens=3000, user_query=req.query))
        logger.info(f"NLP response generated successfully, length: {len(answer)} characters")
        # Display the markdown response in red color
        log_markdown_red(answer)
    except Exception as e:
        logger.error(f"Error generating NLP response: {str(e)}")
        answer = f"Error generating response: {str(e)}"
    
    logger.info(f"Returning NLP response with used_logs={len(entries)}")
    return NLQueryResponse(answer=answer, used_logs=len(entries))
