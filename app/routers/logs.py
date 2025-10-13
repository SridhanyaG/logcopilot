from fastapi import APIRouter, Query
import asyncio

from ..models import ExceptionsResponse, NLQueryRequest, NLQueryResponse, Timeframe
from ..services.aws import get_logs_exceptions
from ..services.llm import summarize_exceptions, summarize_exceptions_async
from ..utils import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/exceptions", response_model=ExceptionsResponse)
def exceptions(hours: int = Query(default=1, ge=1, le=48)):
    logger.info(f"GET /exceptions endpoint called with hours={hours}")
    entries = get_logs_exceptions(hours)
    logger.info(f"Retrieved {len(entries)} exceptions from CloudWatch")
    
    # Generate AI summary if there are exceptions
    summary = ""
    if entries:
        logger.info("Generating AI summary for exceptions using async processing")
        try:
            # Use async processing for better performance with large logs
            summary = asyncio.run(summarize_exceptions_async(entries, max_tokens=3000))
            logger.info(f"AI summary generated successfully, length: {len(summary)} characters")
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
    logger.info(f"POST /nlp endpoint called with query='{req.query}', hours={req.timeframe.hours}")
    # Use enhanced query system that considers user intent in CloudWatch query generation
    # Use NLP-specific patterns for better analysis
    entries = get_logs_exceptions(req.timeframe.hours, user_query=req.query, use_nlp_patterns=True)
    logger.info(f"Retrieved {len(entries)} logs for NLP analysis using user intent and NLP patterns")
    
    logger.info("Generating NLP response for logs using async processing")
    try:
        # Use async processing for better performance with large logs
        answer = asyncio.run(summarize_exceptions_async(entries, max_tokens=3000))
        logger.info(f"NLP response generated successfully, length: {len(answer)} characters")
    except Exception as e:
        logger.error(f"Error generating NLP response: {str(e)}")
        answer = f"Error generating response: {str(e)}"
    
    logger.info(f"Returning NLP response with used_logs={len(entries)}")
    return NLQueryResponse(answer=answer, used_logs=len(entries))
