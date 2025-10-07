from fastapi import APIRouter, Query

from ..models import ExceptionsResponse, NLQueryRequest, NLQueryResponse, Timeframe
from ..services.aws import get_logs_exceptions
from ..services.llm import summarize_exceptions
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
        logger.info("Generating AI summary for exceptions")
        try:
            summary = summarize_exceptions(entries)
            logger.info(f"AI summary generated successfully, length: {len(summary)} characters")
        except Exception as e:
            logger.error(f"Error generating AI summary: {str(e)}")
            summary = f"Error generating summary: {str(e)}"
    else:
        logger.info("No exceptions found, skipping AI summary generation")
    
    # Create response with count, exceptions, and summary
    # return ExceptionsResponse(count=len(entries), exceptions=entries, summary=summary)
    logger.info(f"Returning response with count={len(entries)}, summary_length={len(summary)}")
    return ExceptionsResponse(count=len(entries), exceptions=[], summary=summary)


@router.post("/nlp", response_model=NLQueryResponse)
def nlp_summarize(req: NLQueryRequest):
    logger.info(f"POST /nlp endpoint called with query='{req.query}', hours={req.timeframe.hours}")
    # Minimal MVP: ignore NL query and summarize exceptions for the timeframe
    entries = get_logs_exceptions(req.timeframe.hours)
    logger.info(f"Retrieved {len(entries)} exceptions for NLP analysis")
    
    logger.info("Generating NLP response for exceptions")
    answer = summarize_exceptions(entries)
    logger.info(f"NLP response generated successfully, length: {len(answer)} characters")
    
    logger.info(f"Returning NLP response with used_logs={len(entries)}")
    return NLQueryResponse(answer=answer, used_logs=len(entries))
