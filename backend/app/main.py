import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .analyzer import AnalysisProviderError, MessageAnalysis, analyze_demo, analyze_with_ai
from .config import get_cors_origins, settings
from .url_analyzer import URLAnalysis, analyze_url

logger = logging.getLogger(__name__)
app = FastAPI(title="ScamShield AI API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class MessageAnalysisRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)


class ScreenshotAnalysisRequest(BaseModel):
    extracted_text: str = Field(min_length=1, max_length=20_000)


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8_192)


@app.get("/health", include_in_schema=False)
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "demo_mode": settings.demo_mode,
        "ai_configuration_ready": bool(settings.ai_api_key.strip() and settings.ai_model.strip()),
    }


def _analyze_message_text(message: str) -> MessageAnalysis:
    message = message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Message cannot be blank")
    try:
        analysis = analyze_demo(message) if settings.demo_mode else analyze_with_ai(message)
    except AnalysisProviderError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except Exception as exc:
        logger.error("Unexpected analysis provider failure (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail={"code": "AI_PROVIDER_ERROR", "message": "AI analysis is temporarily unavailable. Check the backend configuration or try again shortly."},
        ) from exc
    return analysis


@app.post("/api/analyze/message", response_model=MessageAnalysis)
def analyze_message(request: MessageAnalysisRequest):
    return _analyze_message_text(request.message)


@app.post("/api/analyze/image", response_model=MessageAnalysis)
def analyze_screenshot(request: ScreenshotAnalysisRequest):
    """Analyze OCR text extracted locally by the frontend; image bytes stay in the browser."""
    return _analyze_message_text(request.extracted_text)


@app.post("/api/analyze/url", response_model=URLAnalysis)
def analyze_submitted_url(request: URLAnalysisRequest):
    try:
        return analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
