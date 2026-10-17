"""
FastAPI Application — Number Porting Anomaly Detection Service
=============================================================
Endpoints:
  POST /api/v1/detect          — single request analysis
  POST /api/v1/detect/batch    — batch analysis (up to 100 records)
  GET  /api/v1/detections/{id} — retrieve a past detection by ID
  GET  /api/v1/health          — liveness probe
  GET  /api/v1/metrics         — aggregated detection statistics

Security controls applied at this layer:
  - API key authentication (header: X-API-Key)
  - Rate limiting per client key
  - Request size limit enforcement
  - Structured access logging on every request
  - No PII in response bodies (customer_id_hash only)
"""

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import (
    FastAPI, Depends, HTTPException, Request,
    Security, status, BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from agents.anomaly_detector import AnomalyDetectorAgent
from models.schemas import (
    PortingRequest, AnomalyResult, BatchResult, HealthResponse
)
from db.result_store import ResultStore
from db.metrics_store import MetricsStore
from security.api_key_manager import APIKeyManager
from config.settings import Settings

# ── Initialisation ─────────────────────────────────────────────────────────────

settings      = Settings()
agent         = AnomalyDetectorAgent()
result_store  = ResultStore()
metrics_store = MetricsStore()
key_manager   = APIKeyManager()
logger        = logging.getLogger(__name__)
limiter       = Limiter(key_func=get_remote_address)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Port Anomaly Detection Service starting", extra={"version": settings.app_version})
    yield
    logger.info("Port Anomaly Detection Service stopping")


app = FastAPI(
    title="Number Porting Anomaly Detection API",
    version=settings.app_version,
    description="Detects deal-hopping and fraud patterns in number porting requests.",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.environment != "production" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.environment != "production" else None,
)

# ── Middleware ─────────────────────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["X-API-Key", "Content-Type"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)


# ── Access logging middleware ──────────────────────────────────────────────────

@app.middleware("http")
async def access_log(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    logger.info(
        "Request received",
        extra={
            "request_id": request_id,
            "method":     request.method,
            "path":       request.url.path,
            "client_ip":  request.client.host if request.client else "unknown",
        },
    )
    response = await call_next(request)
    logger.info(
        "Request completed",
        extra={
            "request_id":  request_id,
            "status_code": response.status_code,
        },
    )
    return response


# ── Authentication dependency ──────────────────────────────────────────────────

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    if not key_manager.is_valid(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key.",
        )
    return api_key


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", response_model=HealthResponse, tags=["Operations"])
async def health():
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        model=settings.model_name,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post(
    "/api/v1/detect",
    response_model=AnomalyResult,
    tags=["Detection"],
    summary="Analyse a single porting request for anomalies",
)
@limiter.limit(settings.rate_limit_single)
async def detect_single(
    request: Request,
    payload: PortingRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
) -> AnomalyResult:
    """
    Runs the full four-layer anomaly detection pipeline on a single
    porting request. Returns a structured risk assessment.
    Customer PII is never included in the response — only a
    one-way hash of the customer_id is returned.
    """
    try:
        result = agent.run(payload.dict())
        background_tasks.add_task(result_store.save, result)
        background_tasks.add_task(metrics_store.record, result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except RuntimeError as exc:
        logger.exception("Detection pipeline error")
        raise HTTPException(status_code=500, detail="Detection service error.")


@app.post(
    "/api/v1/detect/batch",
    response_model=BatchResult,
    tags=["Detection"],
    summary="Analyse a batch of porting requests (max 100)",
)
@limiter.limit(settings.rate_limit_batch)
async def detect_batch(
    request: Request,
    payloads: list[PortingRequest],
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
) -> BatchResult:
    if len(payloads) > 100:
        raise HTTPException(
            status_code=413,
            detail="Batch size exceeds maximum of 100 records.",
        )
    results = []
    for p in payloads:
        try:
            results.append(agent.run(p.dict()))
        except Exception as exc:
            logger.error("Batch item failed", extra={"error": str(exc)})

    batch = BatchResult(
        batch_id=str(uuid.uuid4()),
        processed_at=datetime.now(timezone.utc).isoformat(),
        total_submitted=len(payloads),
        total_anomalies=sum(1 for r in results if r.is_anomaly),
        total_blocked=sum(1 for r in results if r.recommended_action == "BLOCK_PROMOTION"),
        results=results,
    )
    background_tasks.add_task(result_store.save_batch, batch)
    return batch


@app.get(
    "/api/v1/detections/{detection_id}",
    response_model=AnomalyResult,
    tags=["Detection"],
    summary="Retrieve a past detection result by ID",
)
async def get_detection(
    detection_id: str,
    api_key: str = Depends(verify_api_key),
) -> AnomalyResult:
    result = await result_store.fetch(detection_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Detection not found.")
    return result


@app.get(
    "/api/v1/metrics",
    tags=["Operations"],
    summary="Aggregated detection statistics",
)
async def get_metrics(api_key: str = Depends(verify_api_key)) -> dict:
    return await metrics_store.summary()
