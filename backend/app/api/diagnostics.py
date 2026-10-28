
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.diagnostics import diagnose_website

router = APIRouter(prefix="/api/v1/diagnostics", tags=["Diagnostics"])


class DiagnosticRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)


@router.post("")
async def run_diagnostics(payload: DiagnosticRequest):
    try:
        return await diagnose_website(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        # Keep internal exception details out of the public response.
        raise HTTPException(
            status_code=502,
            detail="Diagnostics could not be completed. Please try again.",
        ) from exc
