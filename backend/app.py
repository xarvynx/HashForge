"""
FastAPI application entry point for Password Strength Analyzer.
Provides REST API endpoints for password analysis, generation, and breach checking.
"""
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer import analyze_password_dict, analyze_password
from generator import generate_password, generate_passphrase, generate_pin
from breach_check import check_breach, check_breach_with_count


# Pydantic models for request/response validation
class AnalyzeRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128, description="Password to analyze")
    check_breach: bool = Field(default=True, description="Whether to check HIBP breach database")


class AnalyzeResponse(BaseModel):
    score: int
    strength: str
    entropy: float
    crack_time: dict
    feedback: dict
    breached: bool
    composition: dict


class GenerateRequest(BaseModel):
    length: int = Field(default=20, ge=8, le=128, description="Password length")
    use_uppercase: bool = Field(default=True, description="Include uppercase letters")
    use_lowercase: bool = Field(default=True, description="Include lowercase letters")
    use_digits: bool = Field(default=True, description="Include digits")
    use_symbols: bool = Field(default=True, description="Include symbols")
    exclude_ambiguous: bool = Field(default=False, description="Exclude ambiguous characters")


class GenerateResponse(BaseModel):
    password: str
    entropy: float
    length: int
    composition: dict


class PassphraseRequest(BaseModel):
    word_count: int = Field(default=4, ge=3, le=10, description="Number of words")
    separator: str = Field(default="-", description="Word separator")
    capitalize: bool = Field(default=False, description="Capitalize each word")
    include_number: bool = Field(default=False, description="Append random number")


class BreachCheckRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128, description="Password to check")


class BreachCheckResponse(BaseModel):
    breached: bool
    count: int = 0


class HealthResponse(BaseModel):
    status: str
    version: str


# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: warm up modules
    from constants import load_common_passwords, load_dictionary_words
    load_common_passwords()
    load_dictionary_words()
    yield
    # Shutdown: cleanup if needed


# Create FastAPI app
app = FastAPI(
    title="Password Strength Analyzer API",
    description="Professional-grade password strength analysis with entropy calculation, pattern detection, and breach checking",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="1.0.0")


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze(request: AnalyzeRequest):
    """
    Analyze a password's strength.

    Returns comprehensive analysis including:
    - Score (0-100)
    - Strength label
    - Entropy (bits)
    - Crack time estimates
    - Pattern detection feedback
    - Breach status
    - Character composition
    """
    try:
        result = analyze_password_dict(request.password, request.check_breach)
        return AnalyzeResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/generate", response_model=GenerateResponse, tags=["Generation"])
async def generate(request: GenerateRequest):
    """
    Generate a cryptographically secure random password.

    Uses Python's secrets module (CSPRNG) for maximum security.
    """
    try:
        result = generate_password(
            length=request.length,
            use_uppercase=request.use_uppercase,
            use_lowercase=request.use_lowercase,
            use_digits=request.use_digits,
            use_symbols=request.use_symbols,
            exclude_ambiguous=request.exclude_ambiguous,
        )
        return GenerateResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Generation failed: {str(e)}")


@app.post("/api/generate/passphrase", response_model=GenerateResponse, tags=["Generation"])
async def generate_passphrase_endpoint(request: PassphraseRequest):
    """
    Generate a Diceware-style passphrase.

    More memorable than random passwords, suitable for master passwords.
    """
    try:
        from generator import generate_passphrase
        result = generate_passphrase(
            word_count=request.word_count,
            separator=request.separator,
            capitalize=request.capitalize,
            include_number=request.include_number,
        )
        return GenerateResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Passphrase generation failed: {str(e)}")


@app.post("/api/generate/pin", response_model=GenerateResponse, tags=["Generation"])
async def generate_pin_endpoint(length: int = Query(default=6, ge=4, le=10)):
    """Generate a numeric PIN."""
    try:
        result = generate_pin(length)
        return GenerateResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PIN generation failed: {str(e)}")


@app.post("/api/breach-check", response_model=BreachCheckResponse, tags=["Breach Check"])
async def breach_check(request: BreachCheckRequest):
    """
    Check if a password has been breached using HaveIBeenPwned k-anonymity API.

    Only the first 5 characters of the SHA-1 hash are sent to the API.
    """
    try:
        breached, count = check_breach_with_count(request.password)
        return BreachCheckResponse(breached=breached, count=count)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Breach check failed: {str(e)}")


# Run with: uvicorn app:app --reload --port 5000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)