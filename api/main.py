from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.privacy_scrubber import PrivacyScrubber
from services.risk_scorer import score_email
from models.email_detector import EmailPhishingDetector

app = FastAPI(title="AI Fraud Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Load once at startup
scrubber = PrivacyScrubber()
detector = EmailPhishingDetector()


class EmailRequest(BaseModel):
    subject: str
    body: str


@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze/email")
def analyze_email(req: EmailRequest):
    scrubbed_subject, _             = scrubber.scrub(req.subject)
    scrubbed_body,    content_hash  = scrubber.scrub(req.body)

    result = detector.analyze(scrubbed_subject, scrubbed_body)
    risk   = score_email(result["module_score"], result["evidence_items"])

    return {
        "module_score":     result["module_score"],
        "sub_scores":       result["sub_scores"],
        "matched_patterns": result["matched_patterns"],
        "evidence":         result["evidence_items"],
        "processing_ms":    result["processing_ms"],
        "risk":             risk,
    }


@app.get("/health")
def health():
    return {"status": "ok"}