from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User, ChatMessage
from app.schemas.schemas import ChatMessageRequest, ChatMessageResponse
from app.services.llm_provider import get_llm_provider

router = APIRouter(prefix="/chat", tags=["Help Assistant"])

SYSTEM_HELP_PROMPT = """You are the DefendX AI Security Assistant.
DefendX is an enterprise AI Safety Testing Infrastructure separating Red Team (offensive test creation),
Blue Team (defensive policies/filters), and Auditor (evidence verification).
Provide concise, accurate guidance on:
- How to write adversarial test cases without crashing production systems
- How Blue Team input filters, keyword lists, and regex guardrails prevent leakage
- How to interpret cryptographic SHA-256 hash-linked audit integrity
- How file scanning quarantines suspicious payloads
Strictly avoid assisting with genuine malicious cyberattacks against real-world unauthorized targets.
"""

FAQ_RULES = [
    ("prompt injection", "Prompt injection tests attempt to override the AI model's system instructions. In the Red Team workspace, you can author tests targeting delimiters, role overrides, and instruction conflicts. Blue Team counters these using input keywords and injection risk thresholds."),
    ("canary", "DefendX uses synthetic canary tokens (format: CANARY-XXXXXXXX) to verify context boundaries and detect information leakage without exposing real organizational credentials."),
    ("quarantine", "Uploaded files triggering suspicious heuristics, null bytes, command injection patterns, or mismatched MIME signatures are quarantined automatically in an isolated storage directory."),
    ("audit", "DefendX maintains an immutable SHA-256 hash chain where each event includes the SHA-256 digest of the previous event. The Audit Centre mathematically verifies that logs have not been tampered with or modified."),
    ("isolation", "The Live Isolation Demo verifies that Red Team cannot access Blue Team private defense rules, and Blue Team cannot inspect Red Team private exploits without explicit authorization."),
    ("policy", "Blue Team defensive policies allow configuring input filters, injection risk thresholds, forbidden keywords, and output redaction regex guardrails.")
]

@router.post("/message", response_model=ChatMessageResponse)
async def send_chat_message(
    req: ChatMessageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    msg_lower = req.message.lower().strip()

    # Rule-based fallback or contextual response
    response_text = None
    for kw, answer in FAQ_RULES:
        if kw in msg_lower:
            response_text = f"**DefendX Guidance on {kw.title()}:**\n\n{answer}"
            break

    # If not matched by FAQ rules and external provider is configured
    if not response_text:
        try:
            if settings.LLM_PROVIDER == "openai" and settings.LLM_API_KEY:
                provider = get_llm_provider()
                res = await provider.generate_response(prompt=req.message, system_prompt=SYSTEM_HELP_PROMPT)
                response_text = res["content"]
            else:
                response_text = (
                    "**DefendX Assistant:** I am here to help you navigate adversarial AI safety testing! "
                    "You can test prompt injection resistance in the Red Team workspace, configure input guardrails "
                    "in the Blue Team workspace, verify hash-linked audit trails in the Audit Centre, or test synthetic "
                    "canary leakage in the Leakage Engine. How may I guide you further?"
                )
        except Exception:
            response_text = "DefendX Assistant is currently operating in offline safety fallback mode."

    # Store chat history
    user_msg = ChatMessage(session_id=req.session_id, user_id=current_user.id, role="user", content=req.message)
    bot_msg = ChatMessage(session_id=req.session_id, user_id=None, role="assistant", content=response_text)
    db.add(user_msg)
    db.add(bot_msg)
    await db.commit()

    return ChatMessageResponse(
        role="assistant",
        content=response_text,
        timestamp=datetime.utcnow()
    )
