import os
import re
import uuid
import time
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from google import genai
from dotenv import load_dotenv

from engine import AlgorithmicEngine
from vault import ram_vault

load_dotenv()

app = FastAPI(title="Secure Bridge Demo")

ai_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

class PromptRequest(BaseModel):
    prompt: str
    ttl_seconds: int = 15

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(BASE_DIR, "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/process")
def process_prompt(req: PromptRequest):
    start_time = time.perf_counter()
    sanitized = req.prompt
    tokens_created = 0

    # 1. Credit Cards (Luhn Check)
    cards_found = []
    for card in re.findall(r'\b(?:\d[ -]*?){13,19}\b', req.prompt):
        clean_card = re.sub(r'\D', '', card)
        if AlgorithmicEngine.validate_luhn(clean_card):
            t = f"[CARD_{uuid.uuid4().hex[:4].upper()}]"
            ram_vault.store_mapping(t, card, req.ttl_seconds)
            sanitized = sanitized.replace(card, t)
            cards_found.append(card)
            tokens_created += 1

    # 2. Aadhaar Numbers (Verhoeff Check)
    for aid in re.findall(r'(?<!\d)\b\d{4}[ -]?\d{4}[ -]?\d{4}\b(?!\d)', req.prompt):
        if any(aid in card for card in cards_found):
            continue
            
        clean_aid = re.sub(r'\D', '', aid)
        if AlgorithmicEngine.validate_verhoeff(clean_aid) or len(clean_aid) == 12:
            t = f"[AADHAAR_{uuid.uuid4().hex[:4].upper()}]"
            ram_vault.store_mapping(t, aid, req.ttl_seconds)
            sanitized = sanitized.replace(aid, t)
            tokens_created += 1

    # 3. Email Addresses
    for email in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', req.prompt):
        t = f"[EMAIL_{uuid.uuid4().hex[:4].upper()}]"
        ram_vault.store_mapping(t, email, req.ttl_seconds)
        sanitized = sanitized.replace(email, t)
        tokens_created += 1

    # 4. US Social Security Numbers (SSN)
    for ssn in re.findall(r'\b\d{3}-\d{2}-\d{4}\b', req.prompt):
        if AlgorithmicEngine.validate_ssn(ssn):
            t = f"[SSN_{uuid.uuid4().hex[:4].upper()}]"
            ram_vault.store_mapping(t, ssn, req.ttl_seconds)
            sanitized = sanitized.replace(ssn, t)
            tokens_created += 1

    # 5. PAN Cards
    for pan in re.findall(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', req.prompt):
        if AlgorithmicEngine.validate_pan(pan):
            t = f"[PAN_{uuid.uuid4().hex[:4].upper()}]"
            ram_vault.store_mapping(t, pan, req.ttl_seconds)
            sanitized = sanitized.replace(pan, t)
            tokens_created += 1

    try:
        response = ai_client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=(
                "You are a secure assistant. Acknowledge and process the user's request. "
                "Maintain all token placeholders exactly as written (e.g. [CARD_XXXX], [EMAIL_XXXX], [SSN_XXXX], [PAN_XXXX]): "
                f"\n\n{sanitized}"
            )
        )
        cloud_ai_reply = response.text

    except Exception as e:
        if "503" in str(e) or "UNAVAILABLE" in str(e):
            cloud_ai_reply = (
                f"[Gateway Intercept Success] Payload sanitized securely to: '{sanitized}'. "
                "Upstream Cloud LLM (Gemini) is experiencing temporary high demand (HTTP 503). "
                "Local Zero-Trust Edge processing completed successfully."
            )
        else:
            cloud_ai_reply = f"[Gemini Gateway Connection Error: {str(e)}]"

    rehydrated = cloud_ai_reply
    live_map = ram_vault.get_live_memory_map()
    live_map.sort(key=lambda x: len(x["token"]), reverse=True)

    for item in live_map:
        if item["token"] in rehydrated:
            rehydrated = rehydrated.replace(item["token"], item["cleartext"])

    latency = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "original": req.prompt,
        "sanitized": sanitized,
        "cloud_llm_received": cloud_ai_reply,
        "rehydrated_user_output": rehydrated,
        "tokens_created": tokens_created,
        "latency_ms": latency
    }

@app.get("/api/vault_status")
def vault_status():
    return {"live_vault": ram_vault.get_live_memory_map()}