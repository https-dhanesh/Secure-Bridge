import os
import re
import uuid
import time

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from google import genai
from dotenv import load_dotenv

from detector.hybrid_detector import HybridDetector
from engine import AlgorithmicEngine
from vault import ram_vault


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

app = FastAPI(title="Secure Bridge Demo")


# ============================================================
# GEMINI CLIENT
# ============================================================

ai_client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

CLOUD_LLM_MODEL = "gemini-3.5-flash-lite"


# ============================================================
# REQUEST MODEL
# ============================================================

class PromptRequest(BaseModel):
    prompt: str
    ttl_seconds: int = 15


# ============================================================
# WEB UI
# ============================================================

@app.get("/", response_class=HTMLResponse)
def serve_ui():

    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    html_path = os.path.join(
        base_dir,
        "dashboard.html"
    )

    with open(
        html_path,
        "r",
        encoding="utf-8"
    ) as f:

        return f.read()


# ============================================================
# PROCESS PROMPT
# ============================================================

@app.post("/api/process")
def process_prompt(req: PromptRequest):

    start_time = time.perf_counter()

    original_prompt = req.prompt

    sanitized = original_prompt

    tokens_created = 0

    # ========================================================
    # 1. HYBRID PII DETECTION
    # ========================================================

    detection_result = HybridDetector.detect(
        original_prompt
    )

    detections = detection_result.detections

    # ========================================================
    # 2. LOCAL LLM INFORMATION
    # ========================================================

    local_llm_used = detection_result.model_used

    if local_llm_used:

        local_llm_provider = "local"

        local_llm_runtime = "llama-cpp-python"

        local_llm_model = (
            "qwen2.5-1.5b-instruct-q5_k_m"
        )

    else:

        local_llm_provider = None

        local_llm_runtime = None

        local_llm_model = None

    # ========================================================
    # 3. TOKENIZATION
    # ========================================================

    tokenized_entities = []

    # Replace from right -> left.
    #
    # This keeps detection positions stable and helps when
    # multiple entities exist in the same prompt.

    detections_sorted = sorted(
        detections,
        key=lambda d: d.start,
        reverse=True
    )

    for detection in detections_sorted:

        value = detection.value

        # Safety check.
        if not value:
            continue

        # Only tokenize if the value still exists.
        if value not in sanitized:
            continue

        category = detection.category.upper()

        safe_category = re.sub(
            r"[^A-Z0-9_]",
            "_",
            category
        )

        token = (
            f"[{safe_category}_"
            f"{uuid.uuid4().hex[:4].upper()}]"
        )

        # Store cleartext only in the ephemeral RAM vault.
        ram_vault.store_mapping(
            token,
            value,
            req.ttl_seconds
        )

        sanitized = sanitized.replace(
            value,
            token,
            1
        )

        tokens_created += 1

        tokenized_entities.append(
            {
                "category": category,
                "source": detection.source,
                "confidence": detection.confidence,
                "validated": detection.validated,
                "token": token
            }
        )

    # ========================================================
    # 4. SEND SANITIZED DATA TO CLOUD LLM
    # ========================================================

    cloud_llm_status = "not_called"

    cloud_ai_reply = ""

    try:

        cloud_llm_status = "called"

        response = ai_client.models.generate_content(
            model=CLOUD_LLM_MODEL,
            contents=(
                "You are a secure assistant. "
                "Process the user's request while preserving "
                "all token placeholders exactly as written. "
                "Never modify, remove or invent token "
                "placeholders.\n\n"
                f"{sanitized}"
            )
        )

        cloud_ai_reply = response.text

    except Exception as e:

        error_string = str(e)

        if (
            "503" in error_string
            or "UNAVAILABLE" in error_string
        ):

            cloud_llm_status = "unavailable"

            cloud_ai_reply = (
                "[Gateway Intercept Success] "
                f"Payload sanitized securely to: "
                f"'{sanitized}'. "
                "Upstream Cloud LLM is temporarily "
                "unavailable. "
                "Local Zero-Trust Edge processing "
                "completed."
            )

        else:

            cloud_llm_status = "error"

            cloud_ai_reply = (
                "[Gemini Gateway Connection Error: "
                f"{error_string}]"
            )

    # ========================================================
    # 5. REHYDRATION
    # ========================================================

    rehydrated = cloud_ai_reply

    live_map = ram_vault.get_live_memory_map()

    # Longest token first prevents substring collisions.
    live_map.sort(
        key=lambda x: len(x["token"]),
        reverse=True
    )

    for item in live_map:

        token = item["token"]

        if token in rehydrated:

            rehydrated = rehydrated.replace(
                token,
                item["cleartext"]
            )

    # ========================================================
    # 6. TOTAL LATENCY
    # ========================================================

    latency = round(
        (
            time.perf_counter()
            - start_time
        ) * 1000,
        2
    )

    # ========================================================
    # 7. TERMINAL DEBUG / AUDIT INFORMATION
    # ========================================================

    print()
    print("=" * 70)
    print("SECURE BRIDGE REQUEST")
    print("=" * 70)

    print(
        f"LOCAL LLM USED : "
        f"{'YES' if local_llm_used else 'NO'}"
    )

    if local_llm_used:

        print(
            f"LOCAL MODEL    : "
            f"{local_llm_model}"
        )

        print(
            f"LOCAL RUNTIME  : "
            f"{local_llm_runtime}"
        )

    else:

        print(
            "LOCAL MODEL    : "
            "Not required"
        )

    print(
        f"CLOUD LLM      : "
        f"{CLOUD_LLM_MODEL}"
    )

    print(
        f"CLOUD STATUS   : "
        f"{cloud_llm_status}"
    )

    print(
        f"DETECTIONS     : "
        f"{len(detections)}"
    )

    print(
        f"TOKENS CREATED : "
        f"{tokens_created}"
    )

    print(
        f"DETECTION TIME : "
        f"{detection_result.latency_ms} ms"
    )

    print(
        f"TOTAL TIME     : "
        f"{latency} ms"
    )

    print("=" * 70)
    print()

    # ========================================================
    # 8. API RESPONSE
    # ========================================================

    return {

        # ----------------------------------------------------
        # Original / sanitized / final data
        # ----------------------------------------------------

        "original": original_prompt,

        "sanitized": sanitized,

        "cloud_llm_received": cloud_ai_reply,

        "rehydrated_user_output": rehydrated,

        # ----------------------------------------------------
        # Token information
        # ----------------------------------------------------

        "tokens_created": tokens_created,

        # ----------------------------------------------------
        # Overall latency
        # ----------------------------------------------------

        "latency_ms": latency,

        # ----------------------------------------------------
        # Detection information
        # ----------------------------------------------------

        "detection": {

            "total_detections": len(
                detections
            ),

            "model_used": local_llm_used,

            "detection_latency_ms":
                detection_result.latency_ms,

            "entities": [
                detection.to_dict()
                for detection in detections
            ],

            "tokenized_entities":
                tokenized_entities
        },

        # ----------------------------------------------------
        # LOCAL LLM INFORMATION
        # ----------------------------------------------------

        "local_llm": {

            "used": local_llm_used,

            "provider": local_llm_provider,

            "model": local_llm_model,

            "runtime": local_llm_runtime

        },

        # ----------------------------------------------------
        # CLOUD LLM INFORMATION
        # ----------------------------------------------------

        "cloud_llm": {

            "model": CLOUD_LLM_MODEL,

            "status": cloud_llm_status

        }
    }


# ============================================================
# VAULT STATUS
# ============================================================

@app.get("/api/vault_status")
def vault_status():

    return {
        "live_vault": (
            ram_vault.get_live_memory_map()
        )
    }