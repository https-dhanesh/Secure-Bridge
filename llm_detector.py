import json
import time
from pathlib import Path

from llama_cpp import Llama


class LocalLLMDetector:
    """
    Local sensitive-information detector using Qwen2.5 through
    llama.cpp / llama-cpp-python.

    No Ollama.
    No external LLM API.
    No network request is made by this detector.
    """

    MODEL_PATH = (
        Path(__file__).resolve().parent
        / "models"
        / "qwen2.5-1.5b-instruct-q5_k_m.gguf"
    )

    MODEL = "qwen2.5-1.5b-instruct-q5_k_m"

    CATEGORIES = [
        "PAN",
        "AADHAAR",
        "MOBILE_NUMBER",
        "EMAIL",
        "BANK_ACCOUNT",
        "CREDIT_CARD",
        "UPI_ID",
        "PASSPORT",
        "DRIVING_LICENSE",
        "PERSON_NAME",
        "ADDRESS",
        "DATE_OF_BIRTH",
        "SSN",
        "OTHER_PII",
    ]

    # Model is loaded once and reused.
    _llm = None

    @classmethod
    def _get_model(cls):
        """
        Load Qwen once and reuse the same model instance.
        """

        if cls._llm is None:

            if not cls.MODEL_PATH.exists():
                raise FileNotFoundError(
                    f"Qwen model not found at: {cls.MODEL_PATH}"
                )

            print(
                f"[Secure Bridge] Loading local model: {cls.MODEL}"
            )

            cls._llm = Llama(
                model_path=str(cls.MODEL_PATH),
                n_ctx=4096,
                n_threads=4,
                n_batch=256,
                verbose=False,
            )

            print("[Secure Bridge] Local Qwen model loaded.")

        return cls._llm

    @classmethod
    def detect(cls, text: str) -> dict:
        """
        Run contextual PII detection using the local Qwen model.

        The input never leaves the local machine.
        """

        start_time = time.perf_counter()

        # ---------------------------------------------------------
        # LOCAL MODEL PROMPT
        # ---------------------------------------------------------

        prompt = f"""
You are a privacy and sensitive-information detection engine.

Your task is to identify personally identifiable information
(PII) or sensitive information in the INPUT TEXT.

You MUST use BOTH:

1. The actual value.
2. The surrounding context.

Do NOT assume that every number, identifier, or alphanumeric
sequence is sensitive.

------------------------------------------------------------
IMPORTANT RULES
------------------------------------------------------------

1. Only report information that actually exists in the input.

2. NEVER invent a value.

3. Return the EXACT value as it appears in the input.

4. Do not modify, normalize, mask, or rewrite the detected value.

5. Return a confidence value between 0 and 1.

6. Return ONLY valid JSON.

7. If there is no sensitive information, return:

{{
    "detections": []
}}

------------------------------------------------------------
CONTEXTUAL NUMBER RULE
------------------------------------------------------------

A 10-digit Indian number is NOT automatically a mobile number.

For example:

"Call Rahul on 9876543210"

means:

9876543210 -> MOBILE_NUMBER

But:

"My order ID is 9876543210"

means:

9876543210 -> NOT MOBILE_NUMBER

Similarly:

"Transaction reference: 9876543210"

means:

9876543210 -> NOT MOBILE_NUMBER

"Employee ID: 9876543210"

means:

9876543210 -> NOT MOBILE_NUMBER

Only classify a number as MOBILE_NUMBER when the surrounding
context clearly indicates that it represents a phone, mobile,
contact, telephone, or similar communication number.

------------------------------------------------------------
PAN RULE
------------------------------------------------------------

A value such as:

ABCDE1234F

should be classified as PAN when the surrounding context
indicates that it is a PAN, tax identifier, PAN card number,
or Indian tax identifier.

Do not classify an arbitrary alphanumeric product code as PAN
only because it has a similar format.

------------------------------------------------------------
PERSON NAME RULE
------------------------------------------------------------

Identify PERSON_NAME when the text clearly represents
a person's name.

Example:

"My name is Rahul Sharma"

should identify:

Rahul Sharma -> PERSON_NAME

------------------------------------------------------------
EMAIL RULE
------------------------------------------------------------

Identify email addresses as EMAIL when they appear in the text.

Example:

"Contact Rahul at rahul@example.com"

should identify:

rahul@example.com -> EMAIL

------------------------------------------------------------
ADDRESS RULE
------------------------------------------------------------

Identify physical residential, office, or postal addresses
when the surrounding context clearly indicates an address.

------------------------------------------------------------
OTHER IMPORTANT RULES
------------------------------------------------------------

Do not classify:

- ordinary order IDs
- transaction IDs
- invoice numbers
- ticket numbers
- employee IDs
- customer IDs
- product codes
- random numbers

as PII unless the context indicates that they contain
sensitive personal information.

Do not make assumptions without contextual evidence.

------------------------------------------------------------
ALLOWED CATEGORIES
------------------------------------------------------------

You may ONLY use one of these categories:

PAN
AADHAAR
MOBILE_NUMBER
EMAIL
BANK_ACCOUNT
CREDIT_CARD
UPI_ID
PASSPORT
DRIVING_LICENSE
PERSON_NAME
ADDRESS
DATE_OF_BIRTH
SSN
OTHER_PII

------------------------------------------------------------
REQUIRED JSON FORMAT
------------------------------------------------------------

Return exactly this structure:

{{
    "detections": [
        {{
            "value": "exact value from input",
            "category": "CATEGORY",
            "sensitive": true,
            "confidence": 0.95
        }}
    ]
}}

------------------------------------------------------------
EXAMPLES
------------------------------------------------------------

Example 1:

INPUT:
Call Rahul on 9876543210

OUTPUT:

{{
    "detections": [
        {{
            "value": "Rahul",
            "category": "PERSON_NAME",
            "sensitive": true,
            "confidence": 0.95
        }},
        {{
            "value": "9876543210",
            "category": "MOBILE_NUMBER",
            "sensitive": true,
            "confidence": 0.98
        }}
    ]
}}

Example 2:

INPUT:
My order ID is 9876543210

OUTPUT:

{{
    "detections": []
}}

Example 3:

INPUT:
My PAN is ABCDE1234F

OUTPUT:

{{
    "detections": [
        {{
            "value": "ABCDE1234F",
            "category": "PAN",
            "sensitive": true,
            "confidence": 0.99
        }}
    ]
}}

Example 4:

INPUT:
Product code ABCDE1234F

OUTPUT:

{{
    "detections": []
}}

Example 5:

INPUT:
My name is Rahul Sharma

OUTPUT:

{{
    "detections": [
        {{
            "value": "Rahul Sharma",
            "category": "PERSON_NAME",
            "sensitive": true,
            "confidence": 0.98
        }}
    ]
}}

Example 6:

INPUT:
Rahul Sharma can be contacted at rahul.sharma@gmail.com

OUTPUT:

{{
    "detections": [
        {{
            "value": "Rahul Sharma",
            "category": "PERSON_NAME",
            "sensitive": true,
            "confidence": 0.98
        }},
        {{
            "value": "rahul.sharma@gmail.com",
            "category": "EMAIL",
            "sensitive": true,
            "confidence": 0.99
        }}
    ]
}}

------------------------------------------------------------
INPUT TEXT
------------------------------------------------------------

{text}
"""

        try:

            # -----------------------------------------------------
            # LOAD LOCAL MODEL
            # -----------------------------------------------------

            llm = cls._get_model()

            # -----------------------------------------------------
            # RUN LOCAL QWEN INFERENCE
            # -----------------------------------------------------

            response = llm.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a privacy detection engine. "
                            "Return only valid JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.0,
                max_tokens=512,
                response_format={
                    "type": "json_object"
                },
            )

            # -----------------------------------------------------
            # EXTRACT MODEL RESPONSE
            # -----------------------------------------------------

            raw_response = (
                response["choices"][0]["message"]["content"]
            )

            # -----------------------------------------------------
            # PARSE JSON
            # -----------------------------------------------------

            parsed = json.loads(raw_response)

            detections = parsed.get(
                "detections",
                []
            )

            if not isinstance(detections, list):
                detections = []

            validated = []

            # -----------------------------------------------------
            # VALIDATE MODEL DETECTIONS
            # -----------------------------------------------------

            for detection in detections:

                if not isinstance(detection, dict):
                    continue

                value = str(
                    detection.get(
                        "value",
                        ""
                    )
                ).strip()

                category = str(
                    detection.get(
                        "category",
                        "OTHER_PII"
                    )
                ).upper().strip()

                sensitive = detection.get(
                    "sensitive",
                    True
                )

                if not value:
                    continue

                # Never allow the model to invent a value.
                if value not in text:
                    continue

                # Validate category.
                if category not in cls.CATEGORIES:
                    category = "OTHER_PII"

                # Ignore detections explicitly marked non-sensitive.
                if sensitive is False:
                    continue

                # Validate confidence.
                try:
                    confidence = float(
                        detection.get(
                            "confidence",
                            0.0
                        )
                    )
                except (
                    TypeError,
                    ValueError
                ):
                    confidence = 0.0

                confidence = max(
                    0.0,
                    min(
                        1.0,
                        confidence
                    )
                )

                # Ignore very uncertain predictions.
                if confidence < 0.70:
                    continue

                start = text.find(value)

                if start == -1:
                    continue

                end = start + len(value)

                validated.append(
                    {
                        "value": value,
                        "category": category,
                        "start": start,
                        "end": end,
                        "sensitive": True,
                        "confidence": confidence,
                    }
                )

            # -----------------------------------------------------
            # REMOVE DUPLICATES
            # -----------------------------------------------------

            unique = []
            seen = set()

            for detection in validated:

                key = (
                    detection["value"],
                    detection["category"],
                )

                if key in seen:
                    continue

                seen.add(key)
                unique.append(detection)

            # -----------------------------------------------------
            # LATENCY
            # -----------------------------------------------------

            latency_ms = round(
                (
                    time.perf_counter()
                    - start_time
                ) * 1000,
                2
            )

            return {
                "success": True,
                "detections": unique,
                "latency_ms": latency_ms,
                "model": cls.MODEL,
                "raw_response": raw_response,
            }

        except FileNotFoundError as e:

            return {
                "success": False,
                "detections": [],
                "latency_ms": round(
                    (
                        time.perf_counter()
                        - start_time
                    ) * 1000,
                    2
                ),
                "model": cls.MODEL,
                "error": str(e),
            }

        except Exception as e:

            return {
                "success": False,
                "detections": [],
                "latency_ms": round(
                    (
                        time.perf_counter()
                        - start_time
                    ) * 1000,
                    2
                ),
                "model": cls.MODEL,
                "error": str(e),
            }