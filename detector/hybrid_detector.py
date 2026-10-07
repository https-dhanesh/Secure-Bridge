# hybrid_detector.py
import re
import time

from detector.entities import Detection, DetectionResult
from detector.regex_detector import RegexDetector
from llm_detector import LocalLLMDetector


class HybridDetector:

    HIGH_CONFIDENCE_THRESHOLD = 0.95

    DETERMINISTIC_CATEGORIES = {
        "EMAIL",
        "PAN",
        "CREDIT_CARD",
        "AADHAAR",
        "SSN"
    }

    @classmethod
    def detect(cls, text):
        start_time = time.perf_counter()

        # ---------------------------------------------------------
        # TEMPORARY TEST MODE
        # Force local Qwen to analyze EVERY request.
        # ---------------------------------------------------------

        deterministic = RegexDetector.detect(text)

        # Always call the local LLM
        model_needed = True
        model_used = True

        llm_result = LocalLLMDetector.detect(text)

        final_detections = list(deterministic)

        if llm_result.get("success"):
            llm_detections = cls._convert_llm_results(
                text,
                llm_result.get("detections", [])
            )

            final_detections = cls._merge_detections(
                deterministic,
                llm_detections
            )

        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        return DetectionResult(
            detections=final_detections,
            latency_ms=latency_ms,
            model_used=model_used
        )

    # ======================================================
    # CONTEXT DECISION
    # ======================================================

    @classmethod
    def _requires_contextual_analysis(
        cls,
        text,
        deterministic
    ):

        if not deterministic:
            return True

        for detection in deterministic:

            category = detection.category

            # ----------------------------------------------
            # Strong deterministic PII
            # ----------------------------------------------

            if (
                category in cls.DETERMINISTIC_CATEGORIES
                and detection.validated
                and detection.confidence >= 0.95
            ):
                continue

            # ----------------------------------------------
            # PHONE NUMBERS REQUIRE CONTEXT
            # ----------------------------------------------

            if category == "MOBILE_NUMBER":
                return True

            # ----------------------------------------------
            # Anything uncertain
            # ----------------------------------------------

            if detection.confidence < 0.95:
                return True

        return False

    # ======================================================
    # LLM RESULT CONVERSION
    # ======================================================

    @staticmethod
    def _convert_llm_results(
        text,
        llm_detections
    ):

        results = []

        for item in llm_detections:

            value = str(
                item.get("value", "")
            ).strip()

            if not value:
                continue

            # Model cannot invent text.
            start = text.find(value)

            if start == -1:
                continue

            end = start + len(value)

            try:
                confidence = float(
                    item.get(
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

            category = str(
                item.get(
                    "category",
                    "OTHER_PII"
                )
            ).upper()

            if confidence < 0.70:
                continue

            results.append(
                Detection(
                    value=value,
                    category=category,
                    start=start,
                    end=end,
                    confidence=confidence,
                    source="local_llm",
                    validated=False
                )
            )

        return results

    # ======================================================
    # MERGE RESULTS
    # ======================================================

    @staticmethod
    def _merge_detections(
        deterministic,
        llm_detections
    ):

        merged = list(deterministic)

        for llm_detection in llm_detections:

            overlapping = None

            for existing in merged:

                if (
                    llm_detection.start < existing.end
                    and llm_detection.end > existing.start
                ):
                    overlapping = existing
                    break

            # ----------------------------------------------
            # New LLM detection
            # ----------------------------------------------

            if overlapping is None:

                merged.append(
                    llm_detection
                )

                continue

            # ----------------------------------------------
            # Contextual model can override PHONE
            # ----------------------------------------------

            if (
                overlapping.category
                == "MOBILE_NUMBER"
            ):

                # If LLM says this is something else,
                # contextual understanding wins.

                if (
                    llm_detection.category
                    != "MOBILE_NUMBER"
                ):

                    merged.remove(
                        overlapping
                    )

                    merged.append(
                        llm_detection
                    )

                continue

            # ----------------------------------------------
            # Deterministic validated detection wins
            # ----------------------------------------------

            if overlapping.validated:
                continue

            # ----------------------------------------------
            # Higher confidence wins
            # ----------------------------------------------

            if (
                llm_detection.confidence
                > overlapping.confidence
            ):

                merged.remove(
                    overlapping
                )

                merged.append(
                    llm_detection
                )

        return sorted(
            merged,
            key=lambda d: d.start
        )

    @staticmethod
    def _detect_obvious_contextual_pii(text):

        detections = []

        patterns = [
            (
                r"\bmy name is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
                "PERSON_NAME"
            ),
            (
                r"\bname is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
                "PERSON_NAME"
            ),
            (
                r"\bcontact\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
                "PERSON_NAME"
            )
        ]

        for pattern, category in patterns:

            for match in re.finditer(
                pattern,
                text,
                re.IGNORECASE
            ):

                value = match.group(1).strip()

                start = match.start(1)
                end = match.end(1)

                detections.append(
                    Detection(
                        value=value,
                        category=category,
                        start=start,
                        end=end,
                        confidence=0.95,
                        source="context_rule",
                        validated=True
                    )
                )

        return detections