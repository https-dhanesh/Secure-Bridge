# regex_detector.py
import re
from typing import List

from detector.entities import Detection
from engine import AlgorithmicEngine


class RegexDetector:
    """
    Fast deterministic candidate detector.

    This layer should be extremely fast and should NOT depend
    on the local LLM.
    """

    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    PHONE_PATTERN = re.compile(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
    )

    PAN_PATTERN = re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
    )

    AADHAAR_PATTERN = re.compile(
        r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
    )

    CARD_PATTERN = re.compile(
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
    )

    SSN_PATTERN = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )

    @classmethod
    def detect(cls, text: str) -> List[Detection]:

        detections = []

        # --------------------------------------------------
        # EMAIL
        # --------------------------------------------------

        for match in cls.EMAIL_PATTERN.finditer(text):

            detections.append(
                Detection(
                    value=match.group(),
                    category="EMAIL",
                    start=match.start(),
                    end=match.end(),
                    confidence=0.99,
                    source="regex",
                    validated=True
                )
            )

        # --------------------------------------------------
        # PHONE NUMBER
        # --------------------------------------------------

        for match in cls.PHONE_PATTERN.finditer(text):

            value = match.group()

            detections.append(
                Detection(
                    value=value,
                    category="MOBILE_NUMBER",
                    start=match.start(),
                    end=match.end(),
                    confidence=0.60,
                    source="regex",
                    validated=False
                )
            )

        # --------------------------------------------------
        # PAN
        # --------------------------------------------------

        for match in cls.PAN_PATTERN.finditer(text):

            value = match.group()

            if AlgorithmicEngine.validate_pan(value):

                detections.append(
                    Detection(
                        value=value,
                        category="PAN",
                        start=match.start(),
                        end=match.end(),
                        confidence=0.99,
                        source="regex+validator",
                        validated=True
                    )
                )

        # --------------------------------------------------
        # AADHAAR
        # --------------------------------------------------

        for match in cls.AADHAAR_PATTERN.finditer(text):

            value = match.group()
            clean_value = re.sub(r"\D", "", value)

            if AlgorithmicEngine.validate_verhoeff(clean_value):

                detections.append(
                    Detection(
                        value=value,
                        category="AADHAAR",
                        start=match.start(),
                        end=match.end(),
                        confidence=0.99,
                        source="regex+verhoeff",
                        validated=True
                    )
                )

        # --------------------------------------------------
        # CREDIT / DEBIT CARD
        # --------------------------------------------------

        for match in cls.CARD_PATTERN.finditer(text):

            value = match.group()
            clean_value = re.sub(r"\D", "", value)

            if AlgorithmicEngine.validate_luhn(clean_value):

                detections.append(
                    Detection(
                        value=value,
                        category="CREDIT_CARD",
                        start=match.start(),
                        end=match.end(),
                        confidence=0.99,
                        source="regex+luhn",
                        validated=True
                    )
                )

        # --------------------------------------------------
        # SSN
        # --------------------------------------------------

        for match in cls.SSN_PATTERN.finditer(text):

            value = match.group()

            if AlgorithmicEngine.validate_ssn(value):

                detections.append(
                    Detection(
                        value=value,
                        category="SSN",
                        start=match.start(),
                        end=match.end(),
                        confidence=0.99,
                        source="regex+validator",
                        validated=True
                    )
                )

        return cls._remove_overlaps(detections)

    # ------------------------------------------------------
    # REMOVE OVERLAPPING DETECTIONS
    # ------------------------------------------------------

    @staticmethod
    def _remove_overlaps(detections: List[Detection]) -> List[Detection]:

        if not detections:
            return []

        # Higher confidence gets priority.
        detections = sorted(
            detections,
            key=lambda d: (
                -d.confidence,
                -(d.end - d.start)
            )
        )

        selected = []

        for detection in detections:

            overlaps = False

            for existing in selected:

                if (
                    detection.start < existing.end
                    and detection.end > existing.start
                ):
                    overlaps = True
                    break

            if not overlaps:
                selected.append(detection)

        return sorted(
            selected,
            key=lambda d: d.start
        )   