from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Detection:
    """
    Standard representation of a detected sensitive entity.
    """

    value: str
    category: str
    start: int
    end: int
    confidence: float
    source: str
    validated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DetectionResult:
    """
    Final result returned by the hybrid detection engine.
    """

    detections: list
    latency_ms: float
    model_used: bool = False

    def to_dict(self) -> dict:
        return {
            "detections": [
                detection.to_dict()
                if isinstance(detection, Detection)
                else detection
                for detection in self.detections
            ],
            "latency_ms": self.latency_ms,
            "model_used": self.model_used
        }