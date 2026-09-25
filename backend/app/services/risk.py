from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.models import ExceptionRequest, SystemConfig


@dataclass(frozen=True)
class RiskFactor:
    code: str
    label: str
    points: int
    explanation: str


DEFAULT_WEIGHTS = {
    "data_sensitivity": 20,
    "production_environment": 15,
    "internet_exposure": 20,
    "privilege_impact": 15,
    "regulatory_impact": 15,
    "long_duration": 10,
    "weak_compensating_controls": 15,
    "asset_criticality": 15,
}


def _config_weights(db: DbSession) -> dict[str, int]:
    row = db.scalar(
        select_system_config(db, "risk.weights")
    )
    if not row or not isinstance(row.value, dict):
        return DEFAULT_WEIGHTS.copy()
    return {**DEFAULT_WEIGHTS, **{str(k): int(v) for k, v in row.value.items()}}


def select_system_config(db: DbSession, key: str) -> SystemConfig | None:
    from sqlalchemy import select

    return db.scalar(
        select(SystemConfig).where(
            SystemConfig.config_key == key,
            SystemConfig.is_active.is_(True),
        )
    )


def assess_structured_risk(
    db: DbSession, request: ExceptionRequest, settings: Settings
) -> tuple[int, str, list[RiskFactor]]:
    weights = _config_weights(db)
    sensitivity_points = {
        "Public": 0,
        "Internal": 4,
        "Confidential": 10,
        "Restricted": 16,
        "Highly Restricted": weights["data_sensitivity"],
    }.get(request.data_classification_code, weights["data_sensitivity"] // 2)
    factors = [
        RiskFactor(
            "data_sensitivity",
            "Data sensitivity",
            sensitivity_points,
            f"Classification is {request.data_classification_code}.",
        )
    ]
    if request.environment.casefold() in {"production", "prod"}:
        factors.append(
            RiskFactor("production_environment", "Production environment", weights["production_environment"], "The exception affects production.")
        )
    combined = " ".join(
        [
            request.application_name,
            request.asset_system,
            request.requested_exception,
            request.reason_control_cannot_follow,
            request.control_excepted,
        ]
    ).casefold()
    if re.search(r"\b(internet[- ]facing|public[- ]facing|edge|external)\b", combined):
        factors.append(
            RiskFactor("internet_exposure", "Internet exposure", weights["internet_exposure"], "The request describes an externally reachable asset or control.")
        )
    if re.search(r"\b(admin|administrator|privileged|root|identity|access)\b", combined):
        factors.append(
            RiskFactor("privilege_impact", "Privilege impact", weights["privilege_impact"], "The requested change may affect privileged access or identity controls.")
        )
    if request.regulatory_impact and len(request.regulatory_impact.strip()) > 20:
        factors.append(
            RiskFactor("regulatory_impact", "Regulatory impact", weights["regulatory_impact"], "A regulatory impact is documented.")
        )
    if request.requested_duration_days > settings.default_exception_days:
        factors.append(
            RiskFactor("long_duration", "Duration above standard", weights["long_duration"], f"Requested duration is {request.requested_duration_days} days versus {settings.default_exception_days} days standard.")
        )
    control_text = request.compensating_controls.casefold()
    if len(control_text.strip()) < 80 or not any(
        keyword in control_text for keyword in ("monitor", "detection", "review", "compensating", "alert", "audit")
    ):
        factors.append(
            RiskFactor(
                "weak_compensating_controls",
                "Compensating controls need detail",
                weights["weak_compensating_controls"],
                "The compensating-control narrative lacks a clear monitoring or review mechanism.",
            )
        )
    if re.search(r"\b(critical|payment|core banking|patient|customer data|sap|hrms)\b", combined):
        factors.append(
            RiskFactor("asset_criticality", "Business/asset criticality", weights["asset_criticality"], "The request references a business-critical system or sensitive data set.")
        )
    score = min(100, sum(factor.points for factor in factors))
    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"
    return score, level, factors
