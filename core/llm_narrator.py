"""
core/llm_narrator.py
LLM-powered Executive Narrative Generator for Cryptographic Posture Reports.

Uses the official Google Gen AI SDK (google-genai) to call gemini-2.5-flash and
produce a plain-English analyst narrative from the structured findings emitted by
the scoring engine and rule engine.

Design principles:
  1. Graceful degradation -- if GEMINI_API_KEY / GOOGLE_API_KEY is absent or the
     API call fails, the module returns a NarrativeResult with skipped_reason set
     and no exception propagates to the caller.
  2. Strict separation -- the LLM sees only a curated summary slice; it never sees
     raw packet bytes, internal heuristic state, or any field not meaningful to an
     analyst. This keeps the prompt tight and the output grounded.
  3. Stateless -- every call is self-contained; no session/conversation history is
     maintained. Thread-safe to call concurrently.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

logger = logging.getLogger("cryptoposture.narrator")


# ---------------------------------------------------------------------------
# Model configuration
# ---------------------------------------------------------------------------

# Configurable Gemini Flash model (defaults to gemini-2.5-flash or GEMINI_MODEL env var)
_DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
# Fallback models in case primary model hits 503 UNAVAILABLE or high demand spikes
_FALLBACK_MODELS = ("gemini-2.5-flash", "gemini-3.5-flash")

# System prompt: gives the LLM its analyst persona and output contract.
_SYSTEM_PROMPT = (
    "You are a senior cryptographic security analyst and threat intelligence author "
    "with deep expertise in TLS/STARTTLS forensics, RFC 9325, RFC 8996, RFC 8314, "
    "NIST SP 800-52 Rev. 2, and email infrastructure security. Your job is to "
    "translate structured machine-generated forensic findings into a concise, "
    "authoritative executive narrative that a CISO or senior engineer can act on.\n\n"
    "Output format -- write four clearly labelled sections as plain prose paragraphs "
    "(no markdown, no bullet lists, no headers with # symbols):\n\n"
    "EXECUTIVE SUMMARY\n"
    "One paragraph (3-5 sentences) synthesising the overall risk posture for this "
    "capture. State the Enterprise Posture Index, the risk tier, and the single most "
    "consequential finding.\n\n"
    "CRITICAL FINDINGS\n"
    "One paragraph (up to 6 sentences) describing the top violations and attack "
    "vectors observed. Name the specific flows (protocol, port, IP pair) that are "
    "the primary risk contributors. Where a STARTTLS stripping attack, buffer "
    "injection, or cleartext relay is present, call it out explicitly.\n\n"
    "RISK NARRATIVE\n"
    "One paragraph (3-5 sentences) explaining why the EPI is at the level it is, "
    "referencing the harmonic drag contributions of the worst-offending sessions "
    "and any AI-flagged anomalies from the Isolation Forest detector.\n\n"
    "RECOMMENDED REMEDIATIONS\n"
    "One paragraph (up to 6 sentences) giving prioritised, concrete remediation "
    "steps. Reference specific standards (RFC numbers, NIST guidelines) where "
    "appropriate. Focus on highest-impact changes first.\n\n"
    "Write in a direct, authoritative tone -- no hedging, no pleasantries, no AI "
    "self-referential language. Do not repeat data the reader can already see in the "
    "dashboard. Total length: 300-500 words."
)

# User prompt template -- the structured findings are injected here.
_USER_PROMPT_TEMPLATE = (
    "Analyze the following cryptographic forensic findings from a passive network "
    "capture and write the executive narrative:\n\n{findings_json}\n\n"
    "Remember: write four sections (EXECUTIVE SUMMARY, CRITICAL FINDINGS, RISK "
    "NARRATIVE, RECOMMENDED REMEDIATIONS) as plain prose. No markdown formatting."
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class NarrativeResult:
    """Output from a narrative generation attempt."""
    narrative: str = ""
    model: str = _DEFAULT_MODEL
    generated_at: str = ""
    skipped_reason: Optional[str] = None   # Non-null when generation was bypassed
    token_usage: Optional[dict] = None
    error_detail: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "narrative":      self.narrative,
            "model":          self.model,
            "generated_at":   self.generated_at,
            "skipped_reason": self.skipped_reason,
            "token_usage":    self.token_usage,
            "error_detail":   self.error_detail,
        }


# ---------------------------------------------------------------------------
# Context extraction -- build the minimal JSON the LLM needs
# ---------------------------------------------------------------------------

def _extract_findings_context(summary: Any) -> dict:
    """
    Extract a curated, LLM-friendly context slice from an EnterpriseSummary object.
    Only information meaningful to an analyst narrative is included.
    """
    exp = summary.enterprise_explanation or {}
    top_risk = exp.get("top_risk_contributors", [])

    # Per-session digest: only critical/high sessions, worst 8 by posture score
    sessions_digest = []
    for s in summary.sessions:
        risk = s.risk_tier.value if hasattr(s.risk_tier, "value") else str(s.risk_tier)
        if risk not in ("CRITICAL", "HIGH"):
            continue
        top_viols = [
            {
                "code":        v.code,
                "severity":    v.severity,
                "description": v.description[:120],
            }
            for v in (s.violations or [])
            if getattr(v, "severity", "") in ("CRITICAL", "HIGH")
        ][:4]

        sessions_digest.append({
            "flow":            f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}",
            "protocol":        s.protocol.value if hasattr(s.protocol, "value") else str(s.protocol),
            "channel_type":    s.channel_type.value if hasattr(s.channel_type, "value") else str(s.channel_type),
            "tls_version":     s.tls_version.value if s.tls_version else "None",
            "starttls_status": s.starttls_status.value if hasattr(s.starttls_status, "value") else str(s.starttls_status),
            "risk_tier":       risk,
            "posture_score":   round(s.posture_score, 1),
            "top_violations":  top_viols,
            "is_anomalous":    s.is_anomalous,
            "anomaly_score":   round(s.anomaly_score, 3) if s.anomaly_score is not None else None,
        })

    sessions_digest.sort(key=lambda x: x["posture_score"])
    sessions_digest = sessions_digest[:8]

    # AI-flagged sessions (Isolation Forest)
    anomaly_sessions = [
        {
            "flow":           f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}",
            "anomaly_score":  round(s.anomaly_score, 3) if s.anomaly_score is not None else None,
            "anomaly_status": s.anomaly_status,
            "top_deviations": list(s.anomaly_features.keys())[:4] if s.anomaly_features else [],
        }
        for s in summary.sessions
        if s.is_anomalous
    ][:5]

    # Aggregate violation counts
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in summary.sessions:
        for v in s.violations:
            sev = getattr(v, "severity", "").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1

    return {
        "capture_file":                   getattr(summary.evidence, "filename", "unknown"),
        "total_sessions":                 len(summary.sessions),
        "enterprise_posture_index":       round(summary.enterprise_posture_index, 1),
        "overall_risk_tier":              summary.overall_risk_tier.value if hasattr(summary.overall_risk_tier, "value") else str(summary.overall_risk_tier),
        "session_tier_breakdown": {
            "CRITICAL": summary.critical_sessions,
            "HIGH":     summary.high_sessions,
            "MEDIUM":   summary.medium_sessions,
            "LOW":      summary.low_sessions,
        },
        "violation_severity_counts":      sev_counts,
        "top_harmonic_drag_contributors": top_risk[:5],
        "worst_sessions_detail":          sessions_digest,
        "ai_flagged_anomalies":           anomaly_sessions,
        "scoring_methodology":            "Volume-weighted harmonic mean EPI (0-100); lower EPI = worse posture",
    }


def _extract_findings_context_from_dict(result_dict: dict) -> dict:
    """
    Build the same context slice from a plain analysis result dict
    (used for the /api/narrative endpoint acting on cached results).
    """
    exp = result_dict.get("enterprise_explanation", {})
    top_risk = exp.get("top_risk_contributors", [])
    sessions = result_dict.get("sessions", [])

    sessions_digest = []
    for s in sessions:
        risk = s.get("risk_tier", "")
        if risk not in ("CRITICAL", "HIGH"):
            continue
        top_viols = [
            {
                "code":        v.get("code", ""),
                "severity":    v.get("severity", ""),
                "description": v.get("description", "")[:120],
            }
            for v in s.get("violations", [])
            if v.get("severity", "") in ("CRITICAL", "HIGH")
        ][:4]
        sessions_digest.append({
            "flow":            f"{s.get('src_ip')}:{s.get('src_port')} -> {s.get('dst_ip')}:{s.get('dst_port')}",
            "protocol":        s.get("protocol", "UNKNOWN"),
            "channel_type":    s.get("channel_type", "Unknown"),
            "tls_version":     s.get("tls_version"),
            "starttls_status": s.get("starttls_status"),
            "risk_tier":       risk,
            "posture_score":   round(s.get("posture_score", 0.0), 1),
            "top_violations":  top_viols,
            "is_anomalous":    s.get("ml_anomaly", {}).get("is_anomalous", False),
            "anomaly_score":   s.get("ml_anomaly", {}).get("anomaly_score"),
        })

    sessions_digest.sort(key=lambda x: x["posture_score"])
    sessions_digest = sessions_digest[:8]

    anomaly_sessions = [
        {
            "flow":           f"{s.get('src_ip')}:{s.get('src_port')} -> {s.get('dst_ip')}:{s.get('dst_port')}",
            "anomaly_score":  s.get("ml_anomaly", {}).get("anomaly_score"),
            "anomaly_status": s.get("ml_anomaly", {}).get("status"),
            "top_deviations": list((s.get("ml_anomaly", {}).get("top_features") or {}).keys())[:4],
        }
        for s in sessions
        if s.get("ml_anomaly", {}).get("is_anomalous", False)
    ][:5]

    sev_counts = result_dict.get("violation_severity_breakdown", {})
    tier_breakdown = result_dict.get("session_tier_breakdown", {})

    return {
        "capture_file":                   result_dict.get("evidence", {}).get("filename", "unknown"),
        "total_sessions":                 result_dict.get("session_count", len(sessions)),
        "enterprise_posture_index":       round(result_dict.get("enterprise_posture_index", 0.0), 1),
        "overall_risk_tier":              result_dict.get("overall_risk_tier", "UNKNOWN"),
        "session_tier_breakdown":         tier_breakdown,
        "violation_severity_counts":      sev_counts,
        "top_harmonic_drag_contributors": top_risk[:5],
        "worst_sessions_detail":          sessions_digest,
        "ai_flagged_anomalies":           anomaly_sessions,
        "scoring_methodology":            "Volume-weighted harmonic mean EPI (0-100); lower EPI = worse posture",
    }


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _get_api_key() -> Optional[str]:
    """Resolve the Gemini API key from environment variables."""
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or None


def _is_transient_error(exc: Exception) -> bool:
    """Return True if an exception represents a transient/recoverable API error (503, 429, 500, etc.)."""
    err_str = str(exc).lower()
    return any(
        indicator in err_str
        for indicator in (
            "503",
            "unavailable",
            "high demand",
            "429",
            "resource_exhausted",
            "rate limit",
            "500",
            "internal",
            "504",
            "gateway",
            "timeout",
        )
    )


def _call_gemini(findings_context: dict, model: str = _DEFAULT_MODEL) -> NarrativeResult:
    """
    Call the Gemini API with the structured findings context and return a NarrativeResult.
    Handles automatic retry with backoff and graceful fallback across alternative models
    if the primary model encounters a temporary 503 UNAVAILABLE / high demand condition.
    All exceptions are caught and returned as a skipped/error result.
    """
    api_key = _get_api_key()
    if not api_key:
        logger.info("Narrative generation skipped: no GEMINI_API_KEY / GOOGLE_API_KEY set.")
        return NarrativeResult(
            skipped_reason="NO_API_KEY",
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        findings_json = json.dumps(findings_context, indent=2, default=str)
        user_prompt = _USER_PROMPT_TEMPLATE.format(findings_json=findings_json)

        # Build candidate models list (primary requested model first, then unique fallbacks)
        candidate_models = [model]
        for fallback in _FALLBACK_MODELS:
            if fallback not in candidate_models:
                candidate_models.append(fallback)

        last_exc: Optional[Exception] = None

        for m_idx, current_model in enumerate(candidate_models):
            # Up to 2 attempts per candidate model for transient spikes
            for attempt in range(1, 3):
                try:
                    response = client.models.generate_content(
                        model=current_model,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=_SYSTEM_PROMPT,
                            temperature=0.3,        # Low temperature for consistent, factual prose
                            max_output_tokens=1024,
                            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                        ),
                    )

                    narrative_text = response.text or ""

                    # Extract token usage if available
                    token_usage = None
                    if hasattr(response, "usage_metadata") and response.usage_metadata:
                        um = response.usage_metadata
                        token_usage = {
                            "prompt_tokens":     getattr(um, "prompt_token_count", None),
                            "candidates_tokens": getattr(um, "candidates_token_count", None),
                            "total_tokens":      getattr(um, "total_token_count", None),
                        }

                    logger.info(
                        "Narrative generated via %s (%s tokens)",
                        current_model,
                        token_usage.get("total_tokens") if token_usage else "?",
                    )

                    return NarrativeResult(
                        narrative=narrative_text.strip(),
                        model=current_model,
                        generated_at=datetime.now(timezone.utc).isoformat(),
                        token_usage=token_usage,
                    )

                except Exception as exc:
                    last_exc = exc
                    if _is_transient_error(exc):
                        if attempt < 2:
                            logger.info(
                                "Model %s transient error (attempt %d/2): %s. Retrying in 1s...",
                                current_model,
                                attempt,
                                exc,
                            )
                            time.sleep(1.0)
                            continue
                        else:
                            if m_idx + 1 < len(candidate_models):
                                next_model = candidate_models[m_idx + 1]
                                logger.warning(
                                    "Model %s unavailable after retries (%s). Falling back to %s...",
                                    current_model,
                                    exc,
                                    next_model,
                                )
                            break
                    else:
                        # Non-transient error (auth error, schema error, etc.)
                        raise exc

        if last_exc:
            raise last_exc

    except ImportError:
        logger.warning("google-genai package not installed; skipping narrative generation.")
        return NarrativeResult(
            skipped_reason="PACKAGE_NOT_INSTALLED",
            generated_at=datetime.now(timezone.utc).isoformat(),
            error_detail="Install google-genai: uv pip install google-genai",
        )
    except Exception as exc:
        logger.warning("Narrative generation failed: %s", exc, exc_info=True)
        return NarrativeResult(
            skipped_reason="API_ERROR",
            generated_at=datetime.now(timezone.utc).isoformat(),
            error_detail=str(exc),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_narrative(summary: Any, model: str = _DEFAULT_MODEL) -> NarrativeResult:
    """
    Generate an LLM executive narrative from an EnterpriseSummary object.

    Args:
        summary: A core.models.EnterpriseSummary instance.
        model:   Gemini model name (default: gemini-2.5-flash).

    Returns:
        NarrativeResult with narrative text, or skipped_reason if generation
        was bypassed (no API key, package missing, API error).
    """
    try:
        context = _extract_findings_context(summary)
    except Exception as exc:
        logger.warning("Failed to extract findings context: %s", exc)
        return NarrativeResult(
            skipped_reason="CONTEXT_EXTRACTION_ERROR",
            generated_at=datetime.now(timezone.utc).isoformat(),
            error_detail=str(exc),
        )
    return _call_gemini(context, model=model)


def generate_narrative_from_dict(result_dict: dict, model: str = _DEFAULT_MODEL) -> NarrativeResult:
    """
    Generate an LLM executive narrative from a plain analysis result dictionary
    (e.g. from a cached history record). Used by the /api/narrative endpoint.

    Args:
        result_dict: The dict representation of an EnterpriseSummary (from .to_dict()).
        model:       Gemini model name (default: gemini-2.5-flash).

    Returns:
        NarrativeResult with narrative text or skipped_reason.
    """
    try:
        context = _extract_findings_context_from_dict(result_dict)
    except Exception as exc:
        logger.warning("Failed to extract findings context from dict: %s", exc)
        return NarrativeResult(
            skipped_reason="CONTEXT_EXTRACTION_ERROR",
            generated_at=datetime.now(timezone.utc).isoformat(),
            error_detail=str(exc),
        )
    return _call_gemini(context, model=model)
