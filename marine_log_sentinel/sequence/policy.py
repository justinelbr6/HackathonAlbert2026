"""Auditable parameters for same-actor time merge (long-horizon memory)."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

from marine_log_sentinel.scoring.models import ScoredLog, SequenceContext
from marine_log_sentinel.scoring.weights import DEFAULT_BANDS, SeverityBands


@dataclass(frozen=True)
class SequencePolicy:
    """How point-in-time scores blend with decayed history.

    - ``tau_peak_decay_days`` controls how fast a *past high* fades when the actor
      goes quiet (e.g. years → carry → 0, but slowly).
    - ``blend_carry`` weights the historical carry-in vs the fresh static score.
    - ``repeat_ttp_*`` rewards observing the *same* MITRE technique again for the
      same actor (persistent campaign / habit).
    """

    tau_peak_decay_days: float = 420.0
    blend_carry: float = 0.42
    repeat_ttp_step: float = 3.6
    repeat_ttp_cap: float = 15.0

    def fingerprint(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


DEFAULT_SEQUENCE_POLICY = SequencePolicy()


def compute_sequence_context(
    scored: ScoredLog,
    *,
    actor_key: str,
    chain_index: int,
    now: datetime,
    first_seen: Optional[datetime],
    last_seen: Optional[datetime],
    peak_effective: float,
    last_top_ttp: Optional[str],
    ttp_streak: int,
    policy: SequencePolicy = DEFAULT_SEQUENCE_POLICY,
    bands: SeverityBands = DEFAULT_BANDS,
) -> tuple[float, str, SequenceContext]:
    """Return effective score/band + context row (does not mutate ``scored``)."""

    static_score = scored.score
    static_band = scored.severity_band
    cur_ttp = (
        scored.evidence.top_ttp.technique_id
        if scored.evidence and scored.evidence.top_ttp
        else ""
    )

    days_since_first = 0.0
    if first_seen is not None:
        days_since_first = max(0.0, (now - first_seen).total_seconds() / 86400.0)

    days_since_prev: Optional[float] = None
    decayed_carry = 0.0
    if last_seen is not None:
        days_since_prev = max(0.0, (now - last_seen).total_seconds() / 86400.0)
        decayed_carry = peak_effective * math.exp(-days_since_prev / policy.tau_peak_decay_days)

    ttp_bonus = 0.0
    if ttp_streak > 1 and cur_ttp:
        ttp_bonus = min(
            policy.repeat_ttp_cap,
            (ttp_streak - 1) * policy.repeat_ttp_step,
        )

    blended = (
        static_score * (1.0 - policy.blend_carry)
        + decayed_carry * policy.blend_carry
        + ttp_bonus
    )
    effective = float(min(100.0, max(static_score, blended)))
    eff_band = bands.classify(effective)

    rationale_parts = [
        f"Acteur {actor_key} — événement #{chain_index} dans la chaîne stockée.",
        f"Score ponctuel {static_score:.1f} ({static_band}), "
        f"mémoire décroissante sur le pic précédent = {decayed_carry:.1f} pts.",
    ]
    if days_since_prev is not None:
        rationale_parts.append(f"Écart avec l'événement précédent : {days_since_prev:.1f} j.")
    if ttp_bonus > 0:
        rationale_parts.append(
            f"Majoration cohérence TTP répété ({cur_ttp}) : +{ttp_bonus:.1f} pts."
        )
    rationale_fr = " ".join(rationale_parts)

    ctx = SequenceContext(
        actor_key=actor_key,
        chain_index=chain_index,
        point_in_time_score=static_score,
        point_in_time_band=static_band,
        effective_score=effective,
        effective_band=eff_band,
        days_since_actor_first_event=days_since_first,
        days_since_previous_event=days_since_prev,
        decayed_peak_carry_in=decayed_carry,
        ttp_repeat_bonus=ttp_bonus,
        policy_fingerprint=policy.fingerprint(),
        rationale_fr=rationale_fr,
    )
    return effective, eff_band, ctx
