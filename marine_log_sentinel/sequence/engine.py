"""Apply sequential same-actor policy to chronologically ordered scored logs."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import List

from marine_log_sentinel.scoring.models import ScoredLog
from marine_log_sentinel.sequence.actors import derive_actor_key
from marine_log_sentinel.sequence.policy import (
    DEFAULT_SEQUENCE_POLICY,
    SequencePolicy,
    compute_sequence_context,
)
from marine_log_sentinel.sequence.store import ActorRow, SequenceStore
from marine_log_sentinel.scoring.weights import DEFAULT_BANDS


def _merge_summary(
    *,
    prev_peak: float,
    gap_days: float,
    tau: float,
    effective: float,
    static_score: float,
) -> float:
    """Update stored peak: carry forward decayed history and take the new high."""

    if gap_days <= 0:
        decayed = prev_peak
    else:
        decayed = prev_peak * math.exp(-gap_days / tau)
    return float(min(100.0, max(effective, decayed, static_score)))


def apply_sequential_scoring(
    chronological: List[ScoredLog],
    store: SequenceStore,
    policy: SequencePolicy = DEFAULT_SEQUENCE_POLICY,
) -> List[ScoredLog]:
    """Walk events in time order, merge with DB state, persist, return enriched copies.

    Each returned :class:`ScoredLog` has ``score`` / ``severity_band`` **effective**
    (merged). Point-in-time scoring remains in ``breakdown`` and in
    ``sequence.point_in_time_*``.
    """

    out: list[ScoredLog] = []
    for scored in chronological:
        pred = scored.prediction
        actor_key = derive_actor_key(pred)
        now: datetime = pred.timestamp_utc
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        row: ActorRow | None = store.fetch_actor(actor_key)
        cur_ttp = (
            scored.evidence.top_ttp.technique_id
            if scored.evidence and scored.evidence.top_ttp
            else ""
        )

        if row is None:
            first_seen = None
            last_seen = None
            peak = 0.0
            last_ttp: str | None = None
            ttp_streak = 1
            chain_index = 1
        else:
            first_seen = row.first_seen
            last_seen = row.last_seen
            peak = row.peak_effective
            last_ttp = row.last_top_ttp
            chain_index = row.event_count + 1
            if cur_ttp and last_ttp and cur_ttp == last_ttp:
                ttp_streak = row.ttp_streak + 1
            else:
                ttp_streak = 1

        eff_score, eff_band, ctx = compute_sequence_context(
            scored,
            actor_key=actor_key,
            chain_index=chain_index,
            now=now,
            first_seen=first_seen,
            last_seen=last_seen,
            peak_effective=peak,
            last_top_ttp=last_ttp,
            ttp_streak=ttp_streak,
            policy=policy,
            bands=DEFAULT_BANDS,
        )

        gap_days = 0.0
        if last_seen is not None:
            gap_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)

        new_peak = _merge_summary(
            prev_peak=peak,
            gap_days=gap_days,
            tau=policy.tau_peak_decay_days,
            effective=eff_score,
            static_score=scored.score,
        )

        excerpt = pred.raw_excerpt.replace("\n", " ")[:400]
        store.commit_event(
            actor_key=actor_key,
            event_ts=now,
            ctx=ctx,
            source_file=pred.source_file,
            excerpt=excerpt,
            new_peak_effective=new_peak,
            new_last_top_ttp=cur_ttp or None,
            new_ttp_streak=ttp_streak,
        )

        enriched = scored.model_copy(
            update={
                "score": eff_score,
                "severity_band": eff_band,
                "sequence": ctx,
            }
        )
        out.append(enriched)

    return out


def sort_chronological(scored: List[ScoredLog]) -> List[ScoredLog]:
    return sorted(scored, key=lambda s: s.prediction.timestamp_utc)


def sort_by_priority(scored: List[ScoredLog]) -> List[ScoredLog]:
    return sorted(scored, key=lambda s: (-s.score, s.prediction.timestamp_utc))
