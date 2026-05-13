"""Persistent SQLite backing store for same-actor event chains."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from marine_log_sentinel.scoring.models import SequenceContext


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@dataclass(frozen=True)
class ActorRow:
    actor_key: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    peak_effective: float
    last_top_ttp: Optional[str]
    ttp_streak: int


class SequenceStore:
    """Append-only event log + rolling per-actor summary row."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS actors (
                  actor_key TEXT PRIMARY KEY,
                  first_seen TEXT NOT NULL,
                  last_seen TEXT NOT NULL,
                  event_count INTEGER NOT NULL,
                  peak_effective REAL NOT NULL,
                  last_top_ttp TEXT,
                  ttp_streak INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS actor_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  actor_key TEXT NOT NULL,
                  event_ts TEXT NOT NULL,
                  static_score REAL NOT NULL,
                  effective_score REAL NOT NULL,
                  static_band TEXT NOT NULL,
                  effective_band TEXT NOT NULL,
                  sequence_json TEXT NOT NULL,
                  source_file TEXT,
                  excerpt TEXT,
                  FOREIGN KEY(actor_key) REFERENCES actors(actor_key)
                );
                CREATE INDEX IF NOT EXISTS idx_ae_actor_ts ON actor_events(actor_key, event_ts);
                """
            )

    def fetch_actor(self, actor_key: str) -> Optional[ActorRow]:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT actor_key, first_seen, last_seen, event_count, "
                "peak_effective, last_top_ttp, ttp_streak FROM actors WHERE actor_key = ?",
                (actor_key,),
            ).fetchone()
        if row is None:
            return None
        return ActorRow(
            actor_key=row[0],
            first_seen=_parse_iso(row[1]),
            last_seen=_parse_iso(row[2]),
            event_count=int(row[3]),
            peak_effective=float(row[4]),
            last_top_ttp=row[5],
            ttp_streak=int(row[6]),
        )

    def commit_event(
        self,
        *,
        actor_key: str,
        event_ts: datetime,
        ctx: SequenceContext,
        source_file: str,
        excerpt: str,
        new_peak_effective: float,
        new_last_top_ttp: Optional[str],
        new_ttp_streak: int,
    ) -> None:
        """Transactionally append the event and upsert actor summary."""

        sj = ctx.model_dump_json()
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.cursor()
            row = cur.execute(
                "SELECT actor_key FROM actors WHERE actor_key = ?", (actor_key,)
            ).fetchone()
            ts = _iso(event_ts)
            if row is None:
                cur.execute(
                    "INSERT INTO actors(actor_key, first_seen, last_seen, event_count, "
                    "peak_effective, last_top_ttp, ttp_streak) VALUES(?,?,?,?,?,?,?)",
                    (
                        actor_key,
                        ts,
                        ts,
                        1,
                        new_peak_effective,
                        new_last_top_ttp,
                        new_ttp_streak,
                    ),
                )
            else:
                cur.execute(
                    "UPDATE actors SET last_seen = ?, event_count = event_count + 1, "
                    "peak_effective = ?, last_top_ttp = ?, ttp_streak = ? WHERE actor_key = ?",
                    (
                        ts,
                        new_peak_effective,
                        new_last_top_ttp,
                        new_ttp_streak,
                        actor_key,
                    ),
                )
            cur.execute(
                "INSERT INTO actor_events(actor_key, event_ts, static_score, effective_score, "
                "static_band, effective_band, sequence_json, source_file, excerpt) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    actor_key,
                    ts,
                    ctx.point_in_time_score,
                    ctx.effective_score,
                    ctx.point_in_time_band,
                    ctx.effective_band,
                    sj,
                    source_file,
                    excerpt[:2000],
                ),
            )
            conn.commit()

    def stats(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as conn:
            n_act = conn.execute("SELECT COUNT(*) FROM actors").fetchone()[0]
            n_ev = conn.execute("SELECT COUNT(*) FROM actor_events").fetchone()[0]
        return {"actors": n_act, "events": n_ev}
