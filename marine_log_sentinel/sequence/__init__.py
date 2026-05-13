"""Same-actor sequential risk: SQLite memory + time-decayed merge policy."""

from marine_log_sentinel.sequence.actors import derive_actor_key
from marine_log_sentinel.sequence.engine import apply_sequential_scoring
from marine_log_sentinel.sequence.policy import DEFAULT_SEQUENCE_POLICY, SequencePolicy
from marine_log_sentinel.sequence.store import SequenceStore

__all__ = [
    "DEFAULT_SEQUENCE_POLICY",
    "SequencePolicy",
    "SequenceStore",
    "apply_sequential_scoring",
    "derive_actor_key",
]
