"""TTP tagger: free log text -> top-k MITRE ATT&CK techniques (TF-IDF).

Why TF-IDF and not dense embeddings (sentence-transformers / OpenAI)?
=====================================================================

1. **Air-gap compatibility.** A pre-trained transformer requires either
   a large model file shipped with the deliverable (heavy, non-trivial
   to validate cryptographically) or an outbound download on first run
   (forbidden in our threat model). TF-IDF fits the entire vocabulary
   locally from the MITRE snapshot in <1 second.

2. **Auditability.** Each technique score can be decomposed back into
   `(term, weight, idf)` triples. We expose this via `rationale_terms`,
   so any explanation we give to a Marine officer can be traced to the
   exact terms in the log that matched the technique description.

3. **Vocabulary fit.** ATT&CK descriptions are dense in domain-specific
   jargon (`mimikatz`, `kerberos`, `jndi`, `eventcode`). IDF amplifies
   the rare/discriminative terms precisely — which is what we want.

We deliberately preserve special characters typical of attacks
(`-`, `_`, `:`, `/`) by overriding the default sklearn token pattern
to capture sequences like `powershell -enc`, `jndi:ldap://`, etc.

The tagger is a plain class with `fit` and `predict_top_k` so it can
be swapped for a dense-embedding implementation later without changing
its callers (`BaseTtpTagger`-style polymorphism is straightforward).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from marine_log_sentinel.ml.models import TtpHit
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.threat_intel import ThreatIntelSnapshot
from marine_log_sentinel.threat_intel.models import MitreTechnique

LOGGER = get_logger(__name__)

_TOKEN_PATTERN = r"(?u)[A-Za-z][A-Za-z0-9_\-]+"

_DEFAULT_STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "by",
        "with",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "as",
        "at",
        "from",
        "but",
        "not",
        "may",
        "can",
        "will",
        "would",
        "could",
        "should",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "use",
        "uses",
        "used",
        "using",
        "also",
        "via",
        "such",
        "their",
        "they",
        "them",
        "i",
        "you",
        "he",
        "she",
        "we",
        "our",
        "your",
        "his",
        "her",
    }
)


def _technique_corpus(technique: MitreTechnique, snapshot: ThreatIntelSnapshot) -> str:
    """Build the searchable text for one technique.

    The text is a concatenation of:
      - The technique's identifier, name, description.
      - Tactic names (short + long) it belongs to.
      - The names of immediate relatives (parent + sub-techniques) so
        e.g. "PowerShell" mentioned only in T1059.001 still informs the
        parent T1059 match.
      - **The descriptions of every CVE that references the technique**.
        This is a deliberate design choice: a technique like T1190
        ("Exploit Public-Facing Application") is intentionally generic
        in MITRE's official description, but the CVEs that map to it
        (Log4Shell, ProxyShell, ...) provide very specific vocabulary
        (`jndi`, `ldap`, `deserialization`, ...). Folding the CVE text
        in here turns the TF-IDF index from a pure ATT&CK matcher into
        a CVE-informed ATT&CK matcher — and it stays fully auditable
        because the index input is just text from feeds we control.
    """

    parts: list[str] = [technique.external_id, technique.name]
    if technique.description:
        parts.append(technique.description)
    for tactic_short in technique.tactics:
        tactic = snapshot.tactics.get(tactic_short)
        if tactic is not None:
            parts.append(tactic.name)
            parts.append(tactic_short.replace("-", " "))
    if technique.parent_external_id:
        parent = snapshot.lookup_technique(technique.parent_external_id)
        if parent is not None:
            parts.append(parent.name)
    for sub_id in technique.sub_technique_external_ids[:6]:
        sub = snapshot.lookup_technique(sub_id)
        if sub is not None:
            parts.append(sub.name)
    for cve_id in technique.related_cves[:16]:
        cve = snapshot.lookup_cve(cve_id)
        if cve is None:
            continue
        parts.append(cve.cve_id)
        if cve.description:
            parts.append(cve.description)
        for software in cve.affected_software[:3]:
            parts.append(software)
    return " \n ".join(parts)


@dataclass
class TaggerArtifacts:
    """In-memory artifacts produced by the tagger after fitting."""

    technique_ids: list[str]
    vectorizer: TfidfVectorizer
    technique_matrix: object
    snapshot_signature: str


class MitreTtpTagger:
    """TF-IDF tagger over the MITRE Enterprise corpus."""

    def __init__(
        self,
        *,
        ngram_range: tuple[int, int] = (1, 2),
        min_df: int = 1,
        max_df: float = 0.85,
        sublinear_tf: bool = True,
    ) -> None:
        self.ngram_range = ngram_range
        self.min_df = min_df
        self.max_df = max_df
        self.sublinear_tf = sublinear_tf
        self._artifacts: TaggerArtifacts | None = None
        self._snapshot: ThreatIntelSnapshot | None = None

    @property
    def is_fitted(self) -> bool:
        return self._artifacts is not None

    def fit(self, snapshot: ThreatIntelSnapshot) -> "MitreTtpTagger":
        """Build the TF-IDF index from a TI snapshot."""

        techniques = sorted(snapshot.techniques.values(), key=lambda t: t.external_id)
        corpus = [_technique_corpus(tech, snapshot) for tech in techniques]
        vectorizer = TfidfVectorizer(
            lowercase=True,
            token_pattern=_TOKEN_PATTERN,
            ngram_range=self.ngram_range,
            min_df=self.min_df,
            max_df=self.max_df,
            sublinear_tf=self.sublinear_tf,
            stop_words=list(_DEFAULT_STOPWORDS),
        )
        matrix = vectorizer.fit_transform(corpus)
        self._artifacts = TaggerArtifacts(
            technique_ids=[tech.external_id for tech in techniques],
            vectorizer=vectorizer,
            technique_matrix=matrix,
            snapshot_signature=snapshot.mitre_source.sha256[:16],
        )
        self._snapshot = snapshot
        LOGGER.info(
            "ml.tagger.fit.ok",
            extra={
                "techniques": len(corpus),
                "vocab_size": len(vectorizer.vocabulary_),
                "signature": self._artifacts.snapshot_signature,
            },
        )
        return self

    def _ensure_fitted(self) -> TaggerArtifacts:
        if self._artifacts is None or self._snapshot is None:
            raise RuntimeError("MitreTtpTagger must be fit(snapshot) before predict.")
        return self._artifacts

    def predict_top_k(
        self,
        text: str,
        k: int = 5,
        *,
        min_score: float = 0.05,
    ) -> list[TtpHit]:
        """Return the top-k matching techniques for a piece of text.

        `min_score` filters out near-zero similarities (noise). The
        rationale_terms are the most-contributing TF-IDF terms shared
        between the log text and the technique description.
        """

        artifacts = self._ensure_fitted()
        snapshot = self._snapshot
        assert snapshot is not None

        if not text or not text.strip():
            return []

        query_vec = artifacts.vectorizer.transform([text])
        if query_vec.nnz == 0:
            return []

        sims = cosine_similarity(query_vec, artifacts.technique_matrix).ravel()
        top_indices = np.argsort(-sims)[: max(k * 2, k)]
        hits: list[TtpHit] = []
        for idx in top_indices:
            score = float(sims[idx])
            if score < min_score:
                continue
            tech_id = artifacts.technique_ids[idx]
            technique = snapshot.lookup_technique(tech_id)
            if technique is None:
                continue
            rationale = _rationale_terms(
                artifacts.vectorizer,
                query_vec,
                artifacts.technique_matrix[idx],
                top_n=5,
            )
            hits.append(
                TtpHit(
                    technique_id=technique.external_id,
                    technique_name=technique.name,
                    score=score,
                    tactics=list(technique.tactics),
                    is_subtechnique=technique.is_subtechnique,
                    parent_external_id=technique.parent_external_id,
                    rationale_terms=rationale,
                )
            )
            if len(hits) >= k:
                break
        return hits

    def batch_predict_top_k(
        self,
        texts: Iterable[str],
        k: int = 5,
        *,
        min_score: float = 0.05,
    ) -> list[list[TtpHit]]:
        """Vectorized batch variant for the ingestion-time pipeline."""

        artifacts = self._ensure_fitted()
        snapshot = self._snapshot
        assert snapshot is not None

        texts_list = [t if t else "" for t in texts]
        query_matrix = artifacts.vectorizer.transform(texts_list)
        sims = cosine_similarity(query_matrix, artifacts.technique_matrix)
        results: list[list[TtpHit]] = []
        for row_idx, row in enumerate(sims):
            if query_matrix[row_idx].nnz == 0:
                results.append([])
                continue
            top_indices = np.argsort(-row)[: max(k * 2, k)]
            hits: list[TtpHit] = []
            for idx in top_indices:
                score = float(row[idx])
                if score < min_score:
                    continue
                tech_id = artifacts.technique_ids[idx]
                technique = snapshot.lookup_technique(tech_id)
                if technique is None:
                    continue
                rationale = _rationale_terms(
                    artifacts.vectorizer,
                    query_matrix[row_idx],
                    artifacts.technique_matrix[idx],
                    top_n=5,
                )
                hits.append(
                    TtpHit(
                        technique_id=technique.external_id,
                        technique_name=technique.name,
                        score=score,
                        tactics=list(technique.tactics),
                        is_subtechnique=technique.is_subtechnique,
                        parent_external_id=technique.parent_external_id,
                        rationale_terms=rationale,
                    )
                )
                if len(hits) >= k:
                    break
            results.append(hits)
        return results


def _rationale_terms(
    vectorizer: TfidfVectorizer,
    query_vec,
    technique_vec,
    *,
    top_n: int = 5,
) -> list[str]:
    """Return the most-contributing shared terms between a query and a technique.

    The contribution score is the element-wise product of the two TF-IDF
    vectors: only terms present in both contribute, weighted by their
    combined importance (the heavier they are, the more they explain the
    cosine similarity).
    """

    q_array = query_vec.toarray().ravel()
    t_array = technique_vec.toarray().ravel()
    contributions = q_array * t_array
    if contributions.sum() == 0:
        return []
    nonzero_indices = np.nonzero(contributions)[0]
    if nonzero_indices.size == 0:
        return []
    top = nonzero_indices[np.argsort(-contributions[nonzero_indices])[:top_n]]
    feature_names = vectorizer.get_feature_names_out()
    return [str(feature_names[i]) for i in top]


_SUSPICION_RE = re.compile(
    r"(?ix) "
    r"(?:powershell|cmd\.exe|whoami|net\suser|wmic|mimikatz|rundll32|"
    r"regsvr32|certutil|bitsadmin|psexec|net\sview|netstat|nmap|"
    r"jndi:|ldap://|rmi://|nslookup|getcurrentdir|wget|curl\s)"
)


def expand_query_text(text: str) -> str:
    """Boost the relative weight of known attacker tokens in the query.

    Some log fields are very short (one URL, one process name) and risk
    getting drowned by long template noise. We duplicate matched attacker
    keywords so they carry more weight at TF-IDF transform time. This is
    a pragmatic heuristic, not a model: easy to defend in court.
    """

    if not text:
        return text
    matches = _SUSPICION_RE.findall(text)
    if not matches:
        return text
    return text + " " + " ".join(matches)
