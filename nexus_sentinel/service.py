from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from nexus_sentinel.detector import analyze_url_with_live_checks


LiveFetcher = Callable[[str], tuple[dict[str, object], dict[str, object]]]


@dataclass(frozen=True)
class AnalysisRecord:
    url: str
    analyzed_at: str
    saved_to_history: bool
    risk_score: int
    classification: str
    risk_factors: tuple[str, ...]
    extracted_features: dict[str, object]
    score_breakdown: tuple[dict[str, object], ...]
    content_analysis: dict[str, object]
    redirect_analysis: dict[str, object]
    similar_group_id: str
    similar_group_size: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AnalysisService:
    def __init__(
        self,
        storage_path: str | Path | None = None,
        live_fetcher: LiveFetcher | None = None,
    ) -> None:
        self._storage_path = Path(storage_path) if storage_path else None
        self._live_fetcher = live_fetcher
        self._records = self._load_records()

    def analyze(self, url: str, save: bool = True) -> AnalysisRecord:
        detection = analyze_url_with_live_checks(url, live_fetcher=self._live_fetcher)
        similar_group_id = _similar_group_id_for(detection.extracted_features)
        similar_group_size = (
            sum(
                1
                for record in self._records
                if record.similar_group_id == similar_group_id
            )
            + 1
        )

        record = AnalysisRecord(
            url=url,
            analyzed_at=_timestamp_now(),
            saved_to_history=save,
            risk_score=detection.risk_score,
            classification=detection.classification,
            risk_factors=detection.risk_factors,
            extracted_features=detection.extracted_features,
            score_breakdown=detection.score_breakdown,
            content_analysis=detection.content_analysis,
            redirect_analysis=detection.redirect_analysis,
            similar_group_id=similar_group_id,
            similar_group_size=similar_group_size,
        )
        if save:
            self._records.append(record)
            self._save_records()
        return record

    def list_similar_groups(self) -> list[dict[str, object]]:
        grouped: dict[str, dict[str, object]] = {}

        for record in self._records:
            similar_group = grouped.setdefault(
                record.similar_group_id,
                {
                    "similar_group_id": record.similar_group_id,
                    "classification": record.classification,
                    "size": 0,
                    "example_urls": [],
                    "common_risk_factors": [],
                    "shared_traits": [],
                    "grouping_reason": "",
                    "first_seen": record.analyzed_at,
                    "latest_seen": record.analyzed_at,
                },
            )
            similar_group["size"] = int(similar_group["size"]) + 1
            example_urls = similar_group["example_urls"]
            if len(example_urls) < 3:
                example_urls.append(record.url)
            similar_group["first_seen"] = min(
                str(similar_group["first_seen"]), record.analyzed_at
            )
            similar_group["latest_seen"] = max(
                str(similar_group["latest_seen"]), record.analyzed_at
            )

        for similar_group in grouped.values():
            group_records = [
                record
                for record in self._records
                if record.similar_group_id == similar_group["similar_group_id"]
            ]
            factor_counts: dict[str, int] = {}
            for record in group_records:
                for factor in record.risk_factors:
                    factor_counts[factor] = factor_counts.get(factor, 0) + 1
            similar_group["common_risk_factors"] = [
                factor
                for factor, _count in sorted(
                    factor_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[:2]
            ]
            similar_group["shared_traits"] = _shared_traits(group_records)
            similar_group["grouping_reason"] = _grouping_reason(similar_group)

        return sorted(
            grouped.values(),
            key=lambda group: (-int(group["size"]), str(group["similar_group_id"])),
        )

    def overview(self) -> dict[str, int]:
        risk_scores = [record.risk_score for record in self._records]
        return {
            "total_scans": len(self._records),
            "active_similar_groups": len(
                {record.similar_group_id for record in self._records}
            ),
            "highest_risk": max(risk_scores, default=0),
        }

    def clear_saved_history(self) -> None:
        self._records = []
        self._save_records()

    def _load_records(self) -> list[AnalysisRecord]:
        if not self._storage_path or not self._storage_path.exists():
            return []

        payload = json.loads(self._storage_path.read_text(encoding="utf-8"))
        return [
            AnalysisRecord(
                url=item["url"],
                analyzed_at=item.get("analyzed_at", _timestamp_now()),
                saved_to_history=bool(item.get("saved_to_history", True)),
                risk_score=item["risk_score"],
                classification=item["classification"],
                risk_factors=tuple(item["risk_factors"]),
                extracted_features=dict(item.get("extracted_features", {})),
                score_breakdown=tuple(item.get("score_breakdown", ())),
                content_analysis=dict(item.get("content_analysis", {})),
                redirect_analysis=dict(item.get("redirect_analysis", {})),
                similar_group_id=item.get(
                    "similar_group_id",
                    _similar_group_id_for(dict(item.get("extracted_features", {}))),
                ),
                similar_group_size=item.get("similar_group_size", 1),
            )
            for item in payload
        ]

    def _save_records(self) -> None:
        if not self._storage_path:
            return

        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = [record.to_dict() for record in self._records]
        self._storage_path.write_text(
            json.dumps(serialized, indent=2),
            encoding="utf-8",
        )


def _similar_group_id_for(features: dict[str, object]) -> str:
    pattern = {
        "has_encoded_characters": features.get("has_encoded_characters"),
        "has_suspicious_tld": features.get("has_suspicious_tld"),
        "hostname_hyphen_count": _bucket(int(features.get("hostname_hyphen_count", 0))),
        "is_ip_hostname": features.get("is_ip_hostname"),
        "keyword_count": len(features.get("suspicious_keywords", [])),
        "keywords": features.get("suspicious_keywords", []),
        "path_depth": _bucket(int(features.get("path_depth", 0))),
        "query_parameter_count": _bucket(int(features.get("query_parameter_count", 0))),
        "subdomain_count": _bucket(int(features.get("subdomain_count", 0))),
        "url_length": _bucket(int(features.get("url_length", 0))),
        "uses_https": features.get("uses_https"),
    }
    encoded = json.dumps(pattern, sort_keys=True).encode("utf-8")
    return "grp_" + hashlib.sha256(encoded).hexdigest()[:12]


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bucket(value: int) -> str:
    if value == 0:
        return "none"
    if value <= 2:
        return "low"
    if value <= 5:
        return "medium"
    return "high"


def _shared_traits(records: list[AnalysisRecord]) -> list[str]:
    if not records:
        return []

    features = [record.extracted_features for record in records]
    traits: list[str] = []

    if all(feature.get("uses_https") is False for feature in features):
        traits.append("No HTTPS across similar links")
    if all(feature.get("is_ip_hostname") is True for feature in features):
        traits.append("IP-based website names")
    if all(feature.get("has_suspicious_tld") is True for feature in features):
        traits.append("Unusual website endings")
    if all((feature.get("subdomain_count") or 0) >= 3 for feature in features):
        traits.append("Many extra subdomains")

    keyword_sets = [
        set(feature.get("suspicious_keywords", ()))
        for feature in features
        if feature.get("suspicious_keywords")
    ]
    if keyword_sets:
        shared_keywords = sorted(set.intersection(*keyword_sets))
        if shared_keywords:
            traits.append("Shared suspicious words: " + ", ".join(shared_keywords[:2]))

    return traits[:3]


def _grouping_reason(similar_group: dict[str, object]) -> str:
    shared_traits = list(similar_group.get("shared_traits", ()))
    if shared_traits:
        return "These links share the same suspicious pattern and repeated warning signs."
    return "These links share the same suspicious pattern."
