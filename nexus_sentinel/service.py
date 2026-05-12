from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from nexus_sentinel.detector import DetectionResult, analyze_url_with_live_checks


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
        database_path = str(self._storage_path) if self._storage_path else ":memory:"
        self._connection = sqlite3.connect(database_path)
        self._connection.row_factory = sqlite3.Row
        self._initialize_schema()

    def analyze(self, url: str, save: bool = True) -> AnalysisRecord:
        detection = analyze_url_with_live_checks(url, live_fetcher=self._live_fetcher)
        similar_group_id = _similar_group_id_for(detection.extracted_features)
        saved_count = self._count_saved_records_for_group(similar_group_id)
        similar_group_size = saved_count + 1

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
            self._insert_record(record)
        return record

    def list_similar_groups(self) -> list[dict[str, object]]:
        grouped: dict[str, dict[str, object]] = {}

        for record in self._saved_records():
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
                for record in self._saved_records()
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
        cursor = self._connection.execute(
            """
            SELECT COUNT(*) AS total_scans,
                   COUNT(DISTINCT similar_group_id) AS active_similar_groups,
                   COALESCE(MAX(risk_score), 0) AS highest_risk
            FROM scans
            """
        )
        row = cursor.fetchone()
        return {
            "total_scans": int(row["total_scans"] or 0),
            "active_similar_groups": int(row["active_similar_groups"] or 0),
            "highest_risk": int(row["highest_risk"] or 0),
        }

    def clear_saved_history(self) -> None:
        self._connection.execute("DELETE FROM scans")
        self._connection.commit()

    def _initialize_schema(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                saved_to_history INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                risk_factors_json TEXT NOT NULL,
                extracted_features_json TEXT NOT NULL,
                score_breakdown_json TEXT NOT NULL,
                content_analysis_json TEXT NOT NULL,
                redirect_analysis_json TEXT NOT NULL,
                similar_group_id TEXT NOT NULL,
                similar_group_size INTEGER NOT NULL
            )
            """
        )
        self._connection.commit()

    def _insert_record(self, record: AnalysisRecord) -> None:
        self._connection.execute(
            """
            INSERT INTO scans (
                url,
                analyzed_at,
                saved_to_history,
                risk_score,
                classification,
                risk_factors_json,
                extracted_features_json,
                score_breakdown_json,
                content_analysis_json,
                redirect_analysis_json,
                similar_group_id,
                similar_group_size
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.url,
                record.analyzed_at,
                1 if record.saved_to_history else 0,
                record.risk_score,
                record.classification,
                json.dumps(record.risk_factors),
                json.dumps(record.extracted_features),
                json.dumps(record.score_breakdown),
                json.dumps(record.content_analysis),
                json.dumps(record.redirect_analysis),
                record.similar_group_id,
                record.similar_group_size,
            ),
        )
        self._connection.commit()

    def _saved_records(self) -> list[AnalysisRecord]:
        cursor = self._connection.execute(
            """
            SELECT url,
                   analyzed_at,
                   saved_to_history,
                   risk_score,
                   classification,
                   risk_factors_json,
                   extracted_features_json,
                   score_breakdown_json,
                   content_analysis_json,
                   redirect_analysis_json,
                   similar_group_id,
                   similar_group_size
            FROM scans
            ORDER BY analyzed_at ASC
            """
        )
        return [self._row_to_record(row) for row in cursor.fetchall()]

    def _count_saved_records_for_group(self, similar_group_id: str) -> int:
        cursor = self._connection.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE similar_group_id = ?",
            (similar_group_id,),
        )
        row = cursor.fetchone()
        return int(row["count"] or 0)

    def _row_to_record(self, row: sqlite3.Row) -> AnalysisRecord:
        return AnalysisRecord(
            url=str(row["url"]),
            analyzed_at=str(row["analyzed_at"]),
            saved_to_history=bool(row["saved_to_history"]),
            risk_score=int(row["risk_score"]),
            classification=str(row["classification"]),
            risk_factors=tuple(json.loads(row["risk_factors_json"])),
            extracted_features=dict(json.loads(row["extracted_features_json"])),
            score_breakdown=tuple(json.loads(row["score_breakdown_json"])),
            content_analysis=dict(json.loads(row["content_analysis_json"])),
            redirect_analysis=dict(json.loads(row["redirect_analysis_json"])),
            similar_group_id=str(row["similar_group_id"]),
            similar_group_size=int(row["similar_group_size"]),
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
        traits.append("No HTTPS across scans")
    if all(feature.get("is_ip_hostname") is True for feature in features):
        traits.append("IP-based hostnames")
    if all(feature.get("has_suspicious_tld") is True for feature in features):
        traits.append("High-risk TLDs")
    if all((feature.get("subdomain_count") or 0) >= 3 for feature in features):
        traits.append("Many subdomains")

    keyword_sets = [
        set(feature.get("suspicious_keywords", ()))
        for feature in features
        if feature.get("suspicious_keywords")
    ]
    if keyword_sets:
        shared_keywords = sorted(set.intersection(*keyword_sets))
        if shared_keywords:
            traits.append("Shared keywords: " + ", ".join(shared_keywords[:2]))

    return traits[:3]


def _grouping_reason(similar_group: dict[str, object]) -> str:
    shared_traits = list(similar_group.get("shared_traits", ()))
    if shared_traits:
        return "This group matches the same suspicious link pattern and repeated signs."
    return "This group matches the same suspicious link pattern."
