import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from nexus_sentinel.detector import analyze_url


@dataclass(frozen=True)
class AnalysisRecord:
    url: str
    analyzed_at: str
    risk_score: int
    classification: str
    risk_factors: tuple[str, ...]
    threat_fingerprint_id: str
    extracted_features: dict[str, object]
    score_breakdown: tuple[dict[str, object], ...]
    content_analysis: dict[str, object]
    redirect_analysis: dict[str, object]
    campaign_id: str
    campaign_size: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AnalysisService:
    def __init__(self, storage_path: str | Path | None = None) -> None:
        self._storage_path = Path(storage_path) if storage_path else None
        self._records = self._load_records()

    def analyze(self, url: str) -> AnalysisRecord:
        detection = analyze_url(url)
        campaign_id = _campaign_id_for(detection.threat_fingerprint_id)
        campaign_size = (
            sum(1 for record in self._records if record.campaign_id == campaign_id) + 1
        )

        record = AnalysisRecord(
            url=url,
            analyzed_at=_timestamp_now(),
            risk_score=detection.risk_score,
            classification=detection.classification,
            risk_factors=detection.risk_factors,
            threat_fingerprint_id=detection.threat_fingerprint_id,
            extracted_features=detection.extracted_features,
            score_breakdown=detection.score_breakdown,
            content_analysis=detection.content_analysis,
            redirect_analysis=detection.redirect_analysis,
            campaign_id=campaign_id,
            campaign_size=campaign_size,
        )
        self._records.append(record)
        self._save_records()
        return record

    def list_campaigns(self) -> list[dict[str, object]]:
        grouped: dict[str, dict[str, object]] = {}

        for record in self._records:
            campaign = grouped.setdefault(
                record.campaign_id,
                {
                    "campaign_id": record.campaign_id,
                    "threat_fingerprint_id": record.threat_fingerprint_id,
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
            campaign["size"] = int(campaign["size"]) + 1
            example_urls = campaign["example_urls"]
            if len(example_urls) < 3:
                example_urls.append(record.url)
            campaign["first_seen"] = min(str(campaign["first_seen"]), record.analyzed_at)
            campaign["latest_seen"] = max(
                str(campaign["latest_seen"]), record.analyzed_at
            )

        for campaign in grouped.values():
            campaign_records = [
                record
                for record in self._records
                if record.campaign_id == campaign["campaign_id"]
            ]
            factor_counts: dict[str, int] = {}
            for record in campaign_records:
                for factor in record.risk_factors:
                    factor_counts[factor] = factor_counts.get(factor, 0) + 1
            campaign["common_risk_factors"] = [
                factor
                for factor, _count in sorted(
                    factor_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[:2]
            ]
            campaign["shared_traits"] = _shared_traits(campaign_records)
            campaign["grouping_reason"] = _grouping_reason(campaign)

        return sorted(
            grouped.values(),
            key=lambda campaign: (-int(campaign["size"]), str(campaign["campaign_id"])),
        )

    def overview(self) -> dict[str, int]:
        risk_scores = [record.risk_score for record in self._records]
        return {
            "total_scans": len(self._records),
            "active_campaigns": len(
                {record.campaign_id for record in self._records}
            ),
            "highest_risk": max(risk_scores, default=0),
        }

    def recent_scans(self, limit: int = 10) -> list[dict[str, object]]:
        return [record.to_dict() for record in reversed(self._records[-limit:])]

    def _load_records(self) -> list[AnalysisRecord]:
        if not self._storage_path or not self._storage_path.exists():
            return []

        payload = json.loads(self._storage_path.read_text(encoding="utf-8"))
        return [
            AnalysisRecord(
                url=item["url"],
                analyzed_at=item.get("analyzed_at", _timestamp_now()),
                risk_score=item["risk_score"],
                classification=item["classification"],
                risk_factors=tuple(item["risk_factors"]),
                threat_fingerprint_id=item["threat_fingerprint_id"],
                extracted_features=dict(item.get("extracted_features", {})),
                score_breakdown=tuple(item.get("score_breakdown", ())),
                content_analysis=dict(item.get("content_analysis", {})),
                redirect_analysis=dict(item.get("redirect_analysis", {})),
                campaign_id=item["campaign_id"],
                campaign_size=item["campaign_size"],
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


def _campaign_id_for(threat_fingerprint_id: str) -> str:
    return "cmp_" + threat_fingerprint_id.removeprefix("fp_")


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _grouping_reason(campaign: dict[str, object]) -> str:
    shared_traits = list(campaign.get("shared_traits", ()))
    if shared_traits:
        return "Grouped by the same URL pattern and repeated traits."
    return "Grouped by an exact matching URL pattern fingerprint."
