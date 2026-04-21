from dataclasses import asdict, dataclass

from nexus_sentinel.detector import analyze_url


@dataclass(frozen=True)
class AnalysisRecord:
    url: str
    risk_score: int
    classification: str
    risk_factors: tuple[str, ...]
    threat_fingerprint_id: str
    campaign_id: str
    campaign_size: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AnalysisService:
    def __init__(self) -> None:
        self._records: list[AnalysisRecord] = []

    def analyze(self, url: str) -> AnalysisRecord:
        detection = analyze_url(url)
        campaign_id = _campaign_id_for(detection.threat_fingerprint_id)
        campaign_size = (
            sum(1 for record in self._records if record.campaign_id == campaign_id) + 1
        )

        record = AnalysisRecord(
            url=url,
            risk_score=detection.risk_score,
            classification=detection.classification,
            risk_factors=detection.risk_factors,
            threat_fingerprint_id=detection.threat_fingerprint_id,
            campaign_id=campaign_id,
            campaign_size=campaign_size,
        )
        self._records.append(record)
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
                },
            )
            campaign["size"] = int(campaign["size"]) + 1
            example_urls = campaign["example_urls"]
            if len(example_urls) < 3:
                example_urls.append(record.url)

        return sorted(
            grouped.values(),
            key=lambda campaign: (-int(campaign["size"]), str(campaign["campaign_id"])),
        )

    def recent_scans(self, limit: int = 10) -> list[dict[str, object]]:
        return [record.to_dict() for record in reversed(self._records[-limit:])]


def _campaign_id_for(threat_fingerprint_id: str) -> str:
    return "cmp_" + threat_fingerprint_id.removeprefix("fp_")
