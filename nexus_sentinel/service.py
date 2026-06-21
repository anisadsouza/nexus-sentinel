from __future__ import annotations

import hashlib
import json
from collections import Counter
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
    ml_analysis: dict[str, object]
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
        record = self._build_record(url, save=save, comparison_records=self._records)
        if save:
            self._records.append(record)
            self._save_records()
        return record

    def analyze_batch(self, urls: list[str], save: bool = True) -> list[AnalysisRecord]:
        working_records = list(self._records)
        results: list[AnalysisRecord] = []

        for url in urls:
            record = self._build_record(
                url,
                save=save,
                comparison_records=working_records,
            )
            results.append(record)
            working_records.append(record)

        if save and results:
            self._records.extend(results)
            self._save_records()

        return results

    def list_similar_groups(
        self, records: list[AnalysisRecord] | None = None
    ) -> list[dict[str, object]]:
        working_records = self._records if records is None else records
        groups = [
            _build_similar_group_summary(records)
            for _group_id, records in _group_records_by_id(working_records).items()
        ]
        return sorted(
            groups,
            key=lambda group: (-int(group["size"]), str(group["similar_group_id"])),
        )

    def overview(self, records: list[AnalysisRecord] | None = None) -> dict[str, int]:
        working_records = self._records if records is None else records
        risk_scores = [record.risk_score for record in working_records]
        return {
            "total_scans": len(working_records),
            "active_similar_groups": len(
                {record.similar_group_id for record in working_records}
            ),
            "highest_risk": max(risk_scores, default=0),
        }

    def threatlens_summary(self, days: int | None = None) -> dict[str, object]:
        filtered_records = _filter_records_by_days(self._records, days)
        similar_groups = self.list_similar_groups(filtered_records)
        classification_breakdown = Counter(
            record.classification for record in filtered_records
        )
        theme_breakdown = Counter(_infer_theme(record) for record in filtered_records)
        category_breakdown = Counter(
            _infer_category(record) for record in filtered_records
        )
        brand_breakdown = Counter()
        top_signal_counts = Counter()
        risk_insight_counts = Counter()

        for record in filtered_records:
            top_reason = next(iter(record.risk_factors), None)
            if top_reason:
                top_signal_counts[top_reason] += 1
            for label in _extract_risk_insights(record):
                risk_insight_counts[label] += 1
            for label in _extract_brand_targets(record):
                brand_breakdown[label] += 1

        top_theme = (
            theme_breakdown.most_common(1)[0][0] if theme_breakdown else "None yet"
        )
        top_category = (
            category_breakdown.most_common(1)[0][0]
            if category_breakdown
            else "No category yet"
        )
        top_signal = (
            _humanize_signal_label(top_signal_counts.most_common(1)[0][0])
            if top_signal_counts
            else "No repeated warning signs yet"
        )
        trend = _build_daily_trend(filtered_records)
        trend_change = _build_trend_change(filtered_records)

        return {
            "overview": self.overview(filtered_records),
            "range_days": days,
            "range_label": _range_label(days),
            "classification_breakdown": {
                "safe": classification_breakdown.get("safe", 0),
                "suspicious": classification_breakdown.get("suspicious", 0),
                "phishing": classification_breakdown.get("phishing", 0),
            },
            "top_similar_groups": similar_groups[:5],
            "top_risk_signals": [
                {"label": _humanize_signal_label(label), "count": count}
                for label, count in top_signal_counts.most_common(5)
            ],
            "top_themes": [
                {"label": label, "count": count}
                for label, count in theme_breakdown.most_common(5)
            ],
            "top_categories": [
                {"label": label, "count": count}
                for label, count in category_breakdown.most_common(5)
            ],
            "classification_shares": _build_share_rows(
                classification_breakdown,
                len(filtered_records),
                order=("phishing", "suspicious", "safe"),
                labels={
                    "phishing": "Likely phishing",
                    "suspicious": "Use caution",
                    "safe": "Looks safe",
                },
            ),
            "theme_groups": _build_theme_groups(filtered_records),
            "top_brand_targets": [
                {"label": label, "count": count}
                for label, count in brand_breakdown.most_common(5)
            ],
            "top_risk_insights": [
                {"label": label, "count": count}
                for label, count in risk_insight_counts.most_common(6)
            ],
            "campaign_spotlights": _build_campaign_spotlights(similar_groups[:3]),
            "daily_trend": trend,
            "trend_change": trend_change,
            "weekly_briefing": _build_weekly_briefing(
                total_scans=len(filtered_records),
                phishing_count=classification_breakdown.get("phishing", 0),
                top_category=top_category,
                top_theme=top_theme,
                trend_change=trend_change,
                top_groups=similar_groups[:3],
            ),
            "generated_summary": _build_generated_summary(
                total_scans=len(filtered_records),
                phishing_count=classification_breakdown.get("phishing", 0),
                top_theme=top_theme,
                top_signal=top_signal,
                top_groups=similar_groups[:3],
            ),
        }

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
                ml_analysis=dict(item.get("ml_analysis", {})),
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

    def _build_record(
        self,
        url: str,
        save: bool,
        comparison_records: list[AnalysisRecord],
    ) -> AnalysisRecord:
        detection = analyze_url_with_live_checks(url, live_fetcher=self._live_fetcher)
        similar_group_id = _similar_group_id_for(detection.extracted_features)
        similar_group_size = (
            sum(
                1
                for record in comparison_records
                if record.similar_group_id == similar_group_id
            )
            + 1
        )

        return AnalysisRecord(
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
            ml_analysis=detection.ml_analysis,
            similar_group_id=similar_group_id,
            similar_group_size=similar_group_size,
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


def _group_records_by_id(
    records: list[AnalysisRecord],
) -> dict[str, list[AnalysisRecord]]:
    grouped: dict[str, list[AnalysisRecord]] = {}
    for record in records:
        grouped.setdefault(record.similar_group_id, []).append(record)
    return grouped


def _build_similar_group_summary(
    records: list[AnalysisRecord],
) -> dict[str, object]:
    first_record = records[0]
    factor_counts: dict[str, int] = {}

    for record in records:
        for factor in record.risk_factors:
            factor_counts[factor] = factor_counts.get(factor, 0) + 1

    summary = {
        "similar_group_id": first_record.similar_group_id,
        "classification": first_record.classification,
        "theme": _majority_label(records, _infer_theme),
        "category": _majority_label(records, _infer_category),
        "size": len(records),
        "example_urls": [record.url for record in records[:3]],
        "common_risk_factors": [
            factor
            for factor, _count in sorted(
                factor_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[:2]
        ],
        "shared_traits": _shared_traits(records),
        "grouping_reason": "",
        "first_seen": min(record.analyzed_at for record in records),
        "latest_seen": max(record.analyzed_at for record in records),
    }
    summary["grouping_reason"] = _grouping_reason(summary)
    return summary


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


def _infer_theme(record: AnalysisRecord) -> str:
    content = record.content_analysis
    features = record.extracted_features
    keywords = {
        str(keyword).lower() for keyword in features.get("suspicious_keywords", ())
    }
    page_title = str(content.get("page_title", "")).lower()
    notes = str(content.get("notes", "")).lower()
    brand_words = {
        str(keyword).lower()
        for keyword in content.get("brand_keywords_detected", ())
    }
    combined_words = keywords | brand_words

    if {"bank", "banking", "card", "payment", "paypal"} & combined_words:
        return "Banking and payment"
    if {"verify", "verification", "account", "secure"} & combined_words:
        return "Account verification"
    if content.get("password_field_detected") or content.get("login_form_detected"):
        return "Credential theft"
    if {"instagram", "facebook", "social", "twitter", "x"} & combined_words:
        return "Social media impersonation"
    if "invoice" in page_title or "payment" in notes:
        return "Billing lure"
    return "General phishing"


def _infer_category(record: AnalysisRecord) -> str:
    theme = _infer_theme(record)
    if theme == "Banking and payment":
        return "Financial targeting"
    if theme == "Account verification":
        return "Account takeover"
    if theme == "Credential theft":
        return "Credential theft"
    if theme == "Social media impersonation":
        return "Brand impersonation"
    if theme == "Billing lure":
        return "Payment pressure"
    return "General phishing"


def _extract_risk_insights(record: AnalysisRecord) -> list[str]:
    insights: list[str] = []
    features = record.extracted_features
    content = record.content_analysis
    redirect = record.redirect_analysis

    if features.get("uses_https") is False:
        insights.append("No HTTPS")
    if features.get("has_suspicious_tld") is True:
        insights.append("Unusual website ending")
    if features.get("is_ip_hostname") is True:
        insights.append("IP-based host")
    if content.get("login_form_detected") or content.get("password_field_detected"):
        insights.append("Credential collection page")
    if content.get("urgency_language_detected"):
        insights.append("Urgency wording")
    if content.get("brand_impersonation_clues_detected"):
        insights.append("Brand mismatch clues")
    if content.get("form_action_external_detected"):
        insights.append("External form destination")
    if redirect.get("cross_domain_redirect_detected"):
        insights.append("Cross-site redirect")
    if redirect.get("downgrade_to_http_detected"):
        insights.append("HTTPS downgrade")

    return insights


def _extract_brand_targets(record: AnalysisRecord) -> list[str]:
    content = record.content_analysis
    brands = [
        str(keyword).strip().title()
        for keyword in content.get("brand_keywords_detected", ())
        if str(keyword).strip()
    ]
    return brands[:3]


def _build_daily_trend(records: list[AnalysisRecord]) -> list[dict[str, object]]:
    daily: dict[str, dict[str, int]] = {}

    for record in records:
        date_key = record.analyzed_at[:10]
        bucket = daily.setdefault(
            date_key,
            {"safe": 0, "suspicious": 0, "phishing": 0},
        )
        bucket[record.classification] = bucket.get(record.classification, 0) + 1

    trend = [
        {
            "date": date_key,
            "safe": counts.get("safe", 0),
            "suspicious": counts.get("suspicious", 0),
            "phishing": counts.get("phishing", 0),
            "total": sum(counts.values()),
        }
        for date_key, counts in sorted(daily.items())
    ]
    return trend[-7:]


def _build_theme_groups(records: list[AnalysisRecord]) -> list[dict[str, object]]:
    theme_counts: dict[str, dict[str, int]] = {}

    for record in records:
        theme = _infer_theme(record)
        bucket = theme_counts.setdefault(
            theme,
            {"count": 0, "phishing": 0, "suspicious": 0, "safe": 0},
        )
        bucket["count"] += 1
        bucket[record.classification] += 1

    items = [
        {
            "label": theme,
            "count": counts["count"],
            "phishing": counts["phishing"],
            "suspicious": counts["suspicious"],
            "safe": counts["safe"],
        }
        for theme, counts in theme_counts.items()
    ]
    return sorted(items, key=lambda item: (-int(item["count"]), str(item["label"])))[:5]


def _build_campaign_spotlights(
    similar_groups: list[dict[str, object]],
) -> list[dict[str, object]]:
    spotlights: list[dict[str, object]] = []

    for group in similar_groups[:3]:
        category = str(group.get("category", "General phishing"))
        theme = str(group.get("theme", "General phishing"))
        factor = list(group.get("common_risk_factors", ()))
        spotlights.append(
            {
                "headline": f"{category} · {theme}",
                "size": int(group.get("size", 0)),
                "classification": str(group.get("classification", "suspicious")),
                "grouping_reason": str(group.get("grouping_reason", "")),
                "top_signal": _humanize_signal_label(factor[0]) if factor else "Repeated suspicious pattern",
                "example_url": next(iter(group.get("example_urls", ())), ""),
            }
        )

    return spotlights


def _build_generated_summary(
    total_scans: int,
    phishing_count: int,
    top_theme: str,
    top_signal: str,
    top_groups: list[dict[str, object]],
) -> str:
    if total_scans == 0:
        return (
            "ThreatLens is ready. Save a few analyzed links and it will start surfacing "
            "shared patterns, repeated scams, and activity trends."
        )

    phishing_pct = round((phishing_count / total_scans) * 100) if total_scans else 0
    largest_group = top_groups[0]["size"] if top_groups else 0

    return (
        f"{phishing_pct}% of saved scans were classified as phishing. "
        f"The most common theme so far is {top_theme.lower()}, and the most repeated warning sign "
        f"is {top_signal.lower()}. "
        f"The largest related threat group currently contains {largest_group} link"
        f"{'' if largest_group == 1 else 's'}."
    )


def _build_weekly_briefing(
    total_scans: int,
    phishing_count: int,
    top_category: str,
    top_theme: str,
    trend_change: dict[str, object],
    top_groups: list[dict[str, object]],
) -> str:
    if total_scans == 0:
        return (
            "No saved activity yet. Once results are stored, ThreatLens will turn them into a short "
            "intelligence briefing with themes, shifts, and the biggest repeated groups."
        )

    largest_group = top_groups[0]["size"] if top_groups else 0
    direction_label = str(trend_change.get("label", "Holding steady across saved scans")).lower()

    return (
        f"Saved activity is centered on {top_category.lower()}, with {top_theme.lower()} as the leading theme. "
        f"{phishing_count} of {total_scans} saved scans are currently phishing, {direction_label}, "
        f"and the largest repeated group contains {largest_group} related link"
        f"{'' if largest_group == 1 else 's'}."
    )


def _humanize_signal_label(label: str) -> str:
    return label.replace("_", " ").strip().capitalize()


def _majority_label(
    records: list[AnalysisRecord],
    resolver: Callable[[AnalysisRecord], str],
) -> str:
    counts = Counter(resolver(record) for record in records)
    return counts.most_common(1)[0][0] if counts else "Unknown"


def _range_label(days: int | None) -> str:
    if days is None:
        return "All saved activity"
    if days == 7:
        return "Last 7 days"
    if days == 30:
        return "Last 30 days"
    return f"Last {days} days"


def _build_share_rows(
    counts: Counter[str],
    total: int,
    order: tuple[str, ...],
    labels: dict[str, str],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key in order:
        count = counts.get(key, 0)
        pct = round((count / total) * 100) if total else 0
        rows.append(
            {
                "key": key,
                "label": labels.get(key, key),
                "count": count,
                "pct": pct,
            }
        )
    return rows


def _filter_records_by_days(
    records: list[AnalysisRecord],
    days: int | None,
) -> list[AnalysisRecord]:
    if days is None:
        return list(records)

    cutoff_seconds = max(0, days) * 24 * 60 * 60
    now = datetime.now(timezone.utc)
    filtered: list[AnalysisRecord] = []

    for record in records:
        try:
            analyzed_at = datetime.fromisoformat(record.analyzed_at)
        except ValueError:
            continue
        if analyzed_at.tzinfo is None:
            analyzed_at = analyzed_at.replace(tzinfo=timezone.utc)
        age_seconds = (now - analyzed_at).total_seconds()
        if age_seconds <= cutoff_seconds:
            filtered.append(record)

    return filtered


def _build_trend_change(records: list[AnalysisRecord]) -> dict[str, object]:
    if not records:
        return {
            "recent_total": 0,
            "previous_total": 0,
            "change_pct": 0,
            "direction": "steady",
            "label": "No saved trend yet",
        }

    ordered = sorted(records, key=lambda record: record.analyzed_at)
    midpoint = max(1, len(ordered) // 2)
    previous = ordered[:midpoint]
    recent = ordered[midpoint:]
    previous_total = len(previous)
    recent_total = len(recent)

    if previous_total == 0:
        change_pct = 100 if recent_total else 0
    else:
        change_pct = round(((recent_total - previous_total) / previous_total) * 100)

    if change_pct > 0:
        direction = "up"
        label = f"Up {change_pct}% from the earlier window"
    elif change_pct < 0:
        direction = "down"
        label = f"Down {abs(change_pct)}% from the earlier window"
    else:
        direction = "steady"
        label = "Holding steady across saved scans"

    return {
        "recent_total": recent_total,
        "previous_total": previous_total,
        "change_pct": change_pct,
        "direction": direction,
        "label": label,
    }
