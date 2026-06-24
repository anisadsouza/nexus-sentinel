# Nexus Sentinel

Nexus Sentinel is a phishing-analysis dashboard for checking suspicious links one at a time or in batches from a CSV file.

The product focuses on three things:

- clear link risk scoring
- explanations that a normal person can actually understand
- a lightweight ML layer with SHAP-backed reasoning

It now also includes **ThreatLens**, an intelligence layer that looks across saved scans and turns them into themes, trends, and grouped threat signals.

It is still being built locally today, but the direction is toward a public web product later.

## Core Experience

### Single Link Analysis

You can paste one URL and Nexus Sentinel will inspect:

- URL structure
- suspicious keywords
- risky website endings such as `.top` and `.xyz`
- IP-based hostnames
- encoded characters
- redirect behavior
- live page signals such as login forms, password fields, hidden fields, urgent wording, and embedded frames

The result includes:

- risk score out of 100
- `safe`, `suspicious`, or `phishing` classification
- plain-language explanations
- page check details
- destination check details
- model-based explanation signals

### Batch CSV Analysis

You can upload a CSV with up to 100 URLs and review them in a table.

The batch workflow now supports:

- summary cards
- insight cards
- filtering by result type
- sorting by score, model risk, or URL
- row-level explanation expansion
- CSV export of analyzed results
- a sample CSV shortcut in the interface

### Educational Guidance

The interface also includes:

- “Why this matters” tooltips
- plain-language risk tips
- safe example links for testing

The goal is not just detection. It is to help someone understand why a link deserves caution.

### ThreatLens

ThreatLens sits on top of saved Nexus Sentinel results and answers a different question:

- Nexus Sentinel: `Is this URL risky?`
- ThreatLens: `What are all these saved results telling us together?`

The current ThreatLens build includes:

- grouped threat clusters
- theme and category rollups
- repeated warning-sign insights
- short intelligence-style summaries
- activity trend comparisons
- downloadable ThreatLens JSON reports

## Detection Layers

Nexus Sentinel currently combines:

1. **Rule-based analysis**
   - direct scoring rules for URL and live page signals

2. **Live page and redirect checks**
   - login/password form detection
   - urgent wording detection
   - external script detection
   - external form action detection
   - hidden field count
   - iframe detection
   - brand wording mismatch clues
   - redirect chain analysis
   - cross-domain hops
   - HTTPS-to-HTTP downgrade detection

3. **Machine learning**
   - a dataset-backed classifier
   - model comparison and selection
   - calibrated probabilities
   - SHAP-based explanation signals when the ML environment is available

## ML and Explainability

Nexus Sentinel includes a real dataset-backed ML layer alongside the rule engine.

- primary model family: tree-based classifiers
- selected model in the current build: `RandomForestClassifier`
- explanation layer: `SHAP`
- calibration: sigmoid calibration when available
- fallback path: lightweight local proxy model if the full ML stack is unavailable

### Training Data

- dataset source: `ESDAUNG PhishDataset balanced set`
- dataset size: `20,000` labeled URL rows
- train/test split: `80/20`
- training rows: `16,000`
- test rows: `4,000`

The current build can also resolve multiple local dataset files through the configured dataset path and tracks dataset versions in the model report.

### Current Benchmark

The current held-out benchmark in this build is based on the real dataset-backed model report:

- accuracy: `0.8905`
- precision: `0.9194`
- recall: `0.8560`
- F1 score: `0.8866`

The app also surfaces additional evaluation details in the dashboard model report, including:

- confusion matrix
- ROC AUC
- average precision
- candidate model comparison
- decision thresholds
- recent benchmark history
- dataset set/version tracking when multiple local datasets are used

## Current Stack

- Python
- `wsgiref.simple_server`
- HTML, CSS, JavaScript
- `urllib.parse`
- `ipaddress`
- `unittest`
- optional local ML stack in `requirements-ml.txt`

This is still a lightweight build. A larger framework has not been introduced yet.

## Project Structure

```text
NexusSentinel/
├── nexus_sentinel/
│   ├── __init__.py
│   ├── detector.py
│   ├── live_checks.py
│   ├── ml.py
│   ├── service.py
│   ├── web.py
│   └── webapp/
│       ├── app.js
│       ├── index.html
│       └── styles.css
├── tests/
│   ├── test_detector.py
│   ├── test_service.py
│   └── test_web.py
└── README.md
```

## What Is Already Working

- single URL analysis
- batch CSV analysis
- rule-based phishing scoring
- live page checks
- redirect tracing checks
- educational tooltips and risk explanations
- model report panel in the UI
- SHAP-backed explanation flow
- rule-versus-model agreement view
- candidate model comparison in the report
- benchmark history in the model report
- downloadable batch result CSV
- downloadable single-result JSON
- downloadable model report JSON
- downloadable ThreatLens report JSON
- theme toggle
- test coverage for core flows
