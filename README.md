# Nexus Sentinel

Nexus Sentinel is a local phishing-analysis dashboard that helps you inspect suspicious links, explain why they look risky, and review batches of URLs from a CSV file.

It is designed to feel like a realistic security tool without turning into an overcomplicated enterprise app. The focus is clarity:

- enter a URL and get a risk score
- understand the reasons behind the score
- upload a CSV when you need to analyze many links at once
- keep scans private by default in the dashboard

## What It Does

### 1. Single URL Analysis

Paste a URL and Nexus Sentinel checks:

- URL structure
- suspicious keywords
- high-risk endings like `.top` or `.xyz`
- encoded characters
- IP-based hostnames
- redirect behavior
- page signals such as login forms, password fields, and urgency language

The result includes:

- risk score out of 100
- classification: `safe`, `suspicious`, or `phishing`
- plain-language explanations of why the link was flagged
- page check details
- destination check details
- an ML model check with explanation signals

### 2. Batch URL Upload

Upload a CSV file with up to 100 URLs and Nexus Sentinel will analyze them together in a table.

This is useful for workflows like:

- checking suspicious email links from a mailbox export
- reviewing a list from security logs
- triaging reported links from a team

### 3. Educational Guidance

The dashboard includes:

- plain-language risk explanations
- security tips for normal users
- example URLs you can test safely in the interface

The goal is not just detection. It is also helping the person using the tool understand what they are looking at.

## Current Stack

- Python
- `wsgiref.simple_server`
- HTML, CSS, JavaScript
- `urllib.parse`
- `ipaddress`
- `unittest`
- optional local ML stack in `requirements-ml.txt`

No framework has been added yet. This is still a lightweight local build.

## ML and Explainability

Nexus Sentinel now includes a real dataset-backed ML layer alongside the rule engine.

- model: `RandomForestClassifier`
- explanation layer: `SHAP`
- dataset: `ESDAUNG PhishDataset balanced set`
- dataset size: `20,000` labeled URL rows
- split: `80/20` train/test
- training rows: `16,000`
- test rows: `4,000`

The trained model and evaluation report are cached locally for reuse during development. The dashboard also surfaces model confidence signals and SHAP-backed explanations when the app is run through the local `.venv`.

## Project Structure

```text
NexusSentinel/
├── nexus_sentinel/
│   ├── __init__.py
│   ├── detector.py
│   ├── live_checks.py
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

## Current Development State

Nexus Sentinel is currently in an active build stage.

Right now the project is focused on:

- improving the phishing detection flow
- making the explanations clearer for normal users
- strengthening the ML and SHAP layers
- shaping the dashboard into something deployment-ready

The intention is to deploy Nexus Sentinel later as a hosted web product, not keep it as a local setup guide.

## Privacy

The dashboard is now intended to behave as a **private local tool**.

- scans from the current interface are treated as private by default
- the UI does not ask the user to make a scan public
- there is no public clear-history control in the dashboard

Important note:

This is still a development-stage product, not yet a deployed multi-user system with authentication or per-user workspaces.

## Current Model workflow 

- single URL analysis
- risk scoring
- phishing classification
- page check signals
- redirect checks
- batch CSV analysis
- plain-language risk explanations
- tooltip-based "Why this matters" explanations
- ML model output from a real dataset-backed Random Forest classifier
- SHAP-based explanations in the UI when the app is run from the local `.venv`
- fallback model behavior when the full local ML stack is unavailable
- cached training artifacts and evaluation report for the current model
- theme toggle
- test coverage for core flows

## Current Model Benchmark

The current dataset-backed Random Forest model is trained from the bundled balanced phishing URL dataset and evaluated on a held-out `80/20` split.

- training samples: `16000`
- test samples: `4000`
- accuracy: `0.8905`
- precision: `0.9194`
- recall: `0.8560`
- F1 score: `0.8866`

This is a useful step forward from synthetic training, but it is still not the final model. The next improvement is broadening the training data so the model sees more modern and varied phishing patterns.

