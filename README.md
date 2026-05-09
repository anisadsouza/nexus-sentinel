# Nexus Sentinel

Nexus Sentinel is an explainable phishing detection system under development that analyzes URLs, assigns risk scores, and generates threat fingerprints to identify and group similar attack patterns.

The project focuses on building a practical cybersecurity analysis system rather than a simple phishing classifier. It combines rule-based detection, campaign fingerprinting, and lightweight web-based analysis into a modular Python application.

## Current Features

- URL feature extraction
- Rule-based phishing scoring
- Classification into:
  - `safe`
  - `suspicious`
  - `phishing`
- Threat fingerprint generation
- Basic campaign grouping using shared fingerprints
- Lightweight web dashboard
- API endpoints for URL analysis and campaign listing
- CLI entry point
- Automated tests using `unittest`

## Planned Enhancements

- Hybrid rule + machine learning detection
- SHAP-based explainability for ML predictions
- Persistent scan history and campaign storage
- Domain intelligence (WHOIS, DNS, domain age)
- Redirect tracing
- Educational risk explanations and security tooltips
- Batch URL analysis through CSV upload
- Richer dashboard visualizations
- Public deployment

## Tech Stack

| Category | Technology |
|---|---|
| Language | Python |
| Web Server | `wsgiref.simple_server` |
| Frontend | HTML, CSS, JavaScript |
| URL Parsing | `urllib.parse` |
| Fingerprinting | `hashlib`, `json` |
| IP Detection | `ipaddress` |
| Testing | `unittest` |

## Current Project Structure

```text
nexus_sentinel/
├── detector.py
├── fingerprint.py
├── service.py
├── web.py
├── webapp/
│   ├── index.html
│   ├── app.js
│   └── styles.css
tests/
├── test_detector.py
└── test_service.py
```

## Current System Flow

```text
User Input URL
      ↓
Feature Extraction
      ↓
Rule-Based Risk Analysis
      ↓
Threat Fingerprint Generation
      ↓
Campaign Grouping
      ↓
Risk Classification + Explanation
      ↓
Dashboard/API Output
```

## Project Goals

Nexus Sentinel is being developed with a focus on:

- explainable phishing detection
- practical cybersecurity workflows
- modular system design
- lightweight architecture
- balanced use of rule-based logic and machine learning

The project prioritizes clarity, usability, and realistic implementation over unnecessary complexity.
