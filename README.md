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

No framework has been added yet. This is still a lightweight local build.

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

## Run It Locally

From the project root:

```bash
python3 -m nexus_sentinel.web
```

### Port behavior

The app **tries to start on `http://127.0.0.1:9010` first**.

If port `9010` is already occupied by another process, it automatically tries the next free port in the local range and prints the exact URL in the terminal.

So:

- expected default: `http://127.0.0.1:9010`
- fallback example: `http://127.0.0.1:9011`

The terminal output is the source of truth for which port is active.

## Privacy

The dashboard is now intended to behave as a **private local tool**.

- scans from the current interface are treated as private by default
- the UI does not ask the user to make a scan public
- there is no public clear-history control in the dashboard

Important note:

This is still a local development app, not a multi-user system with accounts. If you later want shared users, private workspaces, or user-specific history, that will need proper authentication and storage separation.

## What Is Already Working

- single URL analysis
- risk scoring
- phishing classification
- page check signals
- redirect checks
- batch CSV analysis
- plain-language risk explanations
- theme toggle
- test coverage for core flows
