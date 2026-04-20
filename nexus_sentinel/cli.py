import argparse
import json

from nexus_sentinel.detector import analyze_url


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a URL for phishing risk.")
    parser.add_argument("url", help="URL to analyze")
    args = parser.parse_args()

    result = analyze_url(args.url)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
