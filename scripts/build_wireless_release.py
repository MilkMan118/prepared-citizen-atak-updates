"""Build exact sanitized wireless release assets; this never publishes them."""
import argparse
import json
from pathlib import Path

from prepared_citizen_atak.wireless_release import build_release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--references", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build_release(Path(__file__).resolve().parents[1], args.output,
        args.version, args.sequence, args.signing_key, args.openssl, args.references), indent=2))


if __name__ == "__main__":
    main()
