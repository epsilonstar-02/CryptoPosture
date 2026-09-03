"""
main.py
Unified CLI for the Email Cryptographic Forensics Framework.

Usage:
  python main.py --analyze <file.pcap>
  python main.py --generate-samples
  python main.py --run-dashboard
  python main.py --run-api
  python main.py --test
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def _analyze(filepath: str, html: bool = False, output: str | None = None):
    """Run forensic analysis on a PCAP file and print/export results."""
    from core.pipeline import analyze_pcap
    from core.report_exporter import export_json, export_html

    print(f"\n🔐 CryptoPosture — Email Cryptographic Forensics Framework")
    print(f"{'─'*60}")
    print(f"  Evidence: {Path(filepath).name}")

    summary = analyze_pcap(filepath, run_ml=True)
    data    = summary.to_dict()

    ev   = data["evidence"]
    epi  = data["enterprise_posture_index"]
    tier = data["overall_risk_tier"]
    rb   = data["risk_breakdown"]

    print(f"\n📄 Evidence Integrity")
    print(f"  SHA-256 : {ev['sha256_hash']}")
    print(f"  Packets : {ev['total_packets']:,}")
    print(f"  Duration: {ev['capture_duration']:.3f}s")

    print(f"\n📊 Enterprise Posture Index: {epi:.1f} / 100  [{tier}]")
    print(f"  CRITICAL: {rb.get('CRITICAL',0)}  HIGH: {rb.get('HIGH',0)}  "
          f"MEDIUM: {rb.get('MEDIUM',0)}  LOW: {rb.get('LOW',0)}")
    print(f"  Total violations: {data['total_violations']}")

    print(f"\n{'─'*60}")
    print(f"  Sessions Analyzed: {data['session_count']}")
    print(f"{'─'*60}")

    for i, s in enumerate(data["sessions"]):
        score = s.get("posture_score", 0)
        tier_s = s.get("risk_tier", "?")
        print(f"\n  [{i+1}] {s.get('protocol','?')}  "
              f"{s.get('src_ip','')}:{s.get('src_port','')} → {s.get('dst_ip','')}:{s.get('dst_port','')}")
        print(f"       Score: {score:.1f}  │  {tier_s}  │  Channel: {s.get('channel_type','?')}")
        print(f"       TLS: {s.get('tls_version') or '—'}  │  Cipher: {(s.get('cipher_suite') or '—')[:40]}")
        print(f"       Cert: {s.get('cert',{}).get('validity','?')}  │  Key Exchange: {s.get('key_exchange') or '—'}")
        if s.get("buffer_injection_detected"):
            print(f"       ⚠️  BUFFER INJECTION DETECTED")
        if s.get("ml_anomaly", {}).get("is_anomalous"):
            print(f"       ⚡ ML ANOMALY SCORE: {s['ml_anomaly'].get('anomaly_score','?')}")
        for v in s.get("violations", []):
            print(f"       ✗ [{v['severity']}] {v['code']}: {v['description']}")

    # Export
    if html:
        html_path = output or (Path(filepath).stem + "_report.html")
        export_html(summary, html_path)
        print(f"\n✅ HTML report saved: {html_path}")
    elif output:
        export_json(summary, output)
        print(f"\n✅ JSON report saved: {output}")
    else:
        # Print JSON to stdout
        print(f"\n{'─'*60}")
        print(json.dumps(data, indent=2))


def _generate_samples():
    """Generate all 5 synthetic forensic test PCAPs."""
    from generator.pcap_generator import generate_all, DEFAULT_OUTPUT_DIR
    print("\n🧪 Generating synthetic forensic test PCAPs...")
    paths = generate_all(DEFAULT_OUTPUT_DIR)
    print(f"\n✅ Done! {sum(1 for v in paths.values() if v)}/{len(paths)} PCAPs generated:")
    for name, path in paths.items():
        status = f"✓ {path}" if path else "✗ FAILED"
        print(f"  {name}: {status}")


def _run_dashboard(host: str = "0.0.0.0", port: int = 8501):
    """Launch the Streamlit dashboard."""
    print(f"🚀 Launching Streamlit dashboard on http://{host}:{port}...")
    dashboard_path = Path(__file__).parent / "dashboard" / "app.py"
    cmd = [
        sys.executable, "-m", "streamlit", "run", str(dashboard_path),
        "--server.address", host,
        "--server.port", str(port),
        "--server.headless", "true"
    ]
    subprocess.run(cmd, check=True)


def _run_api(host: str = "0.0.0.0", port: int = 8000):
    """Launch the FastAPI server."""
    print(f"🚀 Launching FastAPI server on http://{host}:{port}")
    print(f"   Docs: http://{host}:{port}/docs")
    subprocess.run([sys.executable, "-m", "uvicorn", "api.app:app", "--host", host, "--port", str(port), "--reload"], check=True)


def _run_tests():
    """Run the test suite."""
    print("🧪 Running test suite...")
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"], capture_output=False)
    sys.exit(result.returncode)


def main():
    parser = argparse.ArgumentParser(
        prog="cryptoposture",
        description="Email Cryptographic Forensics Framework — CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --analyze capture.pcap
  python main.py --analyze capture.pcap --html --output report.html
  python main.py --generate-samples
  python main.py --run-dashboard --host 0.0.0.0 --port 8501
  python main.py --run-api --host 0.0.0.0 --port 8000
  python main.py --test
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", metavar="FILE.pcap", help="Analyze a PCAP/PCAPNG file")
    mode.add_argument("--generate-samples", action="store_true", help="Generate synthetic demo PCAPs")
    mode.add_argument("--run-dashboard", action="store_true", help="Launch Streamlit dashboard")
    mode.add_argument("--run-api", action="store_true", help="Launch FastAPI REST API server")
    mode.add_argument("--test", action="store_true", help="Run the test suite")

    parser.add_argument("--html",   action="store_true", help="Export HTML report instead of JSON")
    parser.add_argument("--output", metavar="FILE",      help="Output file path for report")
    parser.add_argument("--host",   default="0.0.0.0",   help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=None, help="Port to bind to (default: 8501 for dashboard, 8000 for API)")
    parser.add_argument("--no-ml",  action="store_true", help="Disable ML anomaly detection")

    args = parser.parse_args()

    if args.analyze:
        _analyze(args.analyze, html=args.html, output=args.output)
    elif args.generate_samples:
        _generate_samples()
    elif args.run_dashboard:
        port = args.port if args.port is not None else 8501
        _run_dashboard(host=args.host, port=port)
    elif args.run_api:
        port = args.port if args.port is not None else 8000
        _run_api(host=args.host, port=port)
    elif args.test:
        _run_tests()


if __name__ == "__main__":
    main()

