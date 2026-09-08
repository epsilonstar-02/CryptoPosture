"""
main.py
Unified CLI for the Email Cryptographic Forensics Framework.

Usage:
  python main.py --analyze <file.pcap>
  python main.py --generate-samples
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

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _analyze(filepath: str, html: bool = False, output: str | None = None, run_ml: bool = True, print_json: bool = True):
    """Run forensic analysis on a PCAP file and print/export results."""
    from core.pipeline import analyze_pcap
    from core.report_exporter import export_json, export_html

    print(f"\n🔐 CryptoPosture — Email Cryptographic Forensics Framework")
    print(f"{'─'*60}")
    print(f"  Evidence: {Path(filepath).name}")

    summary = analyze_pcap(filepath, run_ml=run_ml)
    data    = summary.to_dict()

    ev      = data["evidence"]
    epi     = data["enterprise_posture_index"]
    tier    = data["overall_risk_tier"]
    st_rb   = data.get("session_tier_breakdown", data.get("risk_breakdown", {}))
    vs_rb   = data.get("violation_severity_breakdown", {})
    policy  = data.get("scoring_policy", {})
    engine_ver = data.get("forensic_engine_version", "0.2.0")

    print(f"\n📄 Evidence Integrity")
    print(f"  SHA-256 : {ev['sha256_hash']}")
    print(f"  Packets : {ev['total_packets']:,}  │  Size: {ev.get('file_size_bytes', 0):,} bytes")
    print(f"  Duration: {ev['capture_duration']:.3f}s  │  Format: {ev.get('capture_format', 'PCAP')}")

    print(f"\n📊 Enterprise Posture Index (EPI): {epi:.2f} / 100  [{tier}]")
    print(f"  Scoring Policy: {policy.get('id', 'crypto-posture-v1')} v{policy.get('version', '1.0')}  │  Engine: v{engine_ver}")
    print(f"  Sessions By Tier    : CRITICAL: {st_rb.get('CRITICAL',0)}  HIGH: {st_rb.get('HIGH',0)}  "
          f"MEDIUM: {st_rb.get('MEDIUM',0)}  LOW: {st_rb.get('LOW',0)}")
    print(f"  Violations By Severity: CRITICAL: {vs_rb.get('CRITICAL',0)}  HIGH: {vs_rb.get('HIGH',0)}  "
          f"MEDIUM: {vs_rb.get('MEDIUM',0)}  LOW: {vs_rb.get('LOW',0)}  (Total: {data['total_violations']})")

    # Harmonic exposure contributors
    ent_exp = data.get("enterprise_explanation", {})
    top_risk = ent_exp.get("top_risk_contributors", [])
    if top_risk:
        print(f"\n⚠️  Weakest-Link Risk Exposure (Harmonic Drag):")
        for tr in top_risk[:3]:
            print(f"  • {tr.get('protocol')} {tr.get('flow')}: Score {tr.get('posture_score', 0):.1f} [{tr.get('risk_tier')}] — {tr.get('harmonic_drag_percent', 0):.1f}% drag")

    print(f"\n{'─'*60}")
    print(f"  Sessions Analyzed: {data['session_count']}")
    print(f"{'─'*60}")

    for i, s in enumerate(data["sessions"]):
        score = s.get("posture_score", 0)
        tier_s = s.get("risk_tier", "?")
        conf_s = s.get("confidence", "HIGH")
        print(f"\n  [{i+1}] {s.get('protocol','?')}  "
              f"{s.get('src_ip','')}:{s.get('src_port','')} → {s.get('dst_ip','')}:{s.get('dst_port','')}")
        print(f"       Score: {score:.1f}  │  {tier_s}  │  Confidence: {conf_s}  │  Channel: {s.get('channel_type','?')}")
        print(f"       TLS: {s.get('tls_version') or '—'}  │  Cipher: {(s.get('cipher_suite') or '—')[:40]}")
        print(f"       Cert: {s.get('cert',{}).get('validity','?')}  │  Key Exchange: {s.get('key_exchange') or '—'}")
        if s.get("buffer_injection_detected"):
            print(f"       ⚠️  BUFFER INJECTION DETECTED (Poddebniak et al. USENIX '21)")
        ml_res = s.get("ml_anomaly", {})
        if ml_res.get("is_anomalous"):
            traits = list((ml_res.get("unusual_characteristics") or ml_res.get("top_features") or {}).keys())[:3]
            traits_str = f" [Unusual: {', '.join(traits)}]" if traits else ""
            print(f"       ⚡ CAPTURE OUTLIER (Isolation Forest): Score={ml_res.get('anomaly_score','?')}{traits_str}")
        elif ml_res.get("status") == "INSUFFICIENT_BASELINE":
            print(f"       ℹ️  ML Baseline: INSUFFICIENT_BASELINE (<5 sessions in capture; anomaly baseline requires >= 5 flows)")
        for v in s.get("violations", []):
            ref = f" [{v.get('reference')}]" if v.get("reference") else ""
            print(f"       ✗ [{v['severity']}] {v['code']}: {v['description']}{ref}")

    # Export
    if html:
        html_path = output or (Path(filepath).stem + "_report.html")
        export_html(summary, html_path)
        print(f"\n✅ HTML report saved: {html_path}")
    elif output:
        export_json(summary, output)
        print(f"\n✅ JSON report saved: {output}")
    elif print_json:
        # Print JSON to stdout
        print(f"\n{'─'*60}")
        print(json.dumps(data, indent=2))


def _demo(html: bool = False, output: str | None = None, run_ml: bool = True):
    """Run instant live demo using the 16-flow realistic enterprise network simulation capture."""
    from generator.pcap_generator import generate_enterprise_simulations, DEFAULT_OUTPUT_DIR
    pcap_path = DEFAULT_OUTPUT_DIR / "enterprise_network_simulation.pcap"
    if not pcap_path.exists():
        print("🏢 Synthesizing multi-session enterprise network simulation...")
        generate_enterprise_simulations(DEFAULT_OUTPUT_DIR)
    _analyze(str(pcap_path), html=html, output=output, run_ml=run_ml, print_json=False)


def _generate_samples():
    """Generate all synthetic forensic test PCAPs and enterprise simulations."""
    from generator.pcap_generator import generate_all, generate_enterprise_simulations, DEFAULT_OUTPUT_DIR
    print("\n🧪 Generating synthetic forensic test PCAPs...")
    paths = generate_all(DEFAULT_OUTPUT_DIR)
    print(f"\n✅ Benchmarks: {sum(1 for v in paths.values() if v)}/{len(paths)} PCAPs generated.")
    print("\n🏢 Generating multi-session enterprise & adversarial simulations...")
    ent_paths = generate_enterprise_simulations(DEFAULT_OUTPUT_DIR)
    paths.update(ent_paths)
    print(f"\n✅ Total {sum(1 for v in paths.values() if v)} PCAPs generated in {DEFAULT_OUTPUT_DIR}:")
    for name, path in paths.items():
        status = f"✓ {path}" if path else "✗ FAILED"
        print(f"  {name}: {status}")


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
        description="Email Cryptographic Forensics Framework — Backend CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo
  python main.py --analyze capture.pcap
  python main.py --analyze capture.pcap --html --output report.html
  python main.py --generate-samples
  python main.py --run-api --host 0.0.0.0 --port 8000
  python main.py --test
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run instant demo on realistic 16-flow enterprise perimeter simulation")
    mode.add_argument("--analyze", metavar="FILE.pcap", help="Analyze a PCAP/PCAPNG file")
    mode.add_argument("--generate-samples", action="store_true", help="Generate synthetic demo PCAPs and enterprise simulations")
    mode.add_argument("--run-api", action="store_true", help="Launch FastAPI REST API server")
    mode.add_argument("--test", action="store_true", help="Run the test suite")

    parser.add_argument("--html",   action="store_true", help="Export HTML report instead of JSON")
    parser.add_argument("--output", metavar="FILE",      help="Output file path for report")
    parser.add_argument("--host",   default="0.0.0.0",   help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=8000, help="Port to bind to (default: 8000 for API)")
    parser.add_argument("--no-ml",  action="store_true", help="Disable ML anomaly detection")

    args = parser.parse_args()

    if args.demo:
        _demo(html=args.html, output=args.output, run_ml=not args.no_ml)
    elif args.analyze:
        _analyze(args.analyze, html=args.html, output=args.output, run_ml=not args.no_ml)
    elif args.generate_samples:
        _generate_samples()
    elif args.run_api:
        _run_api(host=args.host, port=args.port)
    elif args.test:
        _run_tests()


if __name__ == "__main__":
    main()

