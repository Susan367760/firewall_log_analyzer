from analyzer.parser import parse_log_file
from analyzer.rules import run_all_rules

from reports.report_generator import (
    generate_csv_report,
    generate_pdf_report
)


# ============================================================
# Load Firewall Events
# ============================================================

events = parse_log_file(
    "data/firewall.log"
)


# ============================================================
# Run Security Rules
# ============================================================

alerts = run_all_rules(events)


# ============================================================
# Generate Reports
# ============================================================

csv_report = generate_csv_report(
    events,
    alerts
)

pdf_report = generate_pdf_report(
    events,
    alerts
)


# ============================================================
# Display Results
# ============================================================

print()
print("=" * 50)
print(" FIREWALL SECURITY REPORTS")
print("=" * 50)

print()

print(
    f"Events analyzed: {len(events)}"
)

print(
    f"Security alerts: {len(alerts)}"
)

print()

print(
    f"CSV report: {csv_report}"
)

print(
    f"PDF report: {pdf_report}"
)

print()

print("=" * 50)