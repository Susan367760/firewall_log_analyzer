from flask import Flask, render_template, send_file

from analyzer.parser import parse_log_file

from analyzer.analyzer import (
    total_events,
    count_actions,
    unique_source_ips,
    unique_destination_ips,
    top_source_ips,
    top_destination_ports,
    protocol_statistics,
)

from analyzer.rules import run_all_rules

from reports.report_generator import (
    generate_csv_report,
    generate_pdf_report,
)


# ============================================================
# Flask Application
# ============================================================

app = Flask(__name__)


# ============================================================
# Configuration
# ============================================================

LOG_FILE = "data/firewall.log"


# ============================================================
# Dashboard
# ============================================================

@app.route("/")
def dashboard():

    events = parse_log_file(LOG_FILE)

    actions = count_actions(events)

    statistics = {
        "total_events": total_events(events),

        "accepted": actions.get("ACCEPT", 0),

        "dropped": actions.get("DROP", 0),

        "unique_source_ips": unique_source_ips(events),

        "unique_destination_ips": unique_destination_ips(events),

        "top_source_ips": top_source_ips(events),

        "top_destination_ports": top_destination_ports(events),

        "protocols": protocol_statistics(events),
    }

    alerts = run_all_rules(events)

    chart_data = {

        "actions": {
            "accepted": statistics["accepted"],
            "dropped": statistics["dropped"],
        },

        "source_ips": {
            "labels": [
                ip
                for ip, count
                in statistics["top_source_ips"]
            ],

            "values": [
                count
                for ip, count
                in statistics["top_source_ips"]
            ],
        },

        "destination_ports": {
            "labels": [
                str(port)
                for port, count
                in statistics["top_destination_ports"]
            ],

            "values": [
                count
                for port, count
                in statistics["top_destination_ports"]
            ],
        },

        "protocols": {
            "labels": list(
                statistics["protocols"].keys()
            ),

            "values": list(
                statistics["protocols"].values()
            ),
        },
    }

    return render_template(
        "index.html",

        statistics=statistics,

        alerts=alerts,

        events=events,

        chart_data=chart_data,
    )


# ============================================================
# CSV Report
# ============================================================

@app.route("/download/csv")
def download_csv():

    events = parse_log_file(LOG_FILE)

    alerts = run_all_rules(events)

    report_path = generate_csv_report(
        events,
        alerts
    )

    return send_file(
        report_path,

        as_attachment=True,

        download_name="firewall_security_report.csv",

        mimetype="text/csv"
    )


# ============================================================
# PDF Report
# ============================================================

@app.route("/download/pdf")
def download_pdf():

    events = parse_log_file(LOG_FILE)

    alerts = run_all_rules(events)

    report_path = generate_pdf_report(
        events,
        alerts
    )

    return send_file(
        report_path,

        as_attachment=True,

        download_name="firewall_security_report.pdf",

        mimetype="application/pdf"
    )


# ============================================================
# Run Application
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True,

        host="127.0.0.1",

        port=5000
    )