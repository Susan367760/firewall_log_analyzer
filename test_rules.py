from analyzer.parser import parse_log_file
from analyzer.rules import run_all_rules


LOG_FILE = "data/firewall.log"


def main():

    events = parse_log_file(LOG_FILE)

    alerts = run_all_rules(events)

    print("\n========================================")
    print(" FIREWALL SECURITY ALERTS")
    print("========================================")

    print(f"\nTotal alerts: {len(alerts)}")

    for number, alert in enumerate(alerts, start=1):

        print(f"\nAlert #{number}")
        print("-" * 40)

        print(f"Type: {alert['type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['src_ip']}")
        print(f"Description: {alert['description']}")

        if "ports" in alert:
            print(f"Ports: {alert['ports']}")

        if "service" in alert:
            print(f"Service: {alert['service']}")

    print("\n========================================")


if __name__ == "__main__":
    main()