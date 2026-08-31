from analyzer.parser import parse_log_file


LOG_FILE = "data/firewall.log"


def main():

    events = parse_log_file(LOG_FILE)

    print(f"\nTotal events parsed: {len(events)}")

    print("\nFirst event:")
    print(events[0])

    print("\nLast event:")
    print(events[-1])


if __name__ == "__main__":
    main()