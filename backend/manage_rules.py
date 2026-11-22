import argparse
import json
import sys

from sqlalchemy.orm import Session

from backend.database.session import get_engine
from backend.services.detection_rules import list_rules, update_rule


def read_value(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def main(argv=None):
    parser = argparse.ArgumentParser(description="List or change INDS detection rules.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="show every rule and its settings")
    change = commands.add_parser("set", help="change settings, for example: set PORT_SCAN distinct_ports=30")
    change.add_argument("rule")
    change.add_argument("values", nargs="+", metavar="key=value")
    args = parser.parse_args(argv)

    with Session(get_engine()) as session:
        if args.command == "set":
            changes = {}
            for item in args.values:
                key, sign, value = item.partition("=")
                if not sign:
                    parser.error(f"{item} is not key=value")
                changes[key] = read_value(value)
            try:
                update_rule(session, args.rule.upper(), changes)
            except ValueError as error:
                print(f"Error: {error}", file=sys.stderr)
                return 1
            print("Saved. The change applies the next time monitoring starts.")

        for rule in list_rules(session):
            state = "on " if rule.enabled else "off"
            print(f"{rule.rule_code:<14} {state} {rule.severity:<8} cooldown {rule.cooldown_seconds}s  {json.dumps(rule.settings_json)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())