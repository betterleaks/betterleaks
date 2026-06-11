#!/usr/bin/env python3
"""Count rules and rules with validation in a Betterleaks TOML config."""

import sys


def count_rules(path):
    total = 0
    with_validation = 0
    current_has_validation = False
    in_rule = False

    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            if line == "[[rules]]":
                if in_rule and current_has_validation:
                    with_validation += 1
                total += 1
                in_rule = True
                current_has_validation = False
                continue

            if in_rule and line.startswith("validate"):
                current_has_validation = True

    if in_rule and current_has_validation:
        with_validation += 1

    return total, with_validation


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "config/betterleaks.toml"
    total, with_validation = count_rules(path)
    print(f"rules: {total}")
    print(f"rules_with_validation: {with_validation}")


if __name__ == "__main__":
    main()
