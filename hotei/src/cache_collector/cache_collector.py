"""
cache_collector

Gather secrets!

Supports:
* Windows ?
* Mac ?
* Linux ?
"""

import argparse
import os
import json
from collections import deque

from match_rules import MatchRules
from matching import Matching


# Gather the user directory when relative path is given
def find_dir():
    start_dir = "/home"
    target_dir = "Downloads"
    queue = deque([start_dir])
    while queue:
        current_dir = queue.popleft()
        for dirpath, dirnames, filenames in os.walk(start_dir, topdown=True):
            if target_dir in dirnames:
                return os.path.join(dirpath + "/")
            for dirname in dirnames:
                if dirname not in "Shared":
                    queue.append(os.path.join(dirpath, dirname))
    return None


def main():
    parser = argparse.ArgumentParser(description="Scan for sensitive information.")
    parser.add_argument('-d', '--directory', type=str, required=False, help='Directory in users path to search',
                        default=None)
    parser.add_argument('-p', '--full_path', type=str, required=False, help='Full path to search', default=None)
    parser.add_argument('-r', '--rules_path', type=str, required=True, help='List of rules, overrides -t')
    parser.add_argument('-t', '--match_types', type=str, required=False, help='List of secret types to match')
    parser.add_argument('-o', '--output', type=str, required=False, help='Output file')
    parser.add_argument('-pr', '--print_rules', action='store_true',required=False, help='Output rules and types')
    args = parser.parse_args()

    if args.print_rules:
        with open(args.rules_path + '/yara_rules.json', 'r') as rl:
            for rule in rl:
                cr = json.loads(rule)
                print("Rule: {} : {}".format(cr['collection'], cr['rule_name']))
        exit(0)

    if args.directory is not None:
        scan_dir = [find_dir() + args.directory]
    elif args.full_path is not None:
        scan_dir = [args.full_path]
    elif args.directory is not None and args.full_path is not None:
        print("Only one of -d or -p must be provided.")
        exit(1)
    else:
        scan_dir = None

    rules = MatchRules(scan_dir, args.match_types.split(','))

    rules.create_rules()
    match_secrets = rules.gather_yara_rules(args.rules_path)

    match_array = Matching(rules, match_secrets)
    final_matches_list, analyzed_count = match_array.yara_matches()
    print("Number of matches: ", len(final_matches_list))
    print("Number of files examined: ", analyzed_count)
    if args.output is not None:
        if match_array.matches_json() is not None:
            with open(args.output, 'w') as out_file:
                out_file.write(match_array.matches_json())
        else:
            print("No matches found.")
            exit(1)
    return final_matches_list


if __name__ == "__main__":
    stuff = main()
    for thing in stuff:
        print(thing)
