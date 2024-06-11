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
import pathlib
from collections import deque

from match_rules import MatchRules
from matching import Matching


def find_dir(start_dir, target_dir):
    queue = deque([start_dir])
    while queue:
        current_dir = queue.popleft()
        for dirpath, dirnames, filenames in os.walk(start_dir, topdown=True):
            if target_dir in dirnames:
                return os.path.join(dirpath)
            for dirname in dirnames:
                if dirname not in ("Shared"):
                    queue.append(os.path.join(dirpath, dirname))
    return None


def main():
    parser = argparse.ArgumentParser(description="Scan for secrets.")
    parser.add_argument('-d', '--directory', type=str, required=False, help='Directory in users path to search',
                        default=None)
    parser.add_argument('-p', '--full_path', type=str, required=False, help='Full path to search', default=None)
    parser.add_argument('-r', '--rules', type=str, nargs='+', required=False, help='List of rules')
    parser.add_argument('-t', '--rule_types', type=str, nargs='+', required=False, help='List of rule types')
    parser.add_argument('-o', '--output', type=str, required=False, help='Output file')
    args = parser.parse_args()

    if args.directory is not None:
        scan_dir = [find_dir(args.directory)]
    elif args.full_path is not None:
        scan_dir = [args.full_path]
    else:
        scan_dir = None
    # yara_rules_dict = {"names": ['AWS_KEYS'], "secret_types": None}
    yara_rules_dict = {"names": None, "secret_types": ['CLOUD_SECRETS', 'GENERIC_SECRETS', 'SCM', 'SAAS_SECRETS']}

    rules = MatchRules(scan_dir, yara_rules_dict)

    rules.create_rules()
    cwd = pathlib.Path.cwd()  # TODO: Fix hardcoding
    print(cwd)
    cwd = cwd / ".."
    cwd = cwd / ".."
    cwd = cwd / ".."
    cwd = cwd / "hotei"
    cwd = cwd / "rules"
    print(cwd)
    match_secrets = rules.gather_yara_rules(cwd.resolve())

    match_array = Matching(rules, match_secrets)
    thing = match_array.yara_matches()
    print("Number of matches: ", len(match_array.match_array))
    print("Number of files examined: ", match_array.files_analyzed)
    return thing


if __name__ == "__main__":
    stuff = main()
    for thing in stuff:
        print(thing)
