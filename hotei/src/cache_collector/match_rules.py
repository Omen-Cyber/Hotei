"""
MatchRules

Holds yara rule configurations for scanning directories and files.
"""

import json
import os
import pathlib
import traceback
from platform import system
from re import search
from sys import exit

import yara


class MatchRules:
    def __init__(self, custom_dirs, yara_rules):
        self.max_file_size = {"uncompressed": 25428800, "compressed": 152428800}
        self.ignore_extensions = ['.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tar.gz', '.tar.bz2', '.tar.xz', '.jar',
                                  '.so', '.egg', '.iso', '.sys', '.dll', '.exe', '.bin', '.jpeg', '.jpg', '.png',
                                  '.svg', '.enc', '.js', '.md', '.tiff', '.wav', '.tif', '.pyc', '.pcap', '.obj',
                                  '.sv2', '.fntdata', '.mp4']
        self.compress_extensions = ['.zip', '.docx', '.xlsx', '.pptx', '.numbers']
        self.osx_directories = ["/Users/", "/Volumes/"]
        self.linux_directories = ["/home/", "/mnt/"]
        self.windows_directories = ["C:\\\\Users"]
        self.custom_dirs = custom_dirs
        self.ignore_dirs = [".local", "Users\\\\Default", "Users\\\\Public", "Application Support",
                            "site-packages"]
        self.match_filenames = {}
        self.final_rules = {}
        self.yara_rules = yara_rules

    """
    Determine if a path is in the ignore list.
    
    Returns True if it should be scanned and is
    *not* in the ignore list.
    """

    def check_path(self, path: str) -> bool:
        for i_dir in self.final_rules['ignore_dirs']:
            if search(i_dir, path) is not None:
                return False
        return True

    """
    Determine if a filename is in the filename match list.
    
    Returns the filename match-key for if it should be scanned.
    Returns empty string if it should not be scanned.
    """

    def check_file_name(self, file_path: str) -> str:
        # Check file name
        for k, v in self.final_rules['match_filenames'].items():
            if search(v, file_path) is not None:
                return k
        return ""

    """
    Determine if a file's extension is in the match list and the file isn't too large.

    Returns True if it should be scanned.
    """

    def check_extension(self, file_path: str, size: int) -> bool:
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext in self.ignore_extensions:
            return False
        if ext in self.compress_extensions:
            return size < self.max_file_size["compressed"]
        return size < self.max_file_size["uncompressed"]

    def create_rules(self):
        os_type = system()
        self.final_rules = {"ignore_dirs": self.ignore_dirs, "max_file_size": self.max_file_size,
                            "ignore_extensions": self.ignore_extensions,
                            "compressed_extensions": self.compress_extensions, "directories": None,
                            "match_filenames": self.match_filenames}
        if self.custom_dirs is not None:
            self.final_rules['directories'] = self.custom_dirs
        elif os_type == "Linux":
            self.final_rules['directories'] = self.linux_directories
        elif os_type == "Windows":
            self.final_rules['directories'] = self.windows_directories
        elif os_type == "Darwin":
            self.final_rules['directories'] = self.osx_directories
        else:
            print("OS type not supported")
            exit(1)

    def gather_yara_rules(self, rules_path: pathlib.Path):
        try:
            rules_dict = {}
            rules_path = rules_path.resolve()
            yara_rules_path = rules_path / "yara_rules"
            print("Finding yara rules at:", yara_rules_path)
            if self.yara_rules['names'] is not None:
                rules = self.yara_rules['names']
                for r in rules:
                    rules_dict[r] = str(yara_rules_path / f"{r}.yara")
                    print("Loaded yara rule by name:", rules_dict[r])

            elif self.yara_rules['secret_types'] is not None:
                for st in self.yara_rules['secret_types']:
                    yrj_path = yara_rules_path / "yara_rules.json"
                    with yrj_path.open() as yr:
                        for line in yr:
                            if "#" not in line:
                                jl = json.loads(line)
                                if jl['collection'] == st:
                                    rules_dict[jl['rule_name']] = str(rules_path / jl['file'])
                                    print("Loaded yara rule:", rules_dict[jl['rule_name']])

            things = yara.compile(filepaths=rules_dict)
            return things

        except Exception as e:
            print("Failed to gather yara rules: ", e)
            traceback.print_exc()
            exit()
