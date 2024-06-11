"""
Matching

Processes a list of directories trying to find matches.
"""

import os
import pathlib
import zipfile
from json import dumps

import yara


class Matching:
    def __init__(self, match_rules, yara_match):
        self.match_array = []
        self.rules = match_rules
        self.yara_match = yara_match
        self.files_analyzed = 0
        self.curr_path = None

    def matches_json(self):
        if len(self.match_array) == 0:
            return None
        return dumps(self.match_array, ensure_ascii=True)

    def yara_matches(self):
        # Loop through each directory we want to search
        for match_dirs in self.rules.final_rules['directories']:

            # Walk them
            for root, dirs, files in os.walk(match_dirs):
                print("root: ", root)
                print("\t dirs: ", dirs)
                print("\t files: ", files)

                # Ignore directories we don't care about.
                if not self.rules.check_path(root):
                    continue

                # For each file we find.
                for fn in files:
                    self.curr_path = os.path.join(root, fn)

                    # If a file's name matches one we are looking for.
                    fn_match = self.rules.check_file_name(fn)
                    if len(fn_match) > 0:
                        filename_match = {
                            'file_name': self.curr_path,
                            'rules': {'$filename_match_' + str(fn_match)},
                            'matches': {fn},
                            'total': 0
                        }
                        # Scan it.
                        self.__scan_file(filename_match)
                        continue

                    # If this file's extension is what we are looking for.
                    try:
                        size = os.path.getsize(self.curr_path)
                    except FileNotFoundError:
                        print("Error with file:", self.curr_path)
                        continue
                    if self.rules.check_extension(self.curr_path, size):
                        self.files_analyzed += 1  # TODO: Count zip file and files in zip?
                        # Get the extension
                        _, ext = os.path.splitext(self.curr_path)
                        # If the file is compressed
                        if ext.lower() in self.rules.final_rules['compressed_extensions']:
                            # Process the zip
                            self.__process_zip(self.curr_path)
                        else:
                            print("Evaluating: ", self.curr_path)
                            try:
                                self.yara_match.match(
                                    self.curr_path,
                                    callback=self.__scan_file,
                                    which_callbacks=yara.CALLBACK_MATCHES,
                                    timeout=30)
                                self.files_analyzed += 1
                            except:
                                print("Can't open :", self.curr_path)
        return self.match_array.copy()

    def __scan_file(self, data):
        file_match = {'file_name': self.curr_path, "rules": set([]), "matches": set([]), "total": 0}
        for yara_string in data['strings']:
            file_match['rules'].add(data['rule'])
            for match in yara_string.instances:
                file_match['matches'].add(match.matched_data.decode())
                file_match['total'] += 1

        file_match['matches'] = list(file_match['matches'])
        file_match['rules'] = list(file_match['rules'])
        self.match_array.append(file_match)

        return yara.CALLBACK_CONTINUE

    def __process_file_in_zip(self, zip_file: zipfile.ZipFile, file_path: str):
        try:
            with zip_file.open(file_path) as file_stream:
                # TODO: Clean this up?
                try:
                    match_string = file_stream.read().decode('utf-8', 'replace')
                except:
                    match_string = file_stream.read().decode()

                if self.rules.check_extension(self.curr_path, len(match_string)):  # Check ext and size
                    self.files_analyzed += 1
                    self.yara_match.match(
                        data=match_string,
                        callback=self.__scan_file,
                        which_callbacks=yara.CALLBACK_MATCHES,
                        timeout=30)
        except:
            print("Problem with opening file in zip:", file_path)

    def __process_zip(self, zip_dir: str):
        try:
            with zipfile.ZipFile(zip_dir, 'r') as zip_file:
                for file_info in zip_file.infolist():
                    # Skip directories
                    if file_info.is_dir():
                        continue

                    # Used to generate "/home/thing.zip/dir1/file.txt"
                    path = pathlib.Path(zip_dir) / file_info.filename
                    self.curr_path = str(path)
                    print("Evaluating zip: ", self.curr_path)

                    if self.rules.check_extension(self.curr_path, 0):  # Don't check size yet
                        self.__process_file_in_zip(zip_file, file_info.filename)
        except zipfile.BadZipFile:
            print("Skipping Broken Zip Files: ", str(self.curr_path))
