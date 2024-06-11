import os
import re

import ssdeep


class sensitive_data_analyzer:
    def __init__(self, match_dirs):
        self.files = []
        self.dta = []
        self.match_dirs = match_dirs
        self.analyzed = 0

    def gather_strings(self):

        for root, dirs, files in os.walk(self.match_dirs):
            for dr in files:
                curr_dir = os.path.join(root, dr)
                try:
                    # Dont read binary files
                    with open(curr_dir, 'r') as doc:
                        temp_lines = doc.readlines()

                    for l in temp_lines:
                        temp_line = {'lines': set(), 'name': None}
                        temp_line['lines'].add(l)
                        temp_line['name'] = dr
                        self.files.append(temp_line)
                        self.analyzed += 1
                except UnicodeDecodeError:
                    print("File is binary, ignoring: " + curr_dir)
                except FileNotFoundError:
                    print("Failed to open file: " + curr_dir)

    def prepare_for_model(self):

        dta = []
        u_lines = []
        for file in self.files:
            for line in file['lines']:
                line = line.strip()
                try:
                    if line not in u_lines:
                        temp = {'sentence': {'words': [], 'hashes': [], 'string': line}, 'length': len(line),
                                'hash': ssdeep.hash(line), 'label': None, 'path': file['name']}
                        # Tokenize by splitting on common log delimiters
                        tokens = set(re.split(r'[\s,\t|;:=\[\]{}]', line))
                        for token in tokens:
                            # Ignore single characters
                            if len(token) > 1:
                                temp['sentence']['hashes'].append(ssdeep.hash(token))
                                temp['sentence']['words'].append(token)

                        dta.append(temp)
                except Exception as e:
                    print(e)

        self.dta = dta


def main():
    '''
        sensy = sensitive_data_analyzer("/mnt/osx/Icloud_gathered_files")
        sensy.gather_strings()
        sensy.prepare_for_model()
        with open('/mnt/osx/secrets_analzyed.json','w') as j_file:
            json.dump(sensy.dta,j_file)
        print("Analyzed " + str(sensy.analyzed) + " lines")
    '''


if __name__ == "__main__":
    main()
