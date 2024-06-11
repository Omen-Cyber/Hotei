import argparse
import os
from concurrent.futures import ThreadPoolExecutor

import keyring
import pandas as pd
import requests


class action_center_gather:
    def __init__(self, endpoint_id, output_dir, action_center_id):
        self.api = keyring.get_credential('secrets_finder', '924')
        self.header = {"Authorization": self.api.password,
                       "x-xdr-auth-id": self.api.username,
                       "Accept": "application/json",
                       "Content-Type": "application/json"}
        self.session_object = requests.Session()
        self.endpoint_name = endpoint_id['Endpoint Name']
        self.user = endpoint_id['User']
        self.endpoint_id = endpoint_id['Endpoint ID']
        self.action_id = action_center_id
        self.out_dir = output_dir
        self.response = None

    def download_file(self):

        self.session_object.headers.update(self.header)

        url = "https:///public_api/v1/scripts/get_script_execution_results_files"

        payload = {"request_data": {
            "action_id": self.action_id,
            "endpoint_id": self.endpoint_id
        }}
        resp = self.session_object.post(url, json=payload)
        print("Downloading data for: ", self.endpoint_name)
        try:
            self.response = self.session_object.get(resp.json()['reply']['DATA']).content
            return self
        except:
            return None

    def write_file(self):
        try:
            final_dir = self.out_dir + "/" + self.endpoint_name
            os.mkdir(final_dir)
            output_file_name = final_dir + "/" + self.endpoint_name + '-' + self.user + '.zip'
            with open(output_file_name, 'wb') as file:
                print("Writing file: " + output_file_name)
                file.write(self.response)
        except Exception as e:
            print(e)

    def __str__(self):
        return self.endpoint_name, self.user, self.out_dir


def main():
    parser = argparse.ArgumentParser(description="Gather files from xsiam action center")
    parser.add_argument('-endpoints', help='list of endpoints,users,and,endpoint ids to collect')
    parser.add_argument('-out_dir', help='directory to export files', nargs='?', default=None)
    parser.add_argument('-id', help='action center id', )
    args = parser.parse_args()

    endpoints = pd.read_table(args.endpoints, low_memory=False)
    pd_rows = endpoints.iterrows()
    test = 0
    gathered_actions = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for index, row in pd_rows:
            gatherer = action_center_gather(row, args.out_dir, args.id)
            gathered_actions += [executor.submit(gatherer.download_file)]

        for action in gathered_actions:
            output = action.result()
            if output is not None:
                if output.response is not None:
                    output.write_file()
                else:
                    print(output)
            else:
                pass


if __name__ == "__main__":
    main()
