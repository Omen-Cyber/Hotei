import argparse
import hashlib
import os


def hasher(fp):
    hash_obj = hashlib.new('sha256')
    hash_obj.update(fp)
    return hash_obj.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Tool to create script to gather files from action center action")
    parser.add_argument('-fl', help='list of hostname and files')
    args = parser.parse_args()
    host_name = os.uname().nodename

    try:
        for file in file_list:
            if file[0] == host_name:
                with open(file[1], "rb") as ready:
                    in_file = ready.read()
                    fh = hasher(in_file)

                with open(file[1].split(" ::: ")[-1], 'wb') as test_file:
                    test_file.write(in_file)

                print(fh + " : " + file[1])

    except Exception as e:
        print("Failed to gather file: " + file[1])
        print(e)


if __name__ == "__main__":
    main()
