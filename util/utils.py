import os
import sys
import typing
import signal
import datetime
from typing import List
import base64
import json
import shutil
import time
from subprocess import check_output, STDOUT


class InputTimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise InputTimeoutError


def input_with_timeout(prompt, timeout, default):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        user_input = input(prompt)
        signal.alarm(0)
        return user_input
    except InputTimeoutError:
        # log.info("[->] Continue Listening [<-]")
        return default


def find_subdirectories(root_dir: str, target_name: str) -> str:
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for dirname in dirnames:
            if dirname == target_name:
                return os.path.join(dirpath, dirname)
    return "No target directory found!"


def get_struct_time():
    current_time = datetime.datetime.now()

    formatted_time_str = current_time.strftime("%Y%m%d_%H:%M:%S")

    return formatted_time_str


def find_files_with_name(root_dir: str, target_name: str) -> str:
    for filename in os.listdir(root_dir):
        filepath = os.path.join(root_dir, filename)
        if os.path.isfile(filepath) and filename == target_name:
            return filepath

    return "No target file found!"


def find_files_with_prefix(directory: str, prefix: str) -> list:
    matching_files = []
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            full_path = os.path.join(directory, filename)
            if os.path.isfile(full_path):
                matching_files.append(full_path)

    return matching_files


def process_csv(csv_name: str, feature_list: List[str]):
    data = pd.read_csv(csv_name)
    traffic = data.values[:, 0]
    new_csv = pd.DataFrame(columns=feature_list)
    for index in range(data.shape[0]):
        line = traffic[index]
        values = line.split("$")
        print(values)
        new_csv.loc[new_csv.shape[0]] = values
    new_csv.to_csv(csv_name)


def packet_serialization(features):
    base_string = "("
    for index, feature in enumerate(features):
        base_string += str(feature)
        if index != len(features) - 1:
            base_string += ","
    base_string += ")"
    return base_string


def get_latest_file(directory: str) -> str:
    current_time = datetime.datetime.now()

    latest_file = None
    min_time_diff = None

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            try:
                timestamp_str = filename.rstrip('.json')
                file_time = datetime.datetime.strptime(timestamp_str, '%Y%m%d_%H:%M:%S')

                time_diff = abs((current_time - file_time).total_seconds())

                if min_time_diff is None or time_diff < min_time_diff:
                    min_time_diff = time_diff
                    latest_file = filename
            except ValueError:
                continue

    return latest_file


def get_all_combinations(lst: list):
    if not lst:
        return [[]]
    first_element = lst[0]
    rest_combinations = get_all_combinations(lst[1:])
    result_combinations = []

    if isinstance(first_element, list):
        for item in first_element:
            for combination in rest_combinations:
                result_combinations.append([item] + combination)
    else:
        for combination in rest_combinations:
            result_combinations.append([first_element] + combination)

    return result_combinations


def match_dict_item(dict1: dict, dict2: dict, return_item) -> list:
    if return_item not in dict1.keys():
        return list()

    for name, value in dict2.items():
        if name not in dict1.keys():
            return list()
        if dict1[name] != value:
            return list()

    return dict1[return_item]


def list_files_in_folder(directory: str):
    all_file_path = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            all_file_path.append(os.path.join(root, file))
    return all_file_path


def clear_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"Folder not exists: {folder_path}")
        return

    # traverse all files and folders in the folder_path
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)

        try:
            # if file
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            # if folder
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"delete {file_path} error: {e}")


def is_sublist(sublist, main_list):
    main_str = ','.join(map(str, main_list))
    sub_str = ','.join(map(str, sublist))
    return sub_str in main_str


def is_prefix(string_list: list, target: str):
    matches = [s for s in string_list if target.startswith(s)]
    return any(target.startswith(s) for s in string_list), matches


def progress_bar(duration):
    total_steps = 50
    for i in range(total_steps + 1):
        percent = (i / total_steps) * 100
        bar = '█' * i + '-' * (total_steps - i)
        print(f'\r[{bar}] {percent:.2f}%', end='')
        time.sleep(duration / total_steps)

    print("\n")
    time.sleep(2)


def execute(command):
    """
    Executes a command on the local host.
    :param str command: the command to be executedi
    :return: returns the output of the STDOUT or STDERR
    """
    print("Shell command : {}".format(command))
    command = "{}; exit 0".format(command)
    return check_output(command, stderr=STDOUT, shell=True).decode("utf-8")


def write_list_to_file(filepath, data_list):
    with open(filepath, 'w', encoding='utf-8') as f:
        for item in data_list:
            f.write(f"{item}\n")


def read_list_from_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f.readlines()]


if __name__ == "__main__":
    input_list = [1, [1, 2, 3], 3, [4, 5]]
    combinations = get_all_combinations(input_list)
    for combo in combinations:
        print(combo)



