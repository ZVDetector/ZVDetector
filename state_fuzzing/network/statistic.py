import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

import re
import json
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from util.utils import list_files_in_folder

CLUSTER_DB_DIR = os.path.join(os.path.dirname(os.getcwd()), "library", "cluster_db")
ATTRIBUTE_COUNT_DIR = os.path.join(os.path.dirname(os.getcwd()), "cp_analysis", "static/result/attribute")
PERMISSION_COUNT_DIR = os.path.join(os.path.dirname(os.getcwd()), "cp_analysis", "static/result/permission")
MESSAGE_COUNT_DIR = os.path.join(os.path.dirname(os.getcwd()), "cp_analysis", "static/result/format")


def count_writable_attr():
    all_writable_cluster_count = {}
    all_readable_cluster_count = {}
    all_reportable_cluster_count = {}
    all_sceneable_cluster_count = {}
    all_nonw_cluster_count = {}
    hidden_attr = 0
    all_writable_attr = {}
    all_readable_attr = {}
    all_reportable_attr = {}
    all_sceneable_attr = {}

    with open(os.path.join(ATTRIBUTE_COUNT_DIR, "attribute_fine.json")) as f:
        attributes = json.load(f)

    for cluster_name, cvalue in attributes.items():
        if cluster_name not in all_writable_cluster_count.keys():
            all_writable_cluster_count[cluster_name] = 0

        if cluster_name not in all_readable_cluster_count.keys():
            all_readable_cluster_count[cluster_name] = 0

        if cluster_name not in all_reportable_cluster_count.keys():
            all_reportable_cluster_count[cluster_name] = 0

        if cluster_name not in all_sceneable_cluster_count.keys():
            all_sceneable_cluster_count[cluster_name] = 0

        if cluster_name not in all_nonw_cluster_count.keys():
            all_nonw_cluster_count[cluster_name] = 0

        if cluster_name not in all_writable_attr.keys():
            all_writable_attr[cluster_name] = []

        if cluster_name not in all_reportable_attr.keys():
            all_reportable_attr[cluster_name] = []

        if cluster_name not in all_sceneable_attr.keys():
            all_sceneable_attr[cluster_name] = []

        if cluster_name not in all_readable_attr.keys():
            all_readable_attr[cluster_name] = []

        for attr, schema in cvalue["Attribute"].items():
            if "access" not in schema.keys():
                hidden_attr += 1
                continue

            if 'w' in schema["access"]:
                all_writable_cluster_count[cluster_name] += 1
                all_writable_attr[cluster_name].append(schema['id'])
            else:
                all_nonw_cluster_count[cluster_name] += 1

            if 'r' in schema["access"]:
                all_readable_cluster_count[cluster_name] += 1
                all_readable_attr[cluster_name].append(schema['id'])

            if 'p' in schema["access"]:
                all_reportable_cluster_count[cluster_name] += 1
                all_reportable_attr[cluster_name].append(schema['id'])

            if 's' in schema["access"]:
                all_sceneable_cluster_count[cluster_name] += 1
                all_sceneable_attr[cluster_name].append(schema['id'])

        with open(os.path.join(PERMISSION_COUNT_DIR, "readable_attr(cluster).json"), "w") as f:
            json.dump(all_readable_attr, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "writable_attr(cluster).json"), "w") as f:
            json.dump(all_writable_attr, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "reportable_attr(cluster).json"), "w") as f:
            json.dump(all_reportable_attr, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "sceneable_attr(cluster).json"), "w") as f:
            json.dump(all_sceneable_attr, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "sceneable_attr_count(cluster).json"), "w") as f:
            json.dump(all_sceneable_cluster_count, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "readable_attr_count(cluster).json"), "w") as f:
            json.dump(all_readable_cluster_count, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "writable_attr_count(cluster).json"), "w") as f:
            json.dump(all_readable_cluster_count, f, indent=4)

        with open(os.path.join(ATTRIBUTE_COUNT_DIR, "nonwritable_attr_count(cluster).json"), "w") as f:
            json.dump(all_nonw_cluster_count, f, indent=4)

        with open(os.path.join(PERMISSION_COUNT_DIR, "reportable_attr_count(cluster).json"), "w") as f:
            json.dump(all_readable_cluster_count, f, indent=4)


def judge_write_attr(cluster_name: str):
    count = 0
    with open(os.path.join(ATTRIBUTE_COUNT_DIR, "attribute_fine.json")) as f:
        attributes = json.load(f)

    if cluster_name not in attributes.keys():
        return count

    for attr, schema in attributes[cluster_name]["Attribute"].items():
        if 'w' in schema["access"]:
            count += 1

    return count


if __name__ == "__main__":
    count_writable_attr()

    with open(os.path.join(ATTRIBUTE_COUNT_DIR, "cluster_attribute_count_unique.json")) as f:
        count = json.load(f)

    with open(os.path.join(MESSAGE_COUNT_DIR, "message_distribution.json")) as f:
        msg_count = json.load(f)

    with open(os.path.join(ATTRIBUTE_COUNT_DIR, "nonwritable_attr_count(cluster).json")) as f:
        non_write_count = json.load(f)

    all_files = list_files_in_folder(CLUSTER_DB_DIR)
    name_match = r'.*/(.*?)_.*?\.json'

    all_attr_count = {}
    extra_attr_count = {}

    all_msg_count = {}
    extra_msg_count = {}

    for cluster_file in all_files:
        ieee = re.search(name_match, cluster_file).group(1)
        dev_name = ZIGBEE_DEVICE_MAC_MAP[ieee]
        if dev_name not in all_attr_count.keys():
            all_attr_count[dev_name] = 0

        if dev_name not in extra_attr_count.keys():
            extra_attr_count[dev_name] = 0

        if dev_name not in all_msg_count.keys():
            all_msg_count[dev_name] = 0

        if dev_name not in extra_msg_count.keys():
            extra_msg_count[dev_name] = 0

        with open(cluster_file) as f1:
            support_clusters = json.load(f1)

        for kind, clusters in support_clusters.items():
            for cluster_name, cluster_id in clusters.items():
                if cluster_name == "Unknown":
                    continue

                if cluster_name in count.keys():
                    all_attr_count[dev_name] += count[cluster_name]
                    # extra_attr_count[dev_name] += non_write_count[cluster_name]
                    if kind == "output":
                        extra_attr_count[dev_name] += count[cluster_name]

                if cluster_name in msg_count.keys():
                    all_msg_count[dev_name] += msg_count[cluster_name]
                    if kind == "output":
                        extra_msg_count[dev_name] += msg_count[cluster_name]

    with open(os.path.join(ATTRIBUTE_COUNT_DIR, "official_support_attr(device).json"), "w") as f:
        json.dump(all_attr_count, f, indent=4)

    with open(os.path.join(ATTRIBUTE_COUNT_DIR, "extra_support_attr(device).json"), "w") as f:
        json.dump(extra_attr_count, f, indent=4)

    with open(os.path.join(MESSAGE_COUNT_DIR, "extra_support_msg(device).json"), "w") as f:
        json.dump(extra_msg_count, f, indent=4)

    with open(os.path.join(MESSAGE_COUNT_DIR, "official_support_msg(device).json"), "w") as f:
        json.dump(all_msg_count, f, indent=4)

    hubfuzzer_attr_count = {}
    hubfuzzer_msg_count = {}

    for dev_name, dev_value in all_attr_count.items():
        hubfuzzer_attr_count[dev_name] = dev_value - extra_attr_count[dev_name]

    print("ZVDetector: {}".format(all_attr_count))
    print("Hubfuzzer: {}".format(hubfuzzer_attr_count))
    print("Extra: {}".format(extra_attr_count))

    for dev_name, dev_value in all_msg_count.items():
        hubfuzzer_msg_count[dev_name] = dev_value - extra_msg_count[dev_name]

    print("—————————————————————————————————————————————————————————————————————————————————————————"
          "—————————————————————————————————————————————————————————————————————————————————————————"
          "——————————————————————————————————————")

    print("ZVDetector: {}".format(all_msg_count))
    print("Hubfuzzer: {}".format(hubfuzzer_msg_count))
    print("Extra: {}".format(extra_msg_count))
