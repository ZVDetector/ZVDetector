import sys
import json
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from util.utils import *

base_dir = os.path.dirname(os.path.dirname(__file__))
format_result_dir = os.path.join(base_dir, "result/format")
messages_dir = os.path.join(base_dir, "result/messages")
dependency_dir = os.path.join(base_dir, "result/dependency")


def acquire_layer_messages(layer):
    with open(os.path.join(format_result_dir, f"all_formats(Zigbee).json"), "r") as f:
        all_messages_formats = json.load(f)

    if layer not in all_messages_formats:
        raise ValueError(f"Zigbee Layer {layer} not found in all_messages_formats")

    messages = all_messages_formats[layer].keys()
    write_list_to_file(os.path.join(messages_dir, f"Zigbee-{layer}.txt"), messages)
    return messages


if __name__ == "__main__":
    acquire_layer_messages("ZCL")
    with open(os.path.join(dependency_dir, "ZCL/result_unique.json"), "r") as f:
        dependencies = json.load(f)
    with open(os.path.join(dependency_dir, "ZCL/result_unique.json"), "w") as f:
        json.dump(dependencies, f, indent=4)
