import json
import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

import re
import time
from LLM import *
from const import *
from util.utils import *


class Attributes:
    def __init__(self):
        self.MESSAGE_DIR = os.path.join(os.getcwd(), "result/format")
        self.ZCL_ATTRIBUTE_DIR = os.path.join(os.getcwd(), "zha_zcl_library/zcl/result")
        self.BASIC_ATTR_DIR = os.path.join(os.getcwd(), "result/attribute/basic")
        self.HIDDEN_ATTR_DIR = os.path.join(os.getcwd(), "result/attribute/hidden")
        self.ATTR_PERMISSION_DIR = os.path.join(os.getcwd(), "result/attribute/permission")
        self.LLM = LLMGenerator(key="sk-0e0ebce461784008aa931af7b5fc0622", model="deepseek")

    def common_cluster_basic(self):
        common_cluster_attributes = []
        for cluster in common_used_cluster:
            with open(os.path.join(self.ZCL_ATTRIBUTE_DIR, f"{cluster}-attributes.json"), "r") as f:
                attributes = json.load(f)

            common_cluster_attributes.extend(attributes["Attributes"])

        if not os.path.exists(os.path.join(self.BASIC_ATTR_DIR, "basic attribute(common-cluster).txt")):
            write_list_to_file(os.path.join(self.BASIC_ATTR_DIR, "basic attribute(common-cluster).txt"),
                               common_cluster_attributes)

        return common_cluster_attributes

    def analyze_hidden_attributes(self):
        """
        Analyze hidden attributes using LLM.
        """
        with open(os.path.join(self.MESSAGE_DIR, "all_formats(Zigbee).json"), "r") as f:
            messages = json.load(f)

        hidden_attributes = {}
        llm_hidden_attributes = {}
        total_count = 0
        llm_total_count = 0
        time_cost = 0

        for layer, layer_msgs in messages.items():
            for msg_name, msg_value in layer_msgs.items():
                if msg_name in except_messages:
                    continue

                start_time = time.time()

                result = self.LLM.LLM_hidden_attributes(msg_name, msg_value, layer)

                end_time = time.time()

                time_cost += end_time - start_time

                if "Attributes" not in result.keys():
                    continue

                if result["Attributes"] is not None:
                    hidden_attributes["attr" + str(total_count)] = {
                        "message": msg_name,
                        "attributes": result["Attributes"]
                    }
                    total_count += 1

                llm_hidden_attributes["attr" + str(llm_total_count)] = {
                    "message": msg_name,
                    "attributes": result["Attributes"]
                }

                llm_total_count += 1

                print(f"[+] Round {llm_total_count} completed in {round((end_time - start_time), 2)} seconds.")

                if llm_total_count % 50 == 0:
                    with open(os.path.join(self.HIDDEN_ATTR_DIR, f"rounds/round-{llm_total_count}.json"), "w") as f:
                        json.dump(hidden_attributes, f, indent=4)

        with open(os.path.join(self.HIDDEN_ATTR_DIR, "hidden_attributes.json"), "w") as f:
            json.dump(hidden_attributes, f, indent=4)

        with open(os.path.join(self.HIDDEN_ATTR_DIR, "hidden_attributes(llm).json"), "w") as f:
            json.dump(llm_hidden_attributes, f, indent=4)

        print(f"[+] Hidden Attributes Analysis Time Cost: {time_cost}")

    def verify_hidden_attributes(self):
        with open(os.path.join(self.HIDDEN_ATTR_DIR, "hidden_attributes.json"), "r") as f:
            hidden_attributes = json.load(f)

        hidden_attributes_list = []

        for attr, attr_info in hidden_attributes.items():
            if list(attr_info["attributes"]):
                hidden_attributes_list.extend(attr_info["attributes"])

        print(f"[+] Non-Verified Hidden Attributes Count:{len(hidden_attributes_list)}")

        basic_attribute_list = read_list_from_file(os.path.join(self.BASIC_ATTR_DIR,
                                                                "basic attribute(common-cluster).txt"))

        invalid_count = 0
        valid_attribute_list = []
        for ha in hidden_attributes_list:
            if ha in basic_attribute_list or ha in except_fields:
                invalid_count += 1
            else:
                valid_attribute_list.append(ha)

        write_list_to_file(os.path.join(self.HIDDEN_ATTR_DIR, "hidden_attributes(valid).txt"), valid_attribute_list)

        print(f"[+] Basic-Verified Hidden Attributes Count:{len(valid_attribute_list)}")

    def analyze_attribute_permission(self):
        basic_attribute_list = read_list_from_file(os.path.join(self.BASIC_ATTR_DIR,
                                                                "basic attribute(common-cluster).txt"))
        hidden_attributes_list = read_list_from_file(os.path.join(self.HIDDEN_ATTR_DIR,
                                                                  "hidden_attributes(valid).txt"))

        all_state_attributes = basic_attribute_list + hidden_attributes_list

        with open(os.path.join(self.MESSAGE_DIR, "all_formats(Zigbee).json"), "r") as f:
            messages = json.load(f)

        time_cost = 0
        message_readable = []
        message_writable = []
        # message_reportable = []

        attribute_permission = {}

        rounds = 0
        batch_size = 20

        for layer, layer_msgs in messages.items():
            for msg_name, msg_value in layer_msgs.items():
                if msg_name in except_messages:
                    continue

                state_attributes_batches = [all_state_attributes[i:i + batch_size] for i in
                                            range(0, len(all_state_attributes), batch_size)]

                for batch_index, state_attributes in enumerate(state_attributes_batches):

                    start_time = time.time()

                    result = self.LLM.LLM_attribute_permission(state_attributes, msg_name, msg_value, layer)

                    end_time = time.time()

                    batch_round_cost = round(end_time - start_time, 2)
                    time_cost += end_time - start_time

                    if "Read" in result.keys():
                        message_readable.extend(result["Read"])
                        for attr in result["Read"]:
                            if attr not in attribute_permission.keys():
                                attribute_permission[attr] = {"Read": [msg_name]}
                            elif "Read" not in attribute_permission[attr].keys():
                                attribute_permission[attr]["Read"] = [msg_name]
                            else:
                                attribute_permission[attr]["Read"].append(msg_name)

                    if "Write" in result.keys():
                        message_writable.extend(result["Write"])
                        for attr in result["Write"]:
                            if attr not in attribute_permission.keys():
                                attribute_permission[attr] = {"Write": [msg_name]}
                            elif "Write" not in attribute_permission[attr].keys():
                                attribute_permission[attr]["Write"] = [msg_name]
                            else:
                                attribute_permission[attr]["Write"].append(msg_name)

                    # if "Reportable" in result.keys():
                    #     message_reportable.extend(result["Report"])
                    #     for attr in result["Report"]:
                    #         if attr not in attribute_permission.keys():
                    #             attribute_permission[attr] = {"Report": [msg_name]}
                    #         elif "Report" not in attribute_permission[attr].keys():
                    #             attribute_permission[attr]["Report"] = [msg_name]
                    #         else:
                    #             attribute_permission[attr]["Report"].append(msg_name)

                    print(f"[+] Round {rounds}-batch {batch_index} complete. ({batch_round_cost}s)")

                    if batch_index % 10 == 0:
                        with open(os.path.join(self.ATTR_PERMISSION_DIR, f"round {rounds}-batch {batch_index}.json"),
                                  "w") as f:
                            json.dump(attribute_permission, f, indent=4)

                rounds += 1

        with open(os.path.join(self.ATTR_PERMISSION_DIR, "attribute_permission.json"), "w") as f:
            json.dump(attribute_permission, f, indent=4)

        total_count = len(message_readable) + len(message_writable)

        # print(f"[+] Analyzed Attributes Permission Count: {total_count}")
        print(f"[+] Attributes Permission Analysis Time Cost: {round(time_cost, 2)}")

    def endpoint_support_permission(self):
        with open(os.path.join(self.ATTR_PERMISSION_DIR, "attribute_permission.json"), "r") as f:
            attribute_permission = json.load(f)

        readable = []
        writable = []
        # reportable = []
        for attr, permission in attribute_permission.items():
            if "Read" in permission.keys():
                if type(permission["Read"]) == list:
                    readable.extend(list(set(permission["Read"])))
                elif type(permission["Read"]) == str:
                    readable.append(permission["Read"])

            if "Write" in permission.keys():
                if type(permission["Write"]) == list:
                    writable.extend(list(set(permission["Write"])))
                elif type(permission["Write"]) == str:
                    writable.append(permission["Write"])

            # if "Reportable" in permission.keys():
            #     if type(permission["Report"]) == list:
            #         reportable.extend(list(set(permission["Read"])))
            #     elif type(permission["Report"]) == str:
            #         reportable.append(permission["Report"])

        print(f"[+] Analyzed Attributes Permission Count: {len(readable) + len(writable)}")
        print(f"[+] Read, Write Attributes Permission Count: {len(readable)} {len(writable)}")

        return readable, writable


if __name__ == "__main__":
    attr = Attributes()

    # Step 1: Acquire Common-cluster Basic Attributes
    cla = attr.common_cluster_basic()

    # Step 2: Analyze and Verify Hidden Attributes
    attr.analyze_hidden_attributes()
    attr.verify_hidden_attributes()

    # Step 3: Analyze Attribute Permissions
    attr.analyze_attribute_permission()

    # Step 4: Analyze Endpoint Support Permission
    attr.endpoint_support_permission()
