import json
import os
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import re
import csv
from state_aware.merge import merge_groups
from state_aware.LLM import *
from state_aware.const import *
from util.utils import *


def remove_parentheses(text):
    return re.sub(r'\(.*?\)', '', text).strip()


def check_inclusion_relation(str1: str, str2: str):
    if str1 == str2:
        return False

    if "|" in str1 or "|" in str2:
        str1_list = str1.split("|")
        str2_list = str2.split("|")
        for str11 in str1_list:
            for str22 in str2_list:
                if str11.strip() == str22.strip():
                    continue
                if str11.strip() in str22.strip() or str22.strip() in str11.strip():
                    return True

    elif str1.strip() in str2.strip() or str2.strip() in str1.strip():
        return True
    else:
        return False


def check_dict_inlist(list1):
    list2 = []
    for i in list1:
        if type(i) == dict:
            list2.append(list(i.keys())[0])
        else:
            list2.append(i)
    return list2


def same_field_correlation(message1: dict, message2: dict):
    message1_fields = list(message1.values())[0]
    message2_fields = list(message2.values())[0]

    fields1 = [i for i in message1_fields.keys() if i not in except_fields]
    fields2 = [i for i in message2_fields.keys() if i not in except_fields]

    data_type1 = [message1_fields[i] for i in message1_fields.keys() if i not in except_fields]
    data_type2 = [message2_fields[i] for i in message2_fields.keys() if i not in except_fields]

    data_type1 = check_dict_inlist(data_type1)
    data_type2 = check_dict_inlist(data_type2)

    same_field = list(set(fields1) & set(fields2))
    new_same_field = []

    for field in same_field:
        index1 = fields1.index(field)
        index2 = fields2.index(field)

        dt1 = remove_parentheses(str(data_type1[index1]))
        dt2 = remove_parentheses(str(data_type2[index2]))

        if dt1 == dt2:
            new_same_field.append(field)

    if new_same_field:
        return True, new_same_field
    else:
        return False, []


def type_containment_correlation(message1: dict, message2: dict):
    message1_fields = list(message1.values())[0]
    message2_fields = list(message2.values())[0]

    data_type1 = [message1_fields[i] for i in message1_fields.keys() if i not in except_fields]
    data_type2 = [message2_fields[i] for i in message2_fields.keys() if i not in except_fields]
    data_type1 = check_dict_inlist(data_type1)
    data_type2 = check_dict_inlist(data_type2)

    for index1, type1 in enumerate(data_type1):
        for index2, type2 in enumerate(data_type2):
            if type(type1) == int or type(type2) == int:
                continue
            if check_inclusion_relation(type1, type2):
                return True, [list(message1_fields.keys())[index1], list(message2_fields.keys())[index2]]
    return False, []


class Correlation:
    def __init__(self):
        self.CORR_SAVE_DIR = os.path.join(os.path.dirname(__file__), "result/correlation")
        self.FORMAT_DIR = os.path.join(os.path.dirname(__file__), "result/format")
        self.LLM = LLMGenerator(key="sk-0e0ebce461784008aa931af7b5fc0622", model="deepseek")
        self.layer_map = {
            "zigbee": LAYERS,
            "zwave": ZWAVE_LAYERS
        }

        self.not_consider_corr_msgs = {
            "zigbee": EXCEPT_CORR,
            "zwave": ZWAVE_EXCEPT_CORR
        }

    def zwave_formats_transformation(self, layer: str):

        zwave_layer_formats = {}
        with open(os.path.join(self.FORMAT_DIR, f"Z-Wave/{layer}.json"), "r") as f:
            layer_format = json.load(f)

        for layer_type, layer_value in layer_format.items():
            for sublayer_type, sublayer_value in layer_value.items():
                for cmd_name, cmd_format in sublayer_value.items():
                    cmd_key = layer_type + "_" + sublayer_type + "_" + cmd_name
                    zwave_layer_formats[cmd_key] = cmd_format

        return zwave_layer_formats

    def acquire_layer_messages(self, layer: str, protocol: str = "zigbee"):
        all_messages = []
        layer_messages = {}

        if protocol == "zwave":
            zwave_layer_formats = self.zwave_formats_transformation(layer)
            for message, mvalue in zwave_layer_formats.items():
                all_messages.append({message: mvalue})
                layer_messages[message] = mvalue

            return all_messages, layer_messages

        with open(os.path.join(self.FORMAT_DIR, f"{layer}/format({layer}_Command).json"), "r") as f:
            result = json.load(f)

        if layer == "ZCL":
            for cluster, cvalue in result.items():
                for messages in cvalue.values():
                    for message, mvalue in messages.items():
                        all_messages.append({message: mvalue})
        else:
            for message, mvalue in result.items():
                all_messages.append({message: mvalue})

        return all_messages, layer_messages

    def analyze_basic_correlation(self, protocol: str = "zigbee"):
        """
        Analyze two correlation types: same_field_correlation and type_containment_correlation
        """

        basic_corr_count = 0

        if protocol not in self.layer_map:
            log.error(f"[ERROR] {protocol} is not supported!")
            return None

        all_layers = self.layer_map[protocol]

        all_layer_messages = {}

        for layer in all_layers:
            messages, layer_messages = self.acquire_layer_messages(layer, protocol)
            all_layer_messages[layer] = layer_messages

            results = {}
            base_key = "correlation"

            all_share_fields = []
            for index, message in enumerate(messages):
                for i in range(index + 1, len(messages)):
                    if i == index:
                        continue

                    result1 = same_field_correlation(message, messages[i])
                    result2 = type_containment_correlation(message, messages[i])

                    if result1[0]:
                        basic_corr_count += 1
                        results[base_key + "{}".format(basic_corr_count)] = {"messages": [message, messages[i]],
                                                                             "fields": result1[1]}
                        all_share_fields.extend(result1[1])

                    elif result2[0]:
                        basic_corr_count += 1
                        results[base_key + "{}".format(basic_corr_count)] = {"messages": [message, messages[i]],
                                                                             "fields": result2[1]}
                        all_share_fields.extend(result2[1])

            with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/basic_correlation({layer}).json"), "w") as f:
                json.dump(results, f, indent=4)

            with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/corr_share_fields({layer}).txt"), "w") as f:
                all_share_fields = list(set(all_share_fields))
                for item in all_share_fields:
                    f.write(str(item) + "\n")

            with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/corr_share_fields({layer}).json"), "w") as f2:
                json.dump(list(set(all_share_fields)), f2)

        if protocol != "zigbee":
            with open(os.path.join(self.FORMAT_DIR, f"all_formats({protocol}).json"), "w") as f:
                json.dump(all_layer_messages, f, indent=4)

        return basic_corr_count

    def analyze_hidden_correlation(self, protocol: str = "zigbee"):
        corr_result = {}
        llm_corr_result = {}

        hidden_corr_total = 0
        llm_generated_total = 0

        llm_batch_save_dir = os.path.join(self.CORR_SAVE_DIR, f"{protocol}/llm_batch")

        with open(os.path.join(llm_batch_save_dir, "configuration.json"), "r") as f:
            conf = json.load(f)

        if "round" in conf.keys():
            start_round = conf["round"]
        else:
            start_round = 0

        batch = 20
        rounds = 0

        if protocol not in self.layer_map:
            log.error(f"[ERROR] {protocol} is not supported!")
            return None

        all_layers = self.layer_map[protocol]

        with open(os.path.join(self.FORMAT_DIR, f"all_formats({protocol}).json"), "r") as f:
            all_messages = json.load(f)

        for index, layer in enumerate(all_layers):
            base_messages = all_messages[layer]

            for i in range(index, len(all_layers)):
                layer2 = all_layers[i]
                com_messages = all_messages[layer2]

                for msg_name, msg_format in base_messages.items():
                    items = list(com_messages.items())
                    filtered_items = [item for item in items if item[0] != msg_name]
                    com_messages_batches = [dict(filtered_items[i:i + batch]) for i in
                                            range(0, len(filtered_items), batch)]

                    if rounds < start_round:
                        rounds += 1
                        continue

                    for batch_index, com_messages_batch in enumerate(com_messages_batches):
                        message_name_list = list(com_messages_batch.keys())

                        result = self.LLM.LLM_correlation(msg_name, msg_format, layer,
                                                          message_name_list, com_messages_batch, layer2)

                        # Process the LLM Generated Result
                        for msg_pair, corr_attr in result.items():
                            messages = [msg.strip() for msg in msg_pair.split(",")]

                            if corr_attr is None:
                                continue

                            if "attribute" not in corr_attr.keys():
                                continue

                            if corr_attr["attribute"] is not None:
                                corr_result["hidden_corr" + str(hidden_corr_total)] = {"messages": messages,
                                                                                       "layers": [layer, layer2],
                                                                                       "attribute": corr_attr[
                                                                                           "attribute"]}
                                hidden_corr_total += 1

                            llm_corr_result["hidden_corr" + str(llm_generated_total)] = {"messages": messages,
                                                                                         "layers": [layer, layer2],
                                                                                         "attribute": corr_attr[
                                                                                             "attribute"]}
                            llm_generated_total += 1

                        log.info(f"[+] Hidden Correlation Analysis: Rounds {rounds} - Batch {batch_index} done!")

                        # Each batch save the analyzed result
                        if rounds % 25 == 0:
                            with open(os.path.join(llm_batch_save_dir, f"round{rounds}.json"), "w") as f:
                                json.dump(corr_result, f, indent=4)

                    rounds += 1

        save_path = os.path.join(llm_batch_save_dir, "hidden_correlation({layer}).json")

        if not os.path.exists(save_path):
            with open(save_path, "w") as f:
                json.dump(corr_result, f, indent=4)

        save_path2 = os.path.join(self.CORR_SAVE_DIR, f"{protocol}/hidden_correlation(LLM).json")

        if not os.path.exists(save_path2):
            with open(save_path2, "w") as f:
                json.dump(llm_corr_result, f, indent=4)

        return hidden_corr_total

    def verify_hidden_correlation(self, protocol: str = "zigbee"):

        except_total = 0
        valid_correlation = {}

        except_corr = self.not_consider_corr_msgs[protocol]

        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/hidden_correlation.json"), "r") as f:
            hidden_correlations = json.load(f)

        for corr, corr_value in hidden_correlations.items():
            if len(corr_value["messages"]) != 2:
                except_total += 1
                continue
            if corr_value["messages"][0] in except_corr or corr_value["messages"][1] in except_corr:
                except_total += 1
                continue

            check_attributes = corr_value["attribute"]

            if type(corr_value["attribute"]) == str:
                check_attributes = corr_value["attribute"].split(",")

            duplicate_flag = True
            for attribute in check_attributes:
                if attribute not in except_fields:
                    duplicate_flag = False
                    break
            if duplicate_flag:
                continue

            valid_correlation.update({corr: corr_value})

        save_path = os.path.join(self.CORR_SAVE_DIR, f"{protocol}/hidden_correlation(valid).json")

        if not os.path.exists(save_path):
            with open(save_path, "w") as f:
                json.dump(valid_correlation, f, indent=4)

        log.info(f"[+] Field Filtered Hidden Correlations: {len(hidden_correlations) - len(valid_correlation)}")
        log.info(f"[+] Non ACK & Data Frame Field Valid Hidden Correlations: {len(valid_correlation)}")
        return len(valid_correlation)

    def merge_all_correlations(self, protocol: str = "zigbee"):
        """
        Merge basic correlations and hidden correlations
        :return:
        """
        total_count = 0
        all_correlations = {}

        basic_correlation_msg_pairs = []
        basic_correlation_fields = []

        if protocol not in self.layer_map:
            log.error(f"[ERROR] {protocol} is not supported!")
            return None

        all_layers = self.layer_map[protocol]

        # Acquire all basic correlations
        for layer in all_layers:
            with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/basic_correlation({layer}).json"), "r") as f:
                basic_correlation = json.load(f)

            for cvalue in basic_correlation.values():
                messages = cvalue["messages"]
                basic_correlation_msg_pairs.append((list(messages[0].keys())[0], list(messages[1].keys())[0]))
                basic_correlation_fields.append(
                    cvalue["fields"])  # Add shared fields according to correlated message pairs

            all_correlations.update(basic_correlation)
            total_count += len(basic_correlation)

        # Analyze the hidden correlations
        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/hidden_correlation(valid).json"), "r") as f:
            hidden_correlations = json.load(f)

        # Kind 1: hidden correlations that no duplicate with basic correlations (new discovery)
        non_duplicate_hidden_correlations = {}

        # Kind 2: hidden correlations that duplicate with basic correlations but discover new correlated attributes
        duplicate_correlations_with_new_attributes = {}

        for corr_name, cvalue in hidden_correlations.items():
            messages = cvalue["messages"]
            hidden_correlation_msg_pair = (messages[0], messages[1])

            # Hidden correlation exist in basic correlations,
            # then judge whether new shared attributes is obtained by LLM

            if hidden_correlation_msg_pair in basic_correlation_msg_pairs:
                location = basic_correlation_msg_pairs.index(hidden_correlation_msg_pair)

                if "," in cvalue["attribute"]:
                    hidden_corr_attributes = cvalue["attribute"].split(",")
                else:
                    hidden_corr_attributes = [cvalue["attribute"]]

                for field in basic_correlation_fields[location]:
                    break_flag = False
                    for hidden_field in hidden_corr_attributes:
                        if hidden_field.strip() not in field and field not in hidden_field.strip():
                            duplicate_correlations_with_new_attributes.update({corr_name: cvalue})
                            break_flag = True
                            break
                    if break_flag:
                        break

            else:
                non_duplicate_hidden_correlations.update({corr_name: cvalue})

        all_correlations.update(non_duplicate_hidden_correlations)

        total_count += len(non_duplicate_hidden_correlations)
        # total_count += len(duplicate_correlations_with_new_attributes)

        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/all_correlations.json"), "w") as f:
            json.dump(all_correlations, f, indent=4)

        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/duplicate_correlations_with_new_attr.json"), "w") as f:
            json.dump(duplicate_correlations_with_new_attributes, f, indent=4)

        log.info(
            f"[+] Filtered Duplicate Hidden Correlation Count: {len(hidden_correlations) - len(non_duplicate_hidden_correlations)}")
        log.info(
            f"[+] Duplicate Hidden Correlation With New Attributes Count: {len(duplicate_correlations_with_new_attributes)}")

        log.info(f"[+] Valid Hidden Correlation With No Duplicate Count: {len(non_duplicate_hidden_correlations)}")

        log.info(f"[+] Valid Hidden Correlation Count: {len(non_duplicate_hidden_correlations)}")

        log.info(f"[+] All Correlations Count: {total_count}")

        return all_correlations

    def analyze_correlation_group(self, protocol: str = "zigbee"):
        """
        Merge correlation message pairs and constitute a correlation group
        Correlation 1: [A, B]
        Correlation 2: [B, C]
        -> Correlation Group: [A, B, C]

        :return: Correlation group count
        results are saved in the file "correlation_group.json" and "correlation_group.csv"
        """
        message_pairs = []

        all_correlations = self.merge_all_correlations()

        for cvalue in all_correlations.values():
            messages = cvalue["messages"]
            if type(messages[0]) == dict:
                message_pairs.append((list(messages[0].keys())[0], list(messages[1].keys())[0]))
            else:
                message_pairs.append((messages[0], messages[1]))

        correlation_group = merge_groups(message_pairs)  # Union Set Tree

        result = {}
        for index, corr_group in enumerate(correlation_group):
            result[f"group{index}"] = corr_group

        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/correlation_group.json"), "w") as f:
            json.dump(result, f, indent=4)

        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/correlation_group.csv"), "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(correlation_group)

        return len(correlation_group)

    def analyze_corr_msg_pairs(self, protocol: str = "zigbee"):
        all_message_pairs = []
        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/all_correlations.json"), "r") as f:
            all_correlations = json.load(f)

        hidden_corr_pattern = re.compile(r"hidden_corr\d+")

        for corr_name, corr_value in all_correlations.items():
            match = hidden_corr_pattern.search(corr_name)
            if match is not None:
                all_message_pairs.append(corr_value["messages"])
            else:
                tmp_message_pair = []
                for message in corr_value["messages"]:
                    tmp_message_pair.append(list(message.keys())[0])
                    log.info(f"[Correlation] Correlation Pair: {tmp_message_pair}")
                all_message_pairs.append(tmp_message_pair)

        save_all_message_pairs = []
        for message_pair in all_message_pairs:
            save_all_message_pairs.append(",".join(message_pair))

        write_list_to_file(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/corr_msg_pairs.txt"), save_all_message_pairs)

        correlations = defaultdict(set)
        for message_pair in save_all_message_pairs:
            corr_messages = message_pair.split(",")

            if len(corr_messages) != 2:
                continue

            msg1 = corr_messages[0].strip()
            msg2 = corr_messages[1].strip()

            correlations[msg1].add(msg2)
            correlations[msg2].add(msg1)

        msg_all_corr = {
            message: sorted(list(related_messages))
            for message, related_messages in correlations.items()
        }

        with open(os.path.join(self.CORR_SAVE_DIR, f"{protocol}/msg_all_corr.json"), "w") as f:
            json.dump(msg_all_corr, f, indent=4)

        log.info("[Protocol State Awareness] Correlation Analysis Done!")

    async def run(self, discovery_done=False):
        """
        Analyze Message Correlations. Default zigbee, or set protocol to others like zwave.
        """

        log.info("[Protocol State Awareness] Analyzing Message Correlations...")

        if not discovery_done:
            # Step 1: Analyze all basic correlations
            basic_count = self.analyze_basic_correlation()
            # basic_count = self.analyze_basic_correlation(protocol="zwave")
            log.info(f"[+] Basic Correlation Count: {basic_count}")

            # Step 2: Analyze all hidden correlations
            hidden_count = self.analyze_hidden_correlation()
            # hidden_count = self.analyze_hidden_correlation(protocol="zwave")
            log.info(f"[+] Hidden Correlation With Duplicate Count: {hidden_count}")
            self.verify_hidden_correlation()

            # # Step 3: Merge all correlations and analyze all correlations groups
            # group_count = self.analyze_correlation_group(protocol="zwave")
            group_count = self.analyze_correlation_group()
            log.info(f"[+] Correlation Group Count: {group_count}")

            # self.analyze_corr_msg_pairs(protocol="zwave")
            self.analyze_corr_msg_pairs()

        time.sleep(5)
        log.info("[Protocol State Awareness] Analyzing Message Correlations Done!")


if __name__ == "__main__":
    corr = Correlation()
    corr.run(discovery_done=False)
