import os
import re
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from util.utils import *
from state_aware.LLM import *
from state_aware.const import *


def convert_name(name: str):
    name = re.sub(r'([a-z])([A-Z])', r'\1_\2', name)
    return name.lower()


def convert_list_types(input_dict):
    pattern1 = r'[Ll]ist of (.*)'
    pattern2 = r'list[<\[](.+?)[>\]]'

    for key, value in input_dict.items():
        if isinstance(value, dict):
            input_dict[key] = convert_list_types(value)
        elif isinstance(value, str):
            data_type = re.search(pattern1, value)
            data_type2 = re.search(pattern2, value)

            if data_type is None and data_type2 is None:
                input_dict[key] = value
            elif data_type is not None:
                input_dict[key] = {"t.List": data_type.group(1)}
            else:
                input_dict[key] = {"t.List": data_type2.group(1)}

    return input_dict


class FormatGenerator:
    def __init__(self):
        self.format_dir = os.path.join(os.path.dirname(__file__), "result/format")
        self.description_dir = os.path.join(os.path.dirname(__file__), "result/description")
        self.LLM = LLMGenerator("(Your API Key)", "deepseek")

    def format_generation(self):
        for index, layer in enumerate(LAYERS):
            # We extract formats of ZCL commands from specification directly instead of generating from description
            if layer == "ZCL":
                continue

            frames = FRAMES[index]
            parts = PARTS[index]

            with open(os.path.join(self.description_dir, f"{layer}.json"), "r") as f:
                layer_descriptions = json.load(f)

            for frame, part in zip(frames, parts):

                if layer != "ZDP":
                    general_frame_format_description = layer_descriptions[f"General {layer} Frame Format"]
                else:
                    general_frame_format_description = ""

                if frame == "ACK":
                    descript = {f"General {layer} Frame Format": general_frame_format_description,
                                "Acknowledgement Frame Format": layer_descriptions["Format of Individual Frame Types"][
                                    "Acknowledgement Frame Format"]}
                    message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)

                elif frame == "Data":
                    descript = {f"General {layer} Frame Format": general_frame_format_description,
                                "Acknowledgement Frame Format": layer_descriptions["Format of Individual Frame Types"][
                                    "Data Frame Format"]}
                    message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)

                elif frame == "Beacon":
                    descript = {f"General {layer} Frame Format": general_frame_format_description,
                                "Beacon Frame Format": layer_descriptions["Format of Individual Frame Types"][
                                    "Beacon Frame Format"]}

                    message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)

                else:
                    message_format = {}

                    if layer != "ZDP":
                        base_descript = {f"General {layer} Frame Format": general_frame_format_description,
                                         "Command Frame Format": layer_descriptions["Format of Individual Frame Types"]
                                         [f"{layer} Command Frame Format"]}
                        all_commands = layer_descriptions["Command Frames"]
                    else:
                        base_descript = {}
                        all_commands = {}

                    if layer == "APS":
                        pattern = f"{layer}_CMD_"

                        for cname in all_commands["Command Identifier"]:
                            if cname == "Reserved":
                                continue

                            if cname.startswith(pattern):
                                cname = cname[len(pattern):]
                            else:
                                continue

                            cmd_formatted = cname.title().replace("_", "-")
                            descript_key = f"{cmd_formatted} Commands"

                            descript = base_descript | {f"{descript_key}": layer_descriptions[descript_key]}

                            single_message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)

                            message_format.update(single_message_format)

                    elif layer == "NWK":
                        for cname, cmd_descript in all_commands.items():

                            cmd_final_name = cname.replace(" ", "")
                            descript = base_descript | {f"{cmd_final_name}": cmd_descript}

                            single_message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)
                            message_format.update(single_message_format)

                    elif layer == "MAC":
                        for index2, cname in enumerate(all_commands["Command Identifier"]):
                            if cname == "Reserved":
                                continue

                            cmd_id = all_commands["Value"][index2]
                            cmd_final_name = cname.replace(" ", "")

                            descript = base_descript | {f"Command Name": cmd_final_name, f"Command Identifier": cmd_id}
                            single_message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)
                            message_format.update(single_message_format)

                    else:
                        zdp_cmd_type = ["client", "server"]
                        for cmd_type in zdp_cmd_type:

                            type_commands = layer_descriptions[cmd_type]
                            commands = type_commands["messages"]

                            for command_type in commands.keys():
                                for command in commands[command_type]:
                                    descript = {f"{command}": type_commands[command]}
                                    single_message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)
                                    message_format.update(single_message_format)

                with open(os.path.join(self.format_dir, "{}/llm_format({}_{}).json".format(layer, layer, frame)), "w") as f:
                    json.dump(message_format, f, indent=4)

                self.process_result(layer, frame)

    def process_result(self, layer, frame):
        """
        Process the LLM generated (frame) format of Zigbee (layer) and return a standard json format
        :param layer: Zigbee protocol stack layer
        :param frame: Certain frame of specific layer
        :return:
        """
        with open(os.path.join(self.format_dir, "{}/llm_format({}_{}).json".format(layer, layer, frame)), "r") as f:
            result = json.load(f)

        new_result = {}
        for cmd_name, cmd_argument in result.items():
            cmd_name = convert_name(cmd_name)
            cmd_name = cmd_name.replace("_command", "")
            new_argument = {}
            for field_name, field_value in cmd_argument.items():
                new_field_name = convert_name(field_name)
                if type(field_value) != dict:
                    new_argument[new_field_name] = field_value
                else:
                    new_argument[new_field_name] = {}
                    for field_name2, field_value2 in field_value.items():
                        new_field_name2 = convert_name(field_name2)
                        if type(field_value2) != dict:
                            new_argument[new_field_name][new_field_name2] = field_value2
                        else:
                            new_argument[new_field_name][new_field_name2] = {}
                            for field_name3, field_value3 in field_value2.items():
                                new_field_name3 = convert_name(field_name3)
                                if type(field_value3) != dict:
                                    new_argument[new_field_name][new_field_name2][new_field_name3] = field_value3
            new_result[cmd_name] = new_argument

        new_result = convert_list_types(new_result)
        save_path = os.path.join(self.format_dir, "{}/format({}_{}).json".format(layer, layer, frame))

        if not os.path.exists(save_path):
            with open(save_path, "w") as f:
                json.dump(new_result, f, indent=4)

    def merge_all_messages(self):
        all_messages = {}
        zcl_messages = {}

        total_count = 0
        nozcl_count = 0
        general_count = 0

        save_path = os.path.join(self.format_dir, "all_formats(Zigbee).json")

        for index, layer in enumerate(LAYERS):
            layer_messages = {}
            for frame in FRAMES[index]:
                base_path = os.path.join(self.format_dir, layer)
                with open(os.path.join(base_path, "format({}_{}).json".format(layer, frame)), "r") as f:
                    formats = json.load(f)

                if layer == "ZCL" and frame == "Command":
                    for cluster, cvalue in formats.items():
                        for msg_type, msgs in cvalue.items():
                            for msg_name, msg_schema in msgs.items():
                                layer_messages[str(cluster) + "_" + msg_name] = msg_schema
                                zcl_messages[str(cluster) + "_" + msg_name] = msg_schema

                else:
                    layer_messages.update(formats)

                if frame == "General":
                    general_count += len(layer_messages)

            if layer != "ZCL":
                nozcl_count += len(layer_messages)

            total_count += len(layer_messages)
            all_messages[layer] = layer_messages

        if not os.path.exists(save_path):
            with open(save_path, "w") as f:
                json.dump(all_messages, f, indent=4)

        log.info(f"ZCL Other Layers Message Count: {nozcl_count}")
        log.info(f"ZCL General Message Count: {general_count}")
        log.info(f"ZCL Command Count: {len(zcl_messages)}")
        log.info(f"Extracted message count: {total_count}")

    async def run(self, format_generated=False):
        log.info(f"[Protocol State Awareness] Starting Generating Zigbee Formats...")

        if not format_generated:
            self.format_generation()

        self.merge_all_messages()
        progress_bar(5)

        log.info(f"[Protocol State Awareness] Generating Zigbee Formats Done!")


if __name__ == "__main__":
    fg = FormatGenerator()
    fg.run()
