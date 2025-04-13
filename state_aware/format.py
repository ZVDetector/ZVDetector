import os
import re
import sys

sys.path.append(os.path.dirname(os.getcwd()))

from util.utils import *
from LLM import *
from const import *


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
        self.format_dir = os.path.join(os.getcwd(), "result/format")
        self.description_dir = os.path.join(os.getcwd(), "result/description")
        self.LLM = LLMGenerator("(Your API Key)", "deepseek")

    def format_generation(self):
        for index, layer in enumerate(LAYERS):
            # We extract formats of ZCL commands from specification directly instead of generating from description
            if layer == "ZCL":
                continue

            frames = FRAMES[index]
            parts = PARTS[index]

            for frame, part in zip(frames, parts):
                descript = descriptions[layer][frame]
                message_format = self.LLM.LLM_format_generation(layer, frame, part, descript)

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
        with open(os.path.join(self.format_dir, "{}/format({}_{}).json".format(layer, layer, frame)), "w") as f:
            json.dump(new_result, f, indent=4)

    def merge_all_messages(self):
        all_messages = {}
        zcl_messages = {}

        total_count = 0
        nozcl_count = 0
        general_count = 0

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

        with open(os.path.join(self.format_dir, "all_formats(Zigbee).json"), "w") as f:
            json.dump(all_messages, f, indent=4)

        print(f"ZCL Other Layers Message Count: {nozcl_count}")
        print(f"ZCL General Message Count: {general_count}")
        print(f"ZCL Command Count: {len(zcl_messages)}")
        print(f"Extracted message count: {total_count}")


if __name__ == "__main__":
    fg = FormatGenerator()

    # 1. Generate the format
    # fg.format_generation()

    # 2. Summary all messages into a json file
    fg.merge_all_messages()
