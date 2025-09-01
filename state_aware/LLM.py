import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import json
import logging
import tiktoken

from state_aware.const import *
from openai import OpenAI
from datasets import load_dataset, Audio
from transformers import pipeline, set_seed

log = logging.getLogger(__name__)


class LLMGenerator:
    def __init__(self, key, model):
        self.model = {}
        self.format_dir = os.path.join(os.path.dirname(__file__), "result/format")
        self.description_dir = os.path.join(os.path.dirname(__file__), "result/description")
        self.secret_key = key  # Replace your token
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key))
        self.corr_client = None
        self.initialize(model)

    def initialize(self, model):
        if "OPENAI_API_KEY" not in os.environ.keys():
            os.environ["OPENAI_API_KEY"] = self.secret_key

        if model == "deepseek":
            self.corr_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key), base_url="https://api.deepseek.com")
        else:
            self.corr_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", self.secret_key))

        self.model["audio"] = "facebook/wav2vec2-base-960h"
        self.model["text"] = "gpt-4o-mini"

    def audio_recognition(self):
        speech_recognizer = pipeline("automatic-speech-recognition", model=self.model["audio"])
        dataset = load_dataset("PolyAI/minds14", name="en-US", split="train")
        dataset = dataset.cast_column("audio", Audio(sampling_rate=speech_recognizer.feature_extractor.sampling_rate))
        result = speech_recognizer(dataset[:4]["audio"])
        print([d["text"] for d in result])

    def num_tokens_from_string(self, string: str, task: str) -> int:
        """Returns the number of tokens in a text string."""
        encoding = tiktoken.encoding_for_model(self.model[task])
        num_tokens = len(encoding.encode(string))
        return num_tokens

    def summary_all_descriptions(self):
        all_descriptions = {}
        for index, layer in enumerate(LAYERS):
            frames = FRAMES[index]
            if layer not in all_descriptions.keys():
                all_descriptions[layer] = {}
            for frame in frames:
                with open(os.path.join(self.description_dir, "{}_{}.json".format(layer, frame)), "r") as f:
                    desc = json.load(f)
                    all_descriptions[layer][frame] = desc

        return all_descriptions

    def LLM_format_generation(self, layer: str, frame: str, part: str, descriptions: dict):
        """
        Generate the format from message description using GPT-4o API
        :param descriptions:  All layers frames description list
        :return:
        """
        prompt = """
                The following is a description of the {} format of the Zigbee {} {} Frame.
                {}
        """

        system_instruction = """
                You are a helpful assistant. 
                Please extract the {} format of {} {} Frame.
        """

        standard_output = """
                The answer should be organized in JSON format. Following is an example of ZDP Command SimpleDescriptorRequest payload format.
                {"SimpleDescriptorRequest": {"Nwk Addr Of Interest": "uint16", "Endpoint": "uint8"}}
        """

        num_tokens = self.num_tokens_from_string(prompt, "text")

        if num_tokens > 500:
            log.error("The prompt is so long: {}!".format(num_tokens))
            return

        prompt_focus = prompt.format(part, layer, frame, descriptions)
        system_ins = system_instruction.format(part, layer, frame) + "\n" + standard_output

        response = self.client.responses.create(
            model=self.model["text"],
            instructions=system_ins,
            input=prompt_focus
        )

        message_format = response.output_text[0]

        return message_format

    def LLM_correlation(self, message_name: str, message_format: dict, layer1: str,
                        message_names: list, message_formats: dict, layer2: str) -> dict:

        system_prompt = """
        The answer should be organized in JSON format. The following is a example of a message MoveHue 
        and a list of messages [StepHue, MoveColor].
        
        EXAMPLE JSON OUTPUT:
        {
            "MoveHue, StepHue": {"attribute": "current_hue"},
            "MoveHue, MoveColor": {"attribute": null}
        }
        
        """

        user_prompt = f"""
        The following is the description of a {layer1} message {message_name}.
        {message_format}.
        
        Please determine whether the above message can act on the same device attribute as each message in the following message list. 
        The following are the descriptions of each {layer2} message in the message list {message_names}.
        {message_formats}.
        
         If so, return the device attributes correlated with each message in the list, otherwise return null.
        """

        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]

        attempt_count = 0

        while attempt_count < 3:
            response = self.corr_client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={
                    'type': 'json_object'
                }
            )
            try:
                final_response = json.loads(response.choices[0].message.content)
                return final_response
            except json.encoder.JSONEncoder:
                attempt_count += 1
                continue

        return {}

    def LLM_hidden_attributes(self, message_name: str, message_description: dict, layer: str) -> dict:
        system_prompt = """
        The answer should be organized in JSON format. The following is a example of the result of a ZCL message AddGroup.

        EXAMPLE JSON OUTPUT:
        {
            "Attributes": ["group_count"]
        }

        """

        user_prompt = f"""

        The following is the description of the Zigbee {layer} message {message_name}.
        {message_description}
        
        Focus especially on attributes that represent:
            - Internal state changes
            - Tables or counters
            - Membership tracking
            - Effects on reporting, scenes, or other clusters
        
        Please determine all potential device state attributes or variables that could be affected by the message. 
            If so, returns the names of these attributes. Otherwise, return an empty list.
        """

        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]

        attempt_count = 0

        while attempt_count < 3:
            response = self.corr_client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={
                    'type': 'json_object'
                }
            )
            try:
                final_response = json.loads(response.choices[0].message.content)
                return final_response
            except json.decoder.JSONDecodeError:
                attempt_count += 1
                continue
        return {}

    def LLM_attribute_permission(self, state_attributes_list: list, message_name: str,
                                 message_description: dict, layer: str) -> dict:
        system_prompt = """
        The answer should be organized in JSON format. The following is a example of the result of a ZCL message MoveToHueAndSaturation.

        EXAMPLE JSON OUTPUT:
        {
            "Read": [],
            "Write": ["transition_time", "current_hue", "current_saturation"],
            "Report": []
        }

        """

        user_prompt = f"""
        The following is the list of device state attributes.
        {state_attributes_list}.

        The following is the description of the Zigbee {layer} message {message_name}.
        {message_description}

        Please determine the attributes in the state list that the message can read, write and report respectively.
        If so, return attribute names. Otherwise, return an empty list.
        """

        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]

        attempt_count = 0

        while attempt_count < 3:
            response = self.corr_client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={
                    'type': 'json_object'
                }
            )
            try:
                final_response = json.loads(response.choices[0].message.content)
                return final_response
            except json.decoder.JSONDecodeError:
                attempt_count += 1
                continue
        return {}


if __name__ == "__main__":
    ds_key = "sk-0e0ebce461784008aa931af7b5fc0622"
    lg = LLMGenerator(ds_key, "deepseek")

    # 1. Summary all descriptions
    # description = lg.summary_all_descriptions()

    # 2. Generate formats according to LLM and process the result
    # lg.LLM_format_generation(description)

    # 3. Summary all message formats
    # lg.merge_all_messages()
    # lg.analyze_correlation()
