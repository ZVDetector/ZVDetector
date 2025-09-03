import os
import random
import sys

sys.path.append(os.path.dirname(os.getcwd()))

import re
import copy
import json
import time
import base64
import signal
import typing
import logging
import asyncio
from datetime import datetime

import zigpy.device
from zigpy.zcl import foundation
import zigpy.endpoint
import zigpy.types as t
from zigpy.application import ControllerApplication
from zigpy_znp.zigbee.application import ZNP
from zigpy.types import EUI64, NWK

from util.logger import get_logger
from util.serial import serialize, ZIGBEE_STR_TYPE, ZIGBEE_INTEGER_TYPE, ZIGBEE_ARRAY_TYPE

from util.utils import *
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from state_fuzzing.gateway import ZHAGateway, parse_args
from pathlib import Path

# python fuzzer.py -c 20 -d 15 -l -o network.json /dev/tty.usbserial-14110
# python fuzzer.py -c 20 -d 15 -l -o network.json /dev/ttyUSB0

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

ZIGBEE_STR_MAX_LENGTH = {
    t.LVBytes: 255,
    t.CharacterString: 255,
    t.LongOctetString: 65535,
    t.LongCharacterString: 65535
}

STATUS = {status.value: status.name for status in foundation.Status}


class Mutator:

    def __init__(self):
        self.mutation_strategy = {
            "T-1-1": "Type-aware Mutation: Border & Extreme Values",
            "T-1-2": "Type-aware Mutation: Empty & Excessively Long Strings",
            "T-1-3": "Type-aware Mutation: Empty Arrays",
            "T-1-4": "Type-aware Mutation: Type Changes",
            "F-1-1": "Format-aware Mutation: Truncated Messages",
            "F-1-2": "Format-aware Mutation: Add/remove Fields",
            "F-1-3": "Format-aware Mutation: Unsupported Arguments",
        }

    @classmethod
    async def mutate_value(cls, types: typing.Any) -> list:
        """
        According to different types, generate some mutate values
        :param types: zigbee type
        :return: mutate value list
        """
        mutate_value = []
        if types in ZIGBEE_INTEGER_TYPE:
            bits = types.get_bit()
            max_value = types.max_value
            min_value = types.min_value
            mutate_value.append(int((min_value + max_value) / 2))
            mutate_value.append(max_value)
            mutate_value.append(min_value)
            mutate_value.append(max_value + 1)
            mutate_value.append(min_value - 1)
            mutate_value.append(-max_value + 1)
            mutate_value.append(-max_value)
            mutate_value.append(-max_value - 1)
            mutate_value.append(pow(2, bits * 2))
            mutate_value.append(-pow(2, bits * 2))

        elif types in ZIGBEE_STR_TYPE:
            max_length = ZIGBEE_STR_MAX_LENGTH[types]
            mutate_value.append("Normal")
            mutate_value.append("")
            mutate_value.append("f" * max_length)
            mutate_value.append("f" * (max_length + 1))
            mutate_value.append("f" * (max_length + 2))

        elif types in ZIGBEE_ARRAY_TYPE:
            mutate_value.append(list())

        return mutate_value

    @classmethod
    async def mutate_type(cls, types: typing.Any):
        """

        :param types: 给定数据类型
        :return: 返回针对该类型变异的datatype列表
        """
        mutate_value = []
        mutate_type_name = []
        if types in ZIGBEE_INTEGER_TYPE:
            mutate_value = [foundation.DATA_TYPES.pytype_to_datatype_id(a) for a in ZIGBEE_INTEGER_TYPE if a != types]
            mutate_type_name = [str(a) for a in ZIGBEE_INTEGER_TYPE if a != types]

        if types in ZIGBEE_STR_TYPE:
            mutate_value = [foundation.DATA_TYPES.pytype_to_datatype_id(a) for a in ZIGBEE_STR_TYPE if a != types]
            mutate_type_name = [str(a) for a in ZIGBEE_INTEGER_TYPE if a != types]

        # 正常值和其他变异字段组合
        mutate_value.insert(0, foundation.DATA_TYPES.pytype_to_datatype_id(types))
        mutate_type_name.insert(0, str(types))

        return mutate_value, mutate_type_name

    @classmethod
    async def mutate_payload(cls, payload_component: list, fuzz_prompt: list):
        """
        :param payload_component: Payload composition elements to be mutated
        :param fuzz_prompt: Denote which function to be used to mutate value
        :return: fuzz result
        """
        all_values = []
        fuzzed_payload = []
        mutated_list = []  # Record the mutate value

        # [(value, type: int, to_fuzz: Bool)]
        for index, component in enumerate(payload_component):
            if component[2]:
                mutate_value = await fuzz_prompt[index](component[1])
                all_values.append(mutate_value)
                mutated_list.append(mutate_value)
            else:
                all_values.append(component[0])
                mutated_list.append(None)

        combinations = get_all_combinations(all_values)

        for combo in combinations:
            payload_bytes = b''
            for index, value in enumerate(combo):
                payload_bytes += serialize(value, payload_component[index][1])
            fuzzed_payload.append(payload_bytes)
        return fuzzed_payload, combinations, mutated_list


def get_message_format(msg_name: str, all_messages: dict):
    for layer, layer_cmds in all_messages.items():
        for command, command_format in layer_cmds.items():
            if command == msg_name:
                return command_format
    return None


class StateFuzzer:
    def __init__(self, config):
        self.gateway = ZHAGateway(config)
        self.state_guided = args.load_state
        self.max_fuzzing_packet = 1000000
        self.max_iter_packet = 30000
        self.fuzz_info_db = os.path.join(os.getcwd(), "log")
        self.interesting_case_path = os.path.join(os.getcwd(), "interesting_case")
        self.crash_db_path = os.path.join(os.getcwd(), "crash/json")
        self.fuzzing_dir = os.path.join(os.path.dirname(__file__), "state_aware/result/fuzzing")
        self.format_dir = os.path.join(os.path.dirname(__file__), "state_aware/result/format")
        self.library_dir = os.path.join(os.path.dirname(__file__), "library")
        self.device_crash_count = 0
        self.crash_prompt = {
            "Timestamp": [],
            "Device": [],
            "IEEE": [],
            "Nwk_Address": [],
            "State": [],
            "Message_Relationship": [],
            "Fuzzing_Messages": [],
            "Mutation_Strategy": [],
            "Log": []
        }

    async def check_device_state(self, device_ieee, device_nwk, endpoint_id) -> int:
        # State the application controller
        app = await ControllerApplication.new(config={}, auto_form=True)

        try:
            device = app.get_device(ieee=device_ieee, nwk=device_nwk)
            if device is None:
                log.warning(f"[CRASH DETECTED] Device not found on network.")
                return 0

            # Judge crash by
            try:
                model_id = await device.endpoints[1].basic.read_attributes(['model'], allow_cache=False)
                log.info(f"Model ID: {model_id}")
            except Exception as e:
                log.error(f"[CRASH DETECTED] Cannot read basic attributes: {e}")
                self.device_crash_count += 1
                return 0

            # Judge Abnormal State by checking device alive and send control commands
            try:
                ep = device.endpoints.get(endpoint_id)  # endpoint 1 常用于 on/off cluster
                if ep is None:
                    log.warning(f"[ANOMALY] Endpoint 1 not found.")
                    return 0
                log.info("Sending toggle command to OnOff cluster...")

                # Try to send control messages such as Toggle under OnOff cluster
                res = await ep.on_off.toggle()
                log.info(f"Toggle response: {res}")

            except Exception as e:
                log.error(f"[ANOMALY] Device is alive but does not respond to control command: {e}")
                self.device_crash_count += 1
                return 0

        except Exception as e:
            log.error(f"[ERROR] Cannot Access Device !")
            return 0

        return 1

    async def get_state(self, ieee: t.EUI64) -> dict:
        """
        (1) Get current state and record in state_db
        (2) Get support attributes and record in attribute_db
        :param ieee: Device IEEE Address
        :return: Current device state or Fail Status
        """
        device = self.gateway.application_controller.devices[ieee]
        device_state, failure = {}, {}

        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.gateway.get_support_cluster(ieee, endpoint)
            support_attribute = await self.gateway.get_support_attribute()

            if str(ieee) not in support_attribute.keys():
                continue

            if str(endpoint.endpoint_id) not in support_attribute[str(ieee)].keys():
                continue

            cluster_attribute = support_attribute[str(ieee)][str(endpoint.endpoint_id)]

            device_state[str(endpoint.endpoint_id)] = {}

            for all_clusters in support_cluster.values():
                for cluster_name, cluster_id in all_clusters.items():
                    if cluster_name == "Unknown":
                        for cid in cluster_id:
                            save_cluster_name = "Manufacturer-Specific-Cluster_{}".format(cid)
                            device_state[str(endpoint.endpoint_id)][save_cluster_name] = {}
                    else:
                        device_state[str(endpoint.endpoint_id)][cluster_name] = {}

            for cluster_name, all_attributes in cluster_attribute.items():
                cluster_id = None

                if cluster_name != "Unknown":
                    if cluster_name in support_cluster["input"].keys():
                        cluster_id = support_cluster["input"][cluster_name]
                    elif cluster_name in support_cluster["output"].keys():
                        cluster_id = support_cluster["output"][cluster_name]
                    else:
                        continue

                manufacturer_attribute_count = 0

                for attribute in all_attributes:
                    attr_id = t.uint16_t(attribute["attr_id"])
                    attr_name = attribute["attr_name"]

                    if "cluster_id" in attribute.keys():  # 如果是厂商自定义的cluster
                        cluster_id = attribute["cluster_id"]
                        cluster_name = "Manufacturer-Specific-Cluster_{}".format(cluster_id)
                    try:
                        result = await self.gateway.send_zcl_general(endpoint, t.ClusterId(cluster_id), 0x00, [attr_id])
                        if not isinstance(result[0], list):
                            failure[attr_name] = result[0]
                        else:
                            for record in result[0]:
                                if record.status == foundation.Status.SUCCESS:
                                    try:
                                        value_type_id = record.value.type
                                        value_type = foundation.DATA_TYPES[value_type_id][1]
                                        value = value_type(record.value.value)
                                    except KeyError:
                                        value_type_id = record.type
                                        value = record.value.value
                                    except ValueError:
                                        value_type_id = record.type
                                        value = record.value.value

                                    if cluster_name.startswith("Manufacturer-Specific"):
                                        device_state[str(endpoint.endpoint_id)][cluster_name][attr_name] = {
                                            "type": value_type_id, "value": value,
                                            "id": attr_id}
                                    elif attr_name == "Manufacturer-Specific":
                                        manufacturer_attribute_count += 1
                                        save_name = "Manufacturer-Specific{}".format(manufacturer_attribute_count)
                                        device_state[str(endpoint.endpoint_id)][cluster_name][save_name] = {
                                            "type": value_type_id, "value": value,
                                            "id": attr_id}
                                    else:
                                        device_state[str(endpoint.endpoint_id)][cluster_name][attr_name] = {
                                            "type": value_type_id, "value": value}
                                    # log.info("[RESPONSE] {} Values: {}".format(record_attribute, value))

                                # UNSUPPORTED_ATTRIBUTE, Write Only, other Status
                                else:
                                    failure[attr_name] = record.status
                                    # log.info("[RESPONSE] {} Status: {}".format(record_attribute, record.status))

                    except asyncio.TimeoutError:
                        log.error("[ERROR] Read Attribute Fail! Cluster: {}({}) Attribute: {}"
                                  .format(cluster_name, cluster_id, attr_name))
                        continue
                    except zigpy.exceptions.ParsingError:
                        log.error("[ERROR] Unable to parse response! Cluster: {}({}) Attribute: {}"
                                  .format(cluster_name, cluster_id, attr_name))

        # log.info("[RECORD] [{}] Recording State".format(str(ieee)))
        with open("{}/{}/{}.json".format(self.gateway.state_db, str(ieee), get_struct_time()), "w") as f:
            json.dump(device_state, f, indent=4)

        official_attribute_path = "{}/official_attribute.json".format(self.gateway.attribute_db)
        if not os.path.exists(official_attribute_path):
            attribute_data = {}
        else:
            with open(official_attribute_path, "r", encoding='utf-8') as f2:
                attribute_data = json.load(f2)

        with open(official_attribute_path, "w") as f3:
            # 如果还没有记录Attribute
            if str(ieee) not in attribute_data.keys():
                attribute_data[str(ieee)] = {}
                for cname in device_state.keys():
                    attribute_data[str(ieee)][cname] = list(device_state[cname].keys())

            json.dump(attribute_data, f3, indent=4)

        return device_state

    async def set_state(self, ieee: t.EUI64, state: dict):
        """
        Set the device state
        :param ieee: Device IEEE Address
        :param state: Device State to be set
        :return:
        """
        device = self.gateway.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.gateway.get_support_cluster(ieee, endpoint)

            state_endpoint = state[str(endpoint.endpoint_id)]
            for cluster_name, cluster_state in state_endpoint.items():
                # cluster_id = None
                cluster = None
                if cluster_name.startswith("Manufacturer-Specific"):
                    cluster_id = re.search(r'\d+', cluster_name).group()
                    if cluster_id not in support_cluster["input"]["Unknown"] \
                            or cluster_id not in support_cluster["output"]["Unknown"]:
                        continue
                elif cluster_name in support_cluster["input"].keys():
                    cluster_id = support_cluster["input"][cluster_name]
                    cluster = endpoint.get_cluster(cluster_name)
                elif cluster_name in support_cluster["output"].keys():
                    cluster_id = support_cluster["output"][cluster_name]
                    cluster = endpoint.get_cluster_from_id(cluster_id)
                else:
                    continue

                for attribute_name, attribute_value in cluster_state.items():
                    attr_type = t.uint8_t(attribute_value["type"])
                    attr_value = foundation.DATA_TYPES[attribute_value["type"]][1](attribute_value["value"])

                    if attribute_name.startswith("Manufacturer-Specific") or cluster is None:
                        attr_type = t.uint8_t(attribute_value["type"])
                        attr_id = t.uint16_t(attribute_value["id"])
                    else:
                        attribute_def = cluster.find_attribute(attribute_name)
                        attr_id = attribute_def.id  # t.uint16_t

                    payload = [attr_id, attr_type, attr_value]

                    await self.gateway.send_zcl_general(endpoint, cluster_id, 0x02, payload)

    async def schedule_state_record(self):
        """
        Record the device state in a fixed interval
        :return:
        """
        for ieee, name in ZIGBEE_DEVICE_MAC_MAP.items():
            ieee = t.EUI64.convert(ieee)
            if ieee in self.gateway.application_controller.devices.keys():
                log.info("[RECORD-STATE] [{}] Reading State".format(name))
                state = await self.get_state(ieee)
                if "Status" not in state.keys():
                    log.info("[RECORD-STATE] [{}] Reading State Complete".format(name))

    async def feed_watchdog(self, ieee: t.EUI64, flag: str, next_state: dict = None):
        if flag == "SET":
            if next_state is None:
                log.error("Can't set empty state!")
                return "Fail"
            await self.set_state(ieee, next_state)
            return "Success"
        elif flag == "GET":
            state = await self.get_state(ieee)
            return state
        else:
            log.error("{} not supported!".format(flag))
            raise KeyError

    async def state_feed(self, ieee: t.EUI64, packet):
        device = self.gateway.application_controller.devices[ieee]

        log.info("[State] [{}] Feeding the state to watchdog. Operation: [GET] ".format(device.nwk))
        state = await self.feed_watchdog(ieee, "GET")

        log.info("[State] Calculating next state ··· ")
        next_state = await self.calculate_correlation(state, packet)

        log.info("[State] [{}] Feeding the state to watchdog. Operation: [SET]".format(device.nwk))
        await self.feed_watchdog(ieee, "SET", next_state)

    async def read_attribute_fuzz(self, ieee: t.EUI64):
        device = self.gateway.application_controller.devices[ieee]
        attrid_type = t.uint16_t
        attrid_range = range(45651, attrid_type.max_value + 1)

        log.info("[BRUTE] Fuzzing {}".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.gateway.get_support_cluster(ieee, endpoint)
            interesting_case = await self.gateway.get_interesting_case(ieee, endpoint)

            if support_cluster is None:
                continue

            all_cluster_id = []
            for cluster_name, cluster_id in support_cluster["input"].items():
                if cluster_name == "Unknown":
                    all_cluster_id.extend(cluster_id)
                else:
                    all_cluster_id.append(cluster_id)

            for cid in all_cluster_id:
                interesting_attrid = []
                for attrid in attrid_range:
                    log.info("[BRUTE] CID: {} ATTRID: {}".format(cid, attrid))
                    payload = serialize(attrid, attrid_type)
                    try:
                        result = await self.gateway.request_raw(endpoint, cid, 0x00,
                                                                frame_type=foundation.FrameType.GLOBAL_COMMAND,
                                                                payload_bytes=payload,
                                                                direction=foundation.Direction.Client_to_Server,
                                                                flag=True)
                        for record in result[0]:
                            if record.status == foundation.Status.SUCCESS:
                                try:
                                    value_type_id = record.value.type
                                    value_type = foundation.DATA_TYPES[value_type_id][1]
                                    value = value_type(record.value.value)
                                except KeyError:
                                    value_type_id = record.type
                                    value = record.value.value
                                except ValueError:
                                    value_type_id = record.type
                                    value = record.value.value

                                log.info("[RESPONSE] {} Values: {} Type:{}".format(attrid, value, value_type_id))

                            else:
                                log.info("[RESPONSE] {} Status: {}".format(attrid, record.status))

                    except asyncio.TimeoutError:
                        log.error("[Error] Can't read attribute: {} ! ".format(attrid))
                        interesting_attrid.append(attrid)
                        continue
                    except AttributeError:
                        log.error("[Error] No Status in record! {}")
                        interesting_attrid.append(attrid)
                        continue

                if interesting_attrid:
                    if cid not in interesting_case.keys():
                        interesting_case[cid] = {}
                    interesting_case[cid][0x00] = interesting_attrid

            with open("{}/{}_{}.json".format(self.gateway.case_db, str(ieee), endpoint.endpoint_id), "w") as f:
                json.dump(interesting_case, f, indent=4)

    async def write_attribute_fuzz(self, ieee: t.EUI64, fuzz_type: bool = True):
        fuzz_info_path = "{}/fuzzable.json".format(self.fuzz_info_db)

        if os.path.exists(fuzz_info_path):
            with open(fuzz_info_path, "r") as f:
                all_writable_attr = json.load(f)
        else:
            all_writable_attr = {}

        if "writable" not in all_writable_attr.keys():
            all_writable_attr["writable"] = {}

        if str(ieee) not in all_writable_attr["writable"].keys():
            all_writable_attr["writable"][str(ieee)] = []

        saved_dict = copy.deepcopy(all_writable_attr)
        saved_dict["writable"][str(ieee)] = []

        device = self.gateway.application_controller.devices[ieee]

        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.gateway.get_support_cluster(ieee, endpoint)
            interesting_case = await self.gateway.get_interesting_case(ieee, endpoint)
            support_attribute = await self.gateway.get_support_attribute()

            cluster_attributes = support_attribute[str(ieee)][str(endpoint.endpoint_id)]

            for cluster_name, cluster_value in cluster_attributes.items():
                interesting_payload = []
                interesting_bytes = []

                if cluster_name == "Unknown":
                    cluster_id = None
                elif cluster_name in support_cluster["input"].keys():
                    cluster_id = support_cluster["input"][cluster_name]
                elif cluster_name in support_cluster["output"].keys():
                    cluster_id = support_cluster["output"][cluster_name]
                else:
                    continue

                for attribute in cluster_value:
                    if cluster_name == "Unknown":
                        cluster_id = attribute["cluster_id"]

                    attribute_name = attribute["attr_name"]
                    attribute_id = attribute["attr_id"]
                    attribute_type_id = attribute["attr_type"]
                    attribute_type = foundation.DATA_TYPES[attribute_type_id][1]

                    payload_components = [(attribute_id, t.uint16_t, False), (attribute_type_id, t.uint8_t, fuzz_type),
                                          (0, attribute_type, True)]

                    fuzz_prompt = [Mutator.mutate_value, Mutator.mutate_type, Mutator.mutate_value]

                    all_fuzz_payload, all_fuzz_combination, mutate_list = await Mutator.mutate_payload(
                        payload_components, fuzz_prompt)

                    saved_mutate_value = []
                    saved_mutate_type = []

                    save_info = {"endpoint_id": endpoint.endpoint_id,
                                 "cluster_id": cluster_id,
                                 "cluster_name": cluster_name,
                                 "attribute_id": attribute_id,
                                 "attribute_name": attribute_name,
                                 "attribute_type_id": attribute_type_id,
                                 "attribute_type_name": str(attribute_type)}

                    for fuzz_attr in all_writable_attr["writable"][str(ieee)]:
                        saved_mutate_value = match_dict_item(fuzz_attr, save_info, "mutate_value")
                        saved_mutate_type = match_dict_item(fuzz_attr, save_info, "mutate_type")
                        if not saved_mutate_value:
                            continue
                        break

                    # Whether to fuzz attribute data type?
                    if fuzz_type:
                        save_info["mutate_type"] = list(set(saved_mutate_type) | set(mutate_list[1]))
                    save_info["mutate_value"] = list(set(saved_mutate_value) | set(mutate_list[2]))

                    fuzz_result = []

                    for index, fuzz_payload in enumerate(all_fuzz_payload):
                        if_read_only = False
                        try:
                            log.info("[FUZZ] CID: {} ATTR: {} ATTR TYPE:{} Mutate Value: {}"
                                     .format(cluster_id, all_fuzz_combination[index][0],
                                             all_fuzz_combination[index][1], all_fuzz_combination[index][2]))
                            result = await self.gateway.request_raw(endpoint, cluster_id, 0x02,
                                                                    foundation.FrameType.GLOBAL_COMMAND,
                                                                    payload_bytes=fuzz_payload,
                                                                    direction=foundation.Direction.Client_to_Server,
                                                                    flag=True)
                            if not result:
                                fuzz_result.append("None")
                                continue
                            try:
                                for record in result[0]:
                                    log.info("[RESPONSE] Status: {}".format(record.status))
                                    if record.status in STATUS.keys():
                                        fuzz_result.append(STATUS[record.status])
                                    else:
                                        fuzz_result.append("OTHER")
                                    if record.status == foundation.Status.READ_ONLY:
                                        if_read_only = True
                            except TypeError:
                                log.info("[RESPONSE] Status: {}".format(result.status))
                                if result.status in STATUS.keys():
                                    fuzz_result.append(STATUS[result.status])
                                else:
                                    fuzz_result.append("OTHER")
                                if result.status == foundation.Status.READ_ONLY:
                                    if_read_only = True

                        except asyncio.TimeoutError:
                            interesting_payload.append(all_fuzz_combination[index])
                            interesting_bytes.append(''.join(f'\\x{byte:02x}' for byte in fuzz_payload))

                        # 如果只允许读，则不再fuzz
                        if if_read_only:
                            break

                        # 测试设备是否仍能打开
                        result_on = await self.turn_on_off(ieee, "on")

                        # 如果不能打开，将device enabled位置为1
                        if result_on == "Fail":
                            interesting_payload.append(all_fuzz_combination[index])
                            interesting_bytes.append(''.join(f'\\x{byte:02x}' for byte in fuzz_payload))
                            await self.write_attributes_begin(endpoint.endpoint_id, ieee, cluster_id, 18, 16, 1)

                    if not fuzz_type:
                        save_info["fuzz_value_result"] = fuzz_result
                    else:
                        save_info["fuzz_result"] = fuzz_result
                    saved_dict["writable"][str(ieee)].append(save_info)

                if interesting_payload:
                    if cluster_id not in interesting_case.keys():
                        interesting_case[cluster_id] = {}
                    if 0x02 not in interesting_case[cluster_id].keys():
                        interesting_case[cluster_id][0x02] = {}

                    interesting_case[cluster_id][0x02]["payload"] = interesting_payload
                    interesting_case[cluster_id][0x02]["payload_bytes"] = interesting_bytes

            with open(self.interesting_case_path, "w") as f:
                json.dump(interesting_case, f, indent=4)

        with open("{}/fuzzable.json".format(self.fuzz_info_db), "w") as f:
            json.dump(saved_dict, f, indent=4)

    async def configure_report_fuzz(self, ieee: t.EUI64):
        """
        Configure_Reporting = 0x06
        :param ieee:
        :return:
        """
        device = self.gateway.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            pass
        pass

    async def read_configuration_fuzz(self, ieee: t.EUI64):
        pass

    async def discover_command_fuzz(self, ieee: t.EUI64):
        """
        Discover_Commands_Received = 0x11
        Discover_Commands_Generated = 0x13
        :param ieee:
        :return:
        """
        pass

    async def discover_attribute_fuzz(self, ieee: t.EUI64):
        """
        Fuzzing Discover_Attributes = 0x0C
        Discover_Attribute_Extended = 0x15
        :param ieee:
        :return:
        """
        pass

    async def state_guided_fuzzing(self, ieee: t.EUI64):
        fuzz_count = 0
        with open(os.path.join(self.format_dir, "all_formats(Zigbee).json"), "r") as f:
            message_formats = json.load(f)

        while fuzz_count < self.max_fuzzing_packet:
            fuzz_count += 1

            file_names = ["basic", "strategy-a", "strategy-b", "strategy-c"]

            for filename in file_names:
                file_path = os.path.join(self.fuzzing_dir, f"{filename}.txt")
                if not os.path.exists(file_path):
                    log.error(f"Please run potential state discovery {filename} firstly!")
                    continue

                fuzzing_sequences = read_list_from_file(file_path)

                if filename == "basic":
                    for sequence in fuzzing_sequences:
                        messages = sequence.split(",")
                        for message in messages:
                            msg_format = get_message_format(message, message_formats)
                            if msg_format is None:
                                continue

                            payload_components = [msg_format["schema"]]
                            fuzz_prompt = []

                            mutation_strategy = Mutator.mutate_value

                            for i in range(count_leaf_values(msg_format["schema"])):
                                fuzz_prompt.append(mutation_strategy)

                            all_fuzz_payload, all_fuzz_combination, mutate_list = await Mutator.mutate_payload(
                                payload_components, fuzz_prompt)

                            for fuzz_payload in all_fuzz_payload:
                                try:
                                    result = await self.gateway.request_raw(1, cluster_id, msg_format["id"],
                                                                            foundation.FrameType.GLOBAL_COMMAND,
                                                                            payload_bytes=fuzz_payload,
                                                                            direction=foundation.Direction.Client_to_Server,
                                                                            flag=True)
                                except asyncio.TimeoutError:
                                    crash_info = self.crash_prompt.copy()
                                    now = datetime.now()
                                    crash_info["TimeStamp"].append(
                                        now.strftime("%Y%m%d_%H:%M:%S:") + f"{int(now.microsecond / 1000):03d}")
                                    crash_info["IEEE"].append(str(ieee))
                                    crash_info["DEVICE"].append(ZIGBEE_DEVICE_MAC_MAP[str(ieee)])
                                    crash_info["State"].append("Any")
                                    crash_info["Fuzzing_Messages"].append(fuzz_payload)
                                    crash_info["Mutation_Strategy"].append(mutation_strategy)

                            fuzz_prompt = []
                            mutation_strategy = Mutator.mutate_type

                            for i in range(count_leaf_values(msg_format["schema"])):
                                fuzz_prompt.append(mutation_strategy)

                            all_fuzz_payload, all_fuzz_combination, mutate_list = await Mutator.mutate_payload(
                                payload_components, fuzz_prompt)

                            for fuzz_payload in all_fuzz_payload:
                                try:
                                    result = await self.gateway.request_raw(1, cluster_id, msg_format["id"],
                                                                            foundation.FrameType.GLOBAL_COMMAND,
                                                                            payload_bytes=fuzz_payload,
                                                                            direction=foundation.Direction.Client_to_Server,
                                                                            flag=True)
                                except asyncio.TimeoutError:
                                    crash_info = self.crash_prompt.copy()
                                    now = datetime.now()
                                    crash_info["TimeStamp"].append(
                                        now.strftime("%Y%m%d_%H:%M:%S:") + f"{int(now.microsecond / 1000):03d}")
                                    crash_info["IEEE"].append(str(ieee))
                                    crash_info["DEVICE"].append(ZIGBEE_DEVICE_MAC_MAP[str(ieee)])
                                    crash_info["State"].append("Any")
                                    crash_info["Fuzzing_Messages"].append(fuzz_payload)
                                    crash_info["Mutation_Strategy"].append(mutation_strategy)

                else:
                    for sequence in fuzzing_sequences:
                        messages = sequence.split(",")
                        payload_components = []
                        for message in messages:
                            msg_format = get_message_format(message, message_formats)
                            if msg_format is None:
                                continue

                        payload_components.append([msg_format["schema"]])
                        fuzz_prompt = []

                        mutation_strategy = Mutator.mutate_value

                        for i in range(count_leaf_values(msg_format["schema"])):
                            fuzz_prompt.append(mutation_strategy)

                        all_fuzz_payload, all_fuzz_combination, mutate_list = await Mutator.mutate_payload(
                            payload_components, fuzz_prompt)

                        for fuzz_payload in all_fuzz_payload:
                            try:
                                result = await self.gateway.request_raw(1, cluster_id, msg_format["id"],
                                                                        foundation.FrameType.GLOBAL_COMMAND,
                                                                        payload_bytes=fuzz_payload,
                                                                        direction=foundation.Direction.Client_to_Server,
                                                                        flag=True)
                            except asyncio.TimeoutError:
                                crash_info = self.crash_prompt.copy()
                                now = datetime.now()
                                crash_info["TimeStamp"].append(
                                    now.strftime("%Y%m%d_%H:%M:%S:") + f"{int(now.microsecond / 1000):03d}")
                                crash_info["IEEE"].append(str(ieee))
                                crash_info["DEVICE"].append(ZIGBEE_DEVICE_MAC_MAP[str(ieee)])
                                crash_info["State"].append("Any")
                                crash_info["Fuzzing_Messages"].append(fuzz_payload)
                                crash_info["Mutation_Strategy"].append(mutation_strategy)

                        fuzz_prompt = []
                        mutation_strategy = Mutator.mutate_type

                        for i in range(count_leaf_values(msg_format["schema"])):
                            fuzz_prompt.append(mutation_strategy)

                        all_fuzz_payload, all_fuzz_combination, mutate_list = await Mutator.mutate_payload(
                            payload_components, fuzz_prompt)

                        for fuzz_payload in all_fuzz_payload:
                            try:
                                await self.state_feed(messages)
                                result = await self.gateway.request_raw(1, cluster_id, msg_format["id"],
                                                                        foundation.FrameType.GLOBAL_COMMAND,
                                                                        payload_bytes=fuzz_payload,
                                                                        direction=foundation.Direction.Client_to_Server,
                                                                        flag=True)
                            except asyncio.TimeoutError:
                                crash_info = self.crash_prompt.copy()
                                now = datetime.now()
                                crash_info["TimeStamp"].append(
                                    now.strftime("%Y%m%d_%H:%M:%S:") + f"{int(now.microsecond / 1000):03d}")
                                crash_info["IEEE"].append(str(ieee))
                                crash_info["DEVICE"].append(ZIGBEE_DEVICE_MAC_MAP[str(ieee)])
                                crash_info["State"].append("Any")
                                crash_info["Fuzzing_Messages"].append(fuzz_payload)
                                crash_info["Mutation_Strategy"].append(mutation_strategy)


            # Step 1: Using the last packet and current state to get the next fuzzing state
            await self.state_feed(ieee)
            # Step 1: Calculate the
            log.info("[+] Sending the mutated packet {} for [{}]".format(fuzz_count, ieee))
            # self.mutation(nwk ,ieee)
            await asyncio.sleep(10)

    async def set_recent_state(self, ieee: t.EUI64):
        state_dict = os.path.join(self.gateway.state_db, str(ieee))
        state_file = os.path.join(state_dict, get_latest_file(state_dict))

        with open(state_file, "r", encoding='utf-8') as f:
            state = json.load(f)

        log.info("[STATE] [{}] Setting State".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
        await self.feed_watchdog(ieee, "SET", state)
        log.info("[STATE] [{}] Setting Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

    async def turn_on_off(self, ieee: t.EUI64, command: str):
        """
        Turn on/off the device for checking crashes and abnormal states
        :param command: On / Off
        :param ieee:
        :return:
        """
        command_id = 0x00 if command.lower() == "off" else 0x01

        device = self.gateway.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            support_cluster_path = "{}/{}_{}.json".format(self.gateway.cluster_db,
                                                          str(ieee), endpoint.endpoint_id)
            if not os.path.exists(support_cluster_path):
                print(support_cluster_path)
                continue

            with open(support_cluster_path, "r", encoding='utf-8') as f:
                support_cluster = json.load(f)
                all_cluster_id = support_cluster["input"].values()
                if 0x0006 not in all_cluster_id:
                    # log.error("Device Endpoint{} doesn't have OnOff Cluster".format(endpoint))
                    return

                log.info("[CLUSTER_CMD] {} {}".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], command))

                try:
                    result = await self.gateway.request_raw(endpoint, 0x0006, command_id,
                                                            frame_type=foundation.FrameType.CLUSTER_COMMAND,
                                                            payload_bytes=b'',
                                                            direction=foundation.Direction.Client_to_Server)
                    log.info("[CLUSTER_CMD] {}".format(result))
                    return "Success"
                except asyncio.exceptions.TimeoutError:
                    log.error("[CLUSTER_CMD] {} {} Failed!".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], command))
                    return "Fail"

    async def write_attributes_begin(self, endpoint_id: int, ieee: t.EUI64, cluster_id: int, attr_id: int,
                                     attr_type: int, value):
        device = self.gateway.application_controller.devices[ieee]
        attr_type_spec = foundation.DATA_TYPES[attr_type][1]
        payload_bytes = b''

        if type(value) == str:
            if attr_type_spec not in ZIGBEE_STR_TYPE:
                log.error("[ERROR] Data Type and Value Not Matched!")
        if type(value) == int:
            if attr_type_spec not in ZIGBEE_INTEGER_TYPE:
                log.error("[ERROR] Data Type and Value Not Matched!")

        payload_bytes += serialize(attr_id, t.uint16_t)
        payload_bytes += serialize(attr_type, t.uint8_t)
        payload_bytes += serialize(value, attr_type_spec)

        for endpoint in device.non_zdo_endpoints:
            if endpoint.endpoint_id != endpoint_id:
                continue
            result = await self.gateway.request_raw(endpoint, cluster_id, 0x02, foundation.FrameType.GLOBAL_COMMAND,
                                                    payload_bytes=payload_bytes,
                                                    direction=foundation.Direction.Client_to_Server)
            for record in result[0]:
                log.info("[RESPONSE] Status: {}".format(record.status))

    async def run(self):
        # Initialize gateway and start the zigbee network
        await self.gateway.run()

        log.info(
            "*********************************[ZVDetector] State-Guided Fuzzer *********************************")

        while True:
            debug_flag = False
            fuzz_flag = False
            # poc_flag = True

            while True:
                # if counter % 5 == 0:
                #     await self.schedule_state_record()

                flag = input_with_timeout("Operation:\n", 7, "")

                ieee = None

                if flag == "debug":
                    debug_flag = True
                    break

                if flag == "fuzz":
                    fuzz_flag = True

                    log.info(
                        "*********************************[State-Guided Fuzzer] Begin *********************************")
                #
                # if flag == "poc":
                #     poc_flag = True
                #     break

            if fuzz_flag:
                for ieee in self.gateway.application_controller.devices.keys():
                    await self.state_guided_fuzzing(ieee)

            #  Fuzzer support debug mode for developer applied to other applications
            if debug_flag:
                while True:
                    flag = input_with_timeout("Please input debug operation:\n", 7, "")

                    if flag == "help":
                        print("Supported operations:\n"
                              "get: Get certain device state\n"
                              "set: Set certain device state\n"
                              "write: Write certain device attribute"
                              "on/off: Turn on/off the device\n"
                              "read_fuzz: Using ReadAttributes fuzzing mode(only for single protocol message)\n"
                              "write_fuzz: Using WriteAttributes fuzzing mode(only for single protocol message")
                        continue
                    else:
                        device_name = input_with_timeout("Device:\n", 10, "")
                        if device_name == "":
                            log.error("Please input device name for further debugging!")
                            continue
                        ieee, device = await self.gateway.find_similar_device(device_name)
                        if ieee not in self.gateway.application_controller.devices.keys() or ieee == self.gateway.coordinator_ieee:
                            log.error("Device not connected to coordinator or cannot fuzz coordinator itself!")
                            continue

                    if flag == "get":
                        log.info("[STATE] [{}] Reading State".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
                        state = await self.get_state(ieee)
                        if "Status" not in state.keys():
                            log.info("[OUTPUT] [{}] State: {}".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], state))

                    if flag == "set":
                        await self.set_recent_state(ieee)

                    if flag == "on" or flag == "off":
                        await self.turn_on_off(ieee, flag)

                    if flag == "read_fuzz":
                        await self.read_attribute_fuzz(ieee)

                    if flag == "write_fuzz":
                        await self.write_attribute_fuzz(ieee, fuzz_type=False)

                    if flag == "write":
                        cluster_name = input_with_timeout("Cluster:\n", 10, "")
                        if cluster_name == "":
                            continue

                        attr_name = input_with_timeout("Attr Name:\n", 10, "")
                        if attr_name == "":
                            continue

                        attr_value = input_with_timeout("Attr Value:\n", 10, "")
                        if attr_value == "":
                            continue

                        try:
                            attr_value = int(attr_value)
                        except ValueError:
                            pass

                        attribute_save_path = os.path.join(self.gateway.attribute_db, "support_attribute.json")
                        if not os.path.exists(attribute_save_path):
                            log.error("[ERROR] Support Attribute Json Not Found")

                        with open(attribute_save_path, "r") as f:
                            all_attr = json.load(f)

                        for endpoint_id in all_attr[str(ieee)].keys():
                            cluster_save_path = os.path.join(self.gateway.cluster_db,
                                                             "{}_{}.json".format(str(ieee), endpoint_id))
                            with open(cluster_save_path, "r") as f2:
                                all_clusters = json.load(f2)

                            all_cluster = all_attr[str(ieee)][endpoint_id].keys()
                            if cluster_name not in all_cluster:
                                continue
                            cluster_attr = all_attr[str(ieee)][endpoint_id][cluster_name]

                            cluster_id = all_clusters["input"][cluster_name]

                            for attr in cluster_attr:
                                if attr["attr_name"] == attr_name:
                                    attr_id = attr["attr_id"]
                                    attr_type = attr["attr_type"]
                                    log.info("Writing {} at {}".format(attr_name, attr_value))
                                    await self.write_attributes_begin(int(endpoint_id), ieee, cluster_id, attr_id,
                                                                      attr_type,
                                                                      attr_value)

                    if flag == "quit" or flag == "break":
                        break


if __name__ == "__main__":
    args = parse_args(sys.argv[1:], "Preparing the environment")
    fuzzer = StateFuzzer(args)
    asyncio.run(fuzzer.run())
