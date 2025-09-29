import itertools
import os
import random
import sys

sys.path.append(os.path.dirname(os.getcwd()))

import re
import copy
import json
import time
import logging
import asyncio
import warnings
from datetime import datetime

import zigpy.device
from zigpy.zcl import foundation
import zigpy.endpoint
from zigpy.application import ControllerApplication
from util.logger import get_logger
from util.serial import serialize
import zigpy.zcl
import zigpy.types as t

from util.utils import *
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from state_fuzzing.gateway import ZHAGateway, parse_args
from state_aware.type import *
from state_aware.const import *

# python fuzzer.py -c 20 -d 15 -l -o network.json /dev/tty.usbserial-14410
# python fuzzer.py -c 20 -d 15 -l -o network.json /dev/ttyUSB0

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
warnings.filterwarnings("ignore")

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
    def mutate_type_value(cls, types: typing.Any) -> (list, str):
        """
        According to different types, generate some mutate values
        :param types: zigbee type
        :return: mutate value list
        """
        mutate_value = []
        mutate_strategy = ""

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
            mutate_strategy = "T-1-1"

        elif types in ZIGBEE_STR_TYPE:
            max_length = ZIGBEE_STR_MAX_LENGTH[types]
            mutate_value.append("Normal")
            mutate_value.append("")
            mutate_value.append("\x7FGroup" * max_length)
            mutate_value.append("!@" + "#$%^&*!@" * (max_length + 1))
            mutate_value.append("!@#$%^&*" * (max_length + 2))
            mutate_strategy = "T-1-2"

        elif types in ZIGBEE_DATA_TYPE:
            length = types.get_length()
            item_type = types.get_itemtype()

            # [1, -1], [
            for index in range(length):
                mv, ms = Mutator.mutate_type_value(item_type)
                mutate_value.append(mv)
                mutate_strategy = mutate_strategy + ms + ","

            mutate_value.append("empty array")
            mutate_strategy += "T-1-3"

        else:
            log.error(f"Other types are mutated during process")
            return None, None

        return mutate_value, mutate_strategy

    @classmethod
    def mutate_type(cls, types: typing.Any):
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

        Example: payload_components = [(attribute_id, t.uint16_t, False),
                                       (attribute_type_id, t.uint8_t, fuzz_type),
                                       (0, attribute_type, True)]

        fuzz_prompt = [Mutator.mutate_value, Mutator.mutate_type, Mutator.mutate_value]
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

    @classmethod
    async def type_aware_mutation(cls, parsed_format: list) -> (list, list):
        """
        According to parsed format, mutate each fields and return possible test cases combinations
        """
        raw_test_cases = []
        mutation_strategies = []

        for field1 in parsed_format:
            if type(field1) is list:

                ca, ma = await cls.type_aware_mutation(field1)  # [[], []]
                ca.append("empty array")  # T-1-3 Mutation Strategy

                raw_test_cases.append(ca)
                mutation_strategies.extend(ma)
                mutation_strategies.append("T-1-3")

                continue

            elif field1 == 't.any':
                raw_test_cases.append([0, -1, "", "t.any"])
                mutation_strategies.append("T-1-4")
                continue

            else:
                cases, mutation_strategy = Mutator.mutate_type_value(field1)
                if cases is None:
                    log.error(f"{field1}")
                    continue
                cases.append(field1)
                raw_test_cases.append(cases)
                mutation_strategies.append(mutation_strategy)

        return raw_test_cases, mutation_strategies


def has_nested_list(lst):
    return any(isinstance(item, list) for item in lst)


def count_positions(node):
    """
    CN: 统计最小列表和每个 'empty array' 的总数
    EN: Count the total number of the minimum list and each 'empty array'
    """
    if has_nested_list(node):
        s = 1
        for child in node:
            if child != "empty array":
                s += count_positions(child)
        return s
    elif isinstance(node, list):
        return 1
    else:
        return 0


def get_message_format(msg_name: str, all_messages: dict):
    for layer, layer_cmds in all_messages.items():
        for command, command_format in layer_cmds.items():
            if command == msg_name:
                return command_format
    return None


class StateFuzzer:
    def __init__(self, config):
        self.zcl_cluster_messages = None
        self.zdp_cmd_formats = None
        self.aps_cmd_formats = None
        self.nwk_cmd_formats = None
        self.zcl_cluster_formats = None
        self.zcl_general_formats = None
        self.gateway = ZHAGateway(config)
        self.state_guided = args.load_state
        self.max_fuzzing_packet = 1000000
        self.max_iter_packet = 30000
        self.fuzz_info_db = os.path.join(os.getcwd(), "log")
        self.interesting_case_path = os.path.join(os.getcwd(), "interesting_case")
        self.crash_db_path = os.path.join(os.getcwd(), "crash/json")
        self.fuzzing_dir = os.path.join(os.path.dirname(__file__), "state_aware/result/fuzzing")
        self.format_dir = os.path.join(os.path.dirname(__file__), "state_aware/result/format")
        self.cluster_dir = os.path.join(os.path.dirname(__file__), "state_aware/result/cluster")
        self.library_dir = os.path.join(os.path.dirname(__file__), "library")
        self.fuzz_log_dir = os.path.join(os.path.dirname(__file__), "fuzz.log")
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
        self.layer_messages = {}
        self.phase = "Test case generation"

    def initialize(self):
        with open(os.path.join(self.format_dir, "ZCL/format(ZCL_General).json"), "r") as f1:
            self.zcl_general_formats = json.load(f1)

        with open(os.path.join(self.format_dir, "ZCL/format(ZCL_Command).json"), "r") as f2:
            self.zcl_cluster_formats = json.load(f2)

        with open(os.path.join(self.format_dir, "NWK/format(NWK_Command).json"), "r") as f3:
            self.nwk_cmd_formats = json.load(f3)

        with open(os.path.join(self.format_dir, "APS/format(APS_Command).json"), "r") as f4:
            self.aps_cmd_formats = json.load(f4)

        with open(os.path.join(self.format_dir, "ZDP/format(ZDP_Command).json"), "r") as f5:
            self.zdp_cmd_formats = json.load(f5)

        self.layer_messages["ZCL_General"] = self.zcl_general_formats.keys()
        self.layer_messages["NWK_Command"] = self.nwk_cmd_formats.keys()
        self.layer_messages["ZDP_Command"] = self.zdp_cmd_formats.keys()
        self.layer_messages["APS_Command"] = self.aps_cmd_formats.keys()

        zcl_messages = []
        zcl_cluster_messages = {}

        for cluster, cluster_formats in self.zcl_cluster_formats.items():
            if cluster not in zcl_cluster_messages.keys():
                zcl_cluster_messages[cluster] = []

            for cmd_type, cluster_cmd_format in cluster_formats.items():
                for cmd_name, cmd_format in cluster_cmd_format.items():
                    zcl_messages.append(cmd_name)
                    zcl_cluster_messages[cluster].append({cmd_name: cmd_format})

        self.layer_messages["ZCL_Command"] = zcl_messages
        self.zcl_cluster_messages = zcl_cluster_messages

    def write_fuzz_log(self, msg):
        with open(self.fuzz_log_dir, "a") as f:
            f.write(f"[Fuzzer] {msg} \n")

    def check_message_layer(self, msg_name):
        """
        EN: Check certain message belongs to which layer?
        CN: 检查消息是属于哪个layer

        :param msg_name: message name
        :return: command layer that message belongs to
        """
        if not self.layer_messages:
            log.error("[Error] Message formats have not been extracted!")

        for layer, layer_cmds in self.layer_messages.items():
            if msg_name in layer_cmds:
                return layer

        return None

    def check_message_cluster(self, msg_name):
        """
        EN: Check which cluster that message belongs to.
        CN: 检查消息是属于哪个cluster

        :param msg_name: message name
        :return: cluster that message belongs to and corresponding cluster id
        """

        with open(os.path.join(self.cluster_dir, "cluster_id.json"), "r") as f:
            cluster_id = json.load(f)

        for cluster, cluster_cmds in self.zcl_cluster_messages:
            if msg_name in cluster_cmds.keys():
                cid = int(cluster_id[cluster], 16)
                return cluster, cid

        return None, None

    def acquire_support_clusters(self, ieee: t.EUI64) -> dict:

        """
        # CN: 获取该设备支持的endpoint，以及每个endpoint支持的cluster
        # EN: Get the endpoints supported by the device and the clusters supported by each endpoint
        """

        all_support_clusters = {}

        support_cluster_db = os.path.join(self.library_dir, f"cluster_db")
        ieee_str = str(ieee).replace(":", "_")

        support_clusters_files = find_files_with_prefix(support_cluster_db, ieee_str)

        for support_clusters_file in support_clusters_files:
            cluster_file_name = get_filename_from_filepath(support_clusters_file)

            ieee_endpoint = cluster_file_name.split("_")[-1]

            if ieee_endpoint not in all_support_clusters.keys():
                all_support_clusters[ieee_endpoint] = []

            with open(support_clusters_file, "r") as f:
                endpoint_support_clusters = json.load(f)

            for cluster_type, support_clusters in endpoint_support_clusters.items():
                for cluster, cid in support_clusters.items():
                    if cluster == "Unknown":
                        all_support_clusters[ieee_endpoint].extend(cid)
                    else:
                        all_support_clusters[ieee_endpoint].append(cid)

        return all_support_clusters

    def check_endpoint_support(self, ieee: t.EUI64, endpoint_id: int):
        """
        EN: Determine whether a supported endpoint of the device is correctly identified by the coordinator
        CN: 判断设备的某个supported endpoint是否被coordinator正确识别
        """
        device = self.gateway.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            if endpoint.endpoint_id == endpoint_id:
                return True, endpoint

        return False, None

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

                    fuzz_prompt = [Mutator.mutate_type_value, Mutator.mutate_type, Mutator.mutate_type_value]

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

    def parse_message_formats(self, msg_format: dict):
        """
            基于字段类型的消息格式拆解
        """
        result = []
        reflect_result = []

        for k, v in msg_format.items():
            if k in EXCEPT_MUTATION_FIELDS:
                continue

            if isinstance(k, str) and k.startswith("t."):
                if k == "t.LVList":
                    result.append(self.parse_message_formats(v)[0])
                    reflect_result.append(self.parse_message_formats(v)[1])
                    continue

                elif k == "t.List":
                    result.append([v])
                    if v not in ZIGBEE_ALL_TYPE_MAP.keys():
                        reflect_result.append(None)

                    reflect_result.append([ZIGBEE_ALL_TYPE_MAP[v]])
                    continue

                if isinstance(v, list):
                    result.append(k)
                    if k not in ZIGBEE_ALL_TYPE_MAP.keys():
                        reflect_result.append(None)

                    reflect_result.append(ZIGBEE_ALL_TYPE_MAP[k])
                    continue

            if isinstance(v, str) and (v.startswith("t.") or v.startswith("foundation.")):
                result.append(v)
                reflect_result.append(ZIGBEE_ALL_TYPE_MAP[v])
                continue

            if isinstance(v, dict):
                result.extend(self.parse_message_formats(v)[0])
                reflect_result.extend(self.parse_message_formats(v)[1])

        return result, reflect_result

    async def payload_bytes_serialization_singlepoint(self, raw_test_cases: list, strategies: list):
        """
        EN: Only one field in raw_test_cases is mutated, and the other fields remain fixed.
        CN: 仅针对 raw_test_cases 中一个消息字段进行变异，其它字段固定。

        - raw_test_cases: 嵌套字段结构  nested field structure of a message
        - strategies: 与 raw_test_cases 中【最小列表 + 每个 'empty array'】一一对应
        返回值: [(bytes, [策略])]
        """

        idx = 0  # Global index，correspond to strategies
        results = []  # [(payload_bytes, [strategy])]

        self.phase = "Mutation-Singlepoint"

        total_positions = count_positions(raw_test_cases)

        # ---------- 递归生成函数 ----------
        async def recursion(node, target_pos, mutated=False):
            """
            node: 当前节点
            target_pos: 需要变异的那个全局位置索引
            mutated:   是否已经在上层完成了变异
            return: [(bytes, [策略])]
            """
            nonlocal idx

            # 1. 如果是嵌套List结构，则判断是否为Array, 并且应用 empty array策略
            if has_nested_list(node):
                # 如果这层 Array 对应的 'empty array' 是目标
                if idx == target_pos and node[-1] == "empty array":
                    cur_strategy = strategies[idx]
                    idx += 1
                    # 选择空数组策略 => 直接返回空字节，并记录策略
                    return [(b"", [cur_strategy])]
                else:
                    # 正常路径：组合子节点
                    child_results = []
                    for child in node:
                        if child == "empty array":
                            continue
                        child_results.append(await recursion(child, target_pos, mutated))

                    # 处理 empty array 的占位，但这里不选它，只前进索引，跳过该层的 'empty array' 策略
                    if node[-1] == "empty array":
                        idx += 1

                    combined = list(itertools.product(*child_results))

                    non_empty_results = []

                    for combo in combined:
                        bytes_part = b"".join(b[0] for b in combo)
                        strategy_part = sum((s[1] for s in combo), [])
                        non_empty_results.append((bytes_part, strategy_part))

                    return non_empty_results

            # 2. 最小字段: 则根据是否为变异位置，选择组合变异列表还是组合初始化值列表
            if isinstance(node, list):
                cur_strategy = strategies[idx]
                cur_idx = idx
                idx += 1
                data_type = node[-1]

                # ✅ 这个字段是目标：每个变异值都输出一次
                if cur_idx == target_pos:
                    if data_type == "t.any":
                        vals = [serialize(v, t.CharacterString) if isinstance(v, str)
                                else serialize(v, t.int16s)
                                for v in node[:-1]]
                    else:
                        vals = [serialize(v, data_type) for v in node[:-1]]
                    return [(bts, [cur_strategy]) for bts in vals]

                # ❎ 这个字段不是目标，分配初始化值列表，每个初始值都输出一次
                else:
                    # 非目标字段：固定值列表由 distribute 提供
                    fixed = distribute(data_type)
                    if data_type != "t.any":
                        return [(serialize(v, data_type), []) for v in fixed]
                    else:
                        result = []
                        for fixed_value in fixed[:-1]:
                            result.append((serialize(fixed_value, t.int16s), []))
                        result.append((serialize(fixed[-1], t.CharacterString), []))
            return []

        # ---------- Single Point Mutation ----------
        for target in range(total_positions):
            idx = 0
            for payload, strat in await recursion(raw_test_cases, target_pos=target):
                results.append((payload, strat))

        return results

    async def payload_bytes_serialization_multipoint(self, raw_test_cases: list, strategies: list):
        """
        EN: According to raw test cases, generate mutated bytes stream: mutate multipoint togather
        CN: 根据 raw_test_cases 生成所有可能的字节流和变异策略(payload_bytes, fuzz_strategy)组合，多点变异字节流组合，支持多层 Array 的 'empty array' 策略。

        - raw_test_cases: 嵌套的字段取值
        Example: [[[32767, 65535, 0, 65536, -1, -65534, -65535, -65536, 4294967296, -4294967296, <class 'zigpy.types.basic.uint16_t'>],
                [127, 255, 0, 256, -1, -254, -255, -256, 65536, -65536, <enum 'enum8'>],
                [[127, 255, 0, 256, -1, -254, -255, -256, 65536, -65536, <class 'zigpy.types.basic.uint8_t'>],
                [0, -1, '', 't.any'], 'empty array'], 'empty array']]

        - strategies: 与 raw_test_cases 中最小列表一一对应的策略，'empty array' 对应 'T-1-3'
        Example: ['T-1-1', 'T-1-1', 'T-1-1', 'T-1-4', 'T-1-3', 'T-1-3']

        Return: [(bytes, [策略1, 策略2, ...]), ...]
        """

        idx = 0  # 用于读取 strategies 中的策略
        self.phase = "Mutation-Multipoint"

        async def recursion(node) -> list:
            nonlocal idx
            results = []

            # 1. 嵌套 Array: 如果还有嵌套的列表，意味着存在Array这种数据结构
            if has_nested_list(node):

                # 先递归处理所有子字段
                sub_results = []
                for child in node:
                    # 'empty array' 标识在这里不递归，而是通过下面empty策略
                    if child == 'empty array':
                        continue
                    sub_results.append(await recursion(child))

                # 组合子字段的非空取值
                non_empty_results = []

                if sub_results:
                    combined = list(itertools.product(*sub_results))
                    for combo in combined:
                        bytes_part = b"".join(b[0] for b in combo)
                        strategy_part = sum((s[1] for s in combo), [])
                        non_empty_results.append((bytes_part, strategy_part))

                # empty array 策略：仅使用 'T-1-3'
                empty_strategy = strategies[idx]
                idx += 1

                empty_results = [(b'', [empty_strategy])]

                results = non_empty_results + empty_results
                return results

            # 2. 最小列表字段, 表示该字段根据其数据类型变异的取值列表
            if isinstance(node, list):
                cur_strategy = strategies[idx]
                idx += 1

                # "t.any"数据类型的消息字段，分析所有可能的变异字节流 [0, -1, '', 't.any'] -> [b'', b'', b'']
                if node[-1] == "t.any":
                    mutated_bytes = []
                    for v in node[:-1]:
                        if isinstance(v, str):
                            mutated_bytes.append(serialize(v, t.CharacterString))
                        else:
                            mutated_bytes.append(serialize(v, t.int16s))

                # 具体数据类型data_type的消息字段，分析所有可能的变异字节流
                else:
                    data_type = node[-1]
                    mutated_bytes = [serialize(v, data_type) for v in node[:-1]]

                # 每个值都携带当前字段策略
                results = [(v, [cur_strategy]) for v in mutated_bytes]
                return results

            return []

        all_mutated = await recursion(raw_test_cases[0])
        return all_mutated
    
    async def state_guided_fuzzing(self, ieee: t.EUI64):
        fuzz_count = 0

        # CN: 获取所有Zigbee的消息格式, 五个不同层次  EN: Acquire Zigbee formats across five different layers

        with open(os.path.join(self.format_dir, "all_formats(Zigbee).json"), "r") as f:
            all_message_formats = json.load(f)

        # 获取ieee支持的endpoint，以及每个endpoint下支持的clusters
        support_endpoint_and_clusters = self.acquire_support_clusters(ieee)

        all_support_clusters = []
        for endpoint_support_cluster_ids in support_endpoint_and_clusters.values():
            all_support_clusters.extend(endpoint_support_cluster_ids)

        while fuzz_count < self.max_fuzzing_packet:
            fuzz_count += 1

            file_names = ["basic", "strategy-a", "strategy-b", "strategy-c"]

            for filename in file_names:
                file_path = os.path.join(self.fuzzing_dir, f"{filename}.txt")
                if not os.path.exists(file_path):
                    log.error(f"Please run potential state discovery {filename} firstly!")
                    continue

                fuzzing_sequences = read_list_from_file(file_path)

                # 1. 基本策略: 针对每条消息进行fuzzing

                if filename == "basic":
                    log.info("[Fuzzer] Applying basic fuzzing strategy ...")

                    for sequence in fuzzing_sequences:

                        # 待Fuzzing的消息序列中都是消息名字
                        messages = sequence.split(",")

                        # 定义六个组成消息的参数列表 和 用到的模糊策略
                        parameter_prompt = {
                            "endpoint": [],
                            "clusterID": [],
                            "commandID": [],
                            "frame_type": [],
                            "payload": [],
                            "direction": [],
                            "strategy": [],
                            "fuzz": False
                        }

                        for fuzz_msg_position in range(len(messages)):

                            fuzz_parameters = {}

                            for index, message in enumerate(messages):

                                msg_format = get_message_format(message, all_message_formats)  # 获取消息格式

                                if msg_format is None:
                                    continue

                                msg_layer = self.check_message_layer(message)  # 获取消息所属的层次

                                if msg_layer is None:
                                    continue

                                cluster_supported = False  # 确定该消息所属的cluster是否被设备所支持
                                endpoint = None  # 用于发送消息的endpoint
                                msg_cluster_id = None  # 消息所属的cluster对应的id

                                # 如果消息是ZCL cluster Command, 需要找到对应的endpoint 和 message对应的cluster
                                if msg_layer == "ZCL_Command":

                                    # 如果是ZCL cluster command, 就需要找到command对应的 cluster 和 cluster id
                                    msg_cluster, msg_cluster_id = self.check_message_cluster(message)

                                    if msg_cluster is None:
                                        continue

                                    # 找到哪个endpoint中有包含这个cluster
                                    # 如果有，则返回对应的endpoint
                                    # 如果没有，则使用第一个endpoint来尝试T-2-3: Unsupported策略

                                    for endpoint_id in support_endpoint_and_clusters.keys():
                                        if msg_cluster_id not in support_endpoint_and_clusters[endpoint_id]:
                                            continue

                                        endpoint_added, endpoint = self.check_endpoint_support(ieee,
                                                                                               endpoint_id)
                                        if not endpoint_added:
                                            continue
                                        else:
                                            cluster_supported = True
                                            break

                                    if not cluster_supported:
                                        # Apply strategy T-2-3
                                        endpoint = self.gateway.application_controller.devices[ieee].non_zdo_endpoints[0]

                                # request_raw 第六个参数: 消息的方向
                                if "direction_header" not in msg_format.keys():
                                    msg_direction = foundation.Direction.Client_to_Server
                                else:
                                    msg_direction = msg_format["direction_header"]

                                # ———————————————————————— 消息序列中该消息如果是需要fuzz的消息，则进行变异操作 ————————————————————————
                                if index == fuzz_msg_position:

                                    fuzz_parameters[index] = copy.deepcopy(parameter_prompt)
                                    fuzz_parameters[index]["fuzz"] = True

                                    _, parsed_format = self.parse_message_formats(msg_format)

                                    raw_test_cases, mutation_strategies = Mutator.type_aware_mutation(parsed_format)

                                    log.info(f"[Fuzzer] Single-field mutating for message {message}")
                                    mutated_payload_bytes = await self.payload_bytes_serialization_multipoint(raw_test_cases,
                                                                                                              mutation_strategies)

                                    fuzz_parameters[index]["commandID"].extend([msg_format["id"]] * len(mutated_payload_bytes))
                                    fuzz_parameters[index]["direction"].extend([msg_direction] * len(mutated_payload_bytes))

                                    if msg_layer == "ZCL_Command":
                                        fuzz_parameters[index]["endpoint"].extend([endpoint] * len(mutated_payload_bytes))
                                        fuzz_parameters[index]["clusterID"].extend([msg_cluster_id] * len(mutated_payload_bytes))
                                        fuzz_parameters[index]["frame_type"].extend([foundation.FrameType.CLUSTER_COMMAND] * len(mutated_payload_bytes))

                                        for mutated_case in mutated_payload_bytes:
                                            fuzz_parameters[index]["payload"].append(mutated_case[0])
                                            if cluster_supported:
                                                fuzz_parameters[index]["strategy"].append(mutated_case[1])
                                            else:
                                                fuzz_parameters[index]["strategy"].append(mutated_case[1] + ["T-2-3"])

                                    elif msg_layer == "ZCL_General":
                                        # 如果是ZCL general command, 就需要需要和各种cluster组合

                                        with open(os.path.join(self.cluster_dir, "cluster_id.json"), "r") as f:
                                            all_clusters = json.load(f)

                                        # 尝试各个cluster和ZCL general command的组合
                                        for cluster_id in all_clusters.values():
                                            cluster_id = int(cluster_id, 16)

                                            # 如果 cluster是被设备所支持，则探索对应的endpoint
                                            if cluster_id in all_support_clusters:

                                                for endpoint_id in support_endpoint_and_clusters.keys():
                                                    if cluster_id in support_endpoint_and_clusters[endpoint_id]:
                                                        endpoint_added, endpoint = self.check_endpoint_support(ieee, endpoint_id)

                                                        if endpoint_added:
                                                            cluster_supported = True
                                                            break
                                                        else:
                                                            continue

                                            # 否则，设置为第一个endpoint
                                            if not cluster_supported:
                                                endpoint = self.gateway.application_controller.devices[ieee].non_zdo_endpoints[0]

                                            fuzz_parameters[index]["endpoint"].extend([endpoint] * len(mutated_payload_bytes))
                                            fuzz_parameters[index]["clusterID"].extend([cluster_id] * len(mutated_payload_bytes))
                                            fuzz_parameters[index]["frame_type"].extend([foundation.FrameType.GLOBAL_COMMAND] * len(mutated_payload_bytes))

                                            for mutated_case in mutated_payload_bytes:
                                                fuzz_parameters[index]["payload"].append(mutated_case[0])
                                                if cluster_supported:
                                                    fuzz_parameters[index]["strategy"].append(mutated_case[1])
                                                else:
                                                    fuzz_parameters[index]["strategy"].append(mutated_case[1] + ["T-2-3"])

                                # ———————————————————————— 消息序列中该消息如果不需要fuzz，则进行字段赋值操作 ————————————————————————
                                else:
                                    fuzz_parameters[index] = copy.deepcopy(parameter_prompt)

                                    if msg_layer == "ZCL_Command":
                                        fuzz_parameters[index]["endpoint"].append(endpoint)
                                        fuzz_parameters[index]["clusterID"].append(msg_cluster_id)
                                        fuzz_parameters[index]["commandID"].append(msg_format["id"])
                                        fuzz_parameters[index]["frame_type"].append(foundation.FrameType.CLUSTER_COMMAND)
                                        fuzz_parameters[index]["direction"].append(msg_direction)


                                # self.write_fuzz_log(f"[Fuzzer] Test Case: {mutated_bytes} {mutated_strategy}")
                                        
                                try:
                                    result = await self.gateway.request_raw(endpoint,
                                                                            msg_cluster_id,
                                                                            msg_format["id"],
                                                                            foundation.FrameType.CLUSTER_COMMAND,
                                                                            payload_bytes=fuzz_parameters[index]["payload"],
                                                                            direction=msg_direction,
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
                # 2. 三种启发式 A-C 策略
                else:
                    for sequence in fuzzing_sequences:
                        messages = sequence.split(",")
                        payload_components = []
                        for message in messages:
                            msg_format = get_message_format(message, all_message_formats)
                            if msg_format is None:
                                continue

                        payload_components.append([msg_format["schema"]])
                        fuzz_prompt = []

                        mutation_strategy = Mutator.mutate_type_value

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

    async def run(self):
        # Initialize gateway and start the zigbee network
        await self.gateway.run()

        log.info(
            "*********************************[ZVDetector] State-Guided Fuzzer *********************************")

        counter = 0

        while True:
            debug_flag = False
            fuzz_flag = False
            poc_flag = True

            while True:
                if counter % 5 == 0:
                    await self.schedule_state_record()

                flag = input_with_timeout("Operation:\n", 7, "")

                ieee = None

                if flag == "debug":
                    debug_flag = True
                    break

                if flag == "fuzz":
                    fuzz_flag = True

                    log.info(
                        "*********************************[State-Guided Fuzzer] Begin *********************************")

                if flag == "poc":
                    poc_flag = True
                    break

            if fuzz_flag or poc_flag:
                for ieee in self.gateway.application_controller.devices.keys():
                    log.info(f"[Fuzzer] Fuzzing {ZIGBEE_DEVICE_MAC_MAP[str(ieee)]} ({str(ieee)})")
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
