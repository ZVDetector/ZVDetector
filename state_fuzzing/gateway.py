import os
import re
import sys
import json
import time
import signal
import asyncio
from typing import Tuple, List

sys.path.append(os.path.dirname(os.getcwd()))

import zigpy_znp
import zigpy.zdo
import zigpy.zcl
import zigpy.device
import zigpy.endpoint
import zigpy.application
import zigpy.exceptions
from zigpy.zcl import foundation, convert_list_schema
import zigpy.types as t
import zigpy.zdo.types as zdo_t
import zigpy_znp.frames
from zigpy_znp.api import ZNP
from zigpy_znp.config import CONFIG_SCHEMA
from zigpy_znp.zigbee.application import ControllerApplication
from zigpy_znp.tools.common import setup_parser, ClosableFileType, validate_backup_json

from util.logger import get_logger
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from util.serial import serialize
from util.utils import find_files_with_prefix, input_with_timeout, get_struct_time, clear_folder
from bert.model import BERT
from network.network_backup import backup_network
from network.network_restore import restore_network
from state_aware.specification import get_cluster_command
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# log = get_logger()  # If color log

# python network.py -c 20 -d 15 -l -o network.json /dev/tty.usbserial-14110

def parse_args(argv, notification):
    parser = setup_parser(notification)
    parser.add_argument(
        "-c",
        "--channels",
        dest="channels",
        type=lambda s: t.Channels.from_channel_list(map(int, s.split(","))),
        default=t.Channels.ALL_CHANNELS,
        help="Channels on which to scan for networks",
    )

    parser.add_argument(
        "-d",
        "--duration",
        dest="duration",
        type=int,
        default=60,
        help="Permit duration",
    )
    parser.add_argument(
        "-l",
        "--load_state",
        action="store_true",
        help="Use state to guide fuzzing",
    )

    parser.add_argument(
        "-r",
        "--reset",
        action="store_true",
        help="Reset the network",
    )

    parser.add_argument(
        "--input", "-i", type=ClosableFileType("r"), required=False, help="Input file"
    )

    parser.add_argument(
        "--output", "-o", type=ClosableFileType("w"), required=True, help="Output file"
    )

    args = parser.parse_args(argv)
    # log.info(args.input)
    if args.reset and args.input is None:
        raise InputTimeoutError("Restore the network but no information!")

    return args


def get_attribute_id(cluster: zigpy.zcl.Cluster, attribute_name: str) -> t.uint16_t:
    if attribute_name not in cluster.attributes_by_name.keys():
        return t.uint16_t(0)
    else:
        return t.uint16_t(cluster.attributes_by_name[attribute_name].id)


def get_attribute_name(cluster: zigpy.zcl.Cluster, attribute_id: int) -> str:
    for attribute_name, attribute_def in cluster.attributes_by_name.items():
        if attribute_def.id == t.uint16_t(attribute_id):
            return attribute_name
    return "Manufacturer-Specific"


class ZHAGateway:
    def __init__(self, args):
        self.name = "snoff usb dongle 3.0"
        self.device_path = args.serial
        self.reset_dongle = args.reset
        self.config = {"channels": args.channels,
                       "duration": args.duration,
                       "device": {"path": args.serial},
                       "output": args.output,
                       "state_guide": args.load_state}

        self.application_controller = ControllerApplication(self.config)
        self.coordinator_ieee = t.EUI64.convert("00:12:4b:00:30:cb:d7:43")
        self.parent_nwk = t.NWK.convert("0000")
        self.max_fuzzing_packet = 10
        self.bert_model = BERT()
        self.name2ieee = {a: b for b, a in ZIGBEE_DEVICE_MAC_MAP.items()}
        self.state_db = os.path.join(os.path.dirname(os.getcwd()), "library", "device_state_db")
        self.protocol_db = os.path.join(os.path.dirname(os.getcwd()), "library", "protocol_state_db")
        self.cluster_db = os.path.join(os.path.dirname(os.getcwd()), "library", "cluster_db")
        self.attribute_db = os.path.join(os.path.dirname(os.getcwd()), "library", "attribute_db")
        self.command_db = os.path.join(os.path.dirname(os.getcwd()), "library", "command_db")
        self.case_db = os.path.join(os.path.dirname(os.getcwd()), "library", "interesting_case")
        self.general_packets = 0
        self.zcl_packets = 0
        self.total_packets = 0

        log.info(self.cluster_db)

        if self.reset_dongle:
            self.config["reset"] = True
            self.config["input"] = args.input

    async def initialize(self) -> None:
        await self.application_controller.connect()
        log.info("[INITIALIZE] Starting Zigbee Network")

        await self.application_controller.initialize(auto_form=False)
        log.info("[INITIALIZE] Zigbee Network is Ready !")
        # log.info("[##] Existing Devices: {}".format(self.application_controller.devices))

        # 清空数据库
        # log.info("[INITIALIZE] Clearing the Database")
        # clear_folder(self.cluster_db)
        # clear_folder(self.command_db)
        # clear_folder(self.attribute_db)

    async def clean(self) -> None:
        await self.application_controller.disconnect()

    async def reset_nwk(self) -> None:
        with self.config["input"] as f:
            backup = json.load(f)
            validate_backup_json(backup)
            await restore_network(
                radio_path=self.config["device"]["path"],
                backup=backup
            )

    async def get_nwk_info(self) -> None:
        with self.config["output"] as f:
            backup_obj = await backup_network(self.application_controller.znp_ins)
            f.write(json.dumps(backup_obj, indent=4))
        log.info("[INITIALIZE] Zigbee Network Information Recorded!")

    async def send_permit(self) -> None:
        await self.application_controller.permit(self.config["duration"])

    async def energy_scan(self) -> None:
        await self.application_controller.energy_scan(self.config["channels"], self.config["duration"], 10)

    async def add_device(self) -> None:
        log.info("[##] Existing Devices: {}".format(self.application_controller.devices))

        with open("network.json", 'r', encoding='utf-8') as file:
            network_info = json.load(file)

        for device in network_info["devices"]:
            if not (device["ieee_address"] and device["nwk_address"]):
                continue
            ieee = t.EUI64.convert(device["ieee_address"])
            nwk = t.NWK.convert(device["nwk_address"])
            log.info("[+] [IEEE: {}, NWK: {}] Add device to application controller!".format(ieee, nwk))
            self.application_controller.add_device(ieee, nwk)
            log.info("[+] [NWK: {}] Initialize device instance".format(nwk))
        #     await self.application_controller.devices[ieee].schedule_initialize()

    async def find_similar_device(self, device_name: str) -> Tuple[t.EUI64, zigpy.device.Device]:
        """
        Using BERT/LLM to get the most similar device according to the given device name

        :param device_name: IoT Device Name
        :return: The IEEE Address and Zigpy.Device Instance of the most similar device
        """
        device_name = self.bert_model.find_pair(device_name, list(ZIGBEE_DEVICE_MAC_MAP.values()))[0]
        ieee = t.EUI64.convert(self.name2ieee[device_name])
        device = self.application_controller.devices[ieee]
        return ieee, device

    async def request_node_descriptor(self, ieee: t.EUI64) -> None:
        """
        Requesting the node descriptor of device

        :param ieee: Device IEEE Address
        :return: None
        """
        device = self.application_controller.devices[ieee]
        log.info("[REQUEST] Requesting Node Descriptor")
        status, _, node_desc = await device.zdo.Node_Desc_req(device.nwk)
        if status == zdo_t.Status.SUCCESS:
            log.info("[RESPONSE] Node Descriptor {}".format(node_desc))

    async def request_simple_descriptor(self, ieee: t.EUI64) -> None:
        """
        Requesting the active endpoint list of a device
        Requesting the simple descriptor of a device

        :param ieee: Device IEEE Address
        :return: None
        """
        device = self.application_controller.devices[ieee]
        log.info("[REQUEST] Requesting Active Descriptor")
        status, _, endpoints = await device.zdo.Active_EP_req(device.nwk)
        log.info("Discovered endpoints of [{}]: {}".format(device.nwk, endpoints))
        for endpoint_id in endpoints:
            status, _, sd = await device.zdo.Simple_Desc_req(
                device.nwk, endpoint_id
            )
            log.info("[RESPONSE] Endpoint: {}".format(sd))

    async def generate_pairing_graph(self):
        log.info("[IV-A1] Generating Pairing Graph")

        log.info("[IV-A1] Generating Pairing Graph Done!")

    async def get_support_cluster(self, ieee: t.EUI64, endpoint: zigpy.endpoint.Endpoint):
        support_cluster_path = "{}/{}_{}.json".format(self.cluster_db, str(ieee), endpoint.endpoint_id)
        if not os.path.exists(support_cluster_path):
            # log.error("No information are fetched during commissioning phase!")
            return None
        with open(support_cluster_path, "r", encoding='utf-8') as f1:
            support_cluster = json.load(f1)
        return support_cluster

    async def support_cluster_collection(self, ieee: t.EUI64) -> None:
        """
        Record supported cluster of each device in cluster database

        :param ieee: Device IEEE Address
        :return: None
        """

        log.info("[A2-COMMISSIONING GET] [{}] Discover Supported Cluster".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

        device = self.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            cluster_dict = {
                "input": {
                    "Unknown": []
                },
                "output": {
                    "Unknown": []
                }
            }

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            if support_cluster is not None:
                continue

            with open("{}/{}_{}.json".format(self.cluster_db, str(ieee), endpoint.endpoint_id), "w") as f:
                for id, cluster in endpoint.in_clusters.items():
                    if cluster.ep_attribute is not None:
                        cluster_dict["input"][cluster.ep_attribute] = cluster.cluster_id
                    else:
                        cluster_dict["input"]["Unknown"].append(id)

                for id, cluster in endpoint.out_clusters.items():
                    if cluster.ep_attribute is not None:
                        cluster_dict["output"][cluster.ep_attribute] = id
                    else:
                        cluster_dict["output"]["Unknown"].append(id)

                json.dump(cluster_dict, f, indent=4)

        log.info(
            "[A2-COMMISSIONING GET] [{}] Discover Supported Cluster Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

    async def get_support_attribute(self):
        attribute_save_path = os.path.join(self.attribute_db, "support_attribute.json")
        if os.path.exists(attribute_save_path):
            with open(attribute_save_path, "r", encoding='utf-8') as fa:
                support_attribute = json.load(fa)
        else:
            support_attribute = dict()
        return support_attribute

    async def discover_cluster_attributes(self, ieee: t.EUI64, cluster_name: str, cluster_id: int = None) -> dict:
        """

        :param ieee: Device IEEE Address
        :param cluster_name: The name of certain cluster
        :param cluster_id: If Cluster is Manufacturer-Specific, this field need to provide value
        :return: All attributes values with its type are stored in a dictionary
        """
        device = self.application_controller.devices[ieee]
        # log.info("[+] Reading Attribute Value of Cluster: {}".format(cluster_name))

        success, failure = {}, {}

        if cluster_name == "Unknown" and cluster_id is None:
            log.error("[ERROR] Manufacturer-Specific Cluster Need to Provide Cluster ID!")
            return dict()

        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            support_attribute = await self.get_support_attribute()
            cluster_attribute = support_attribute[str(ieee)][str(endpoint.endpoint_id)]
            check_id = False

            if cluster_name not in cluster_attribute.keys():
                continue

            if cluster_name == "Unknown":
                check_id = True
            else:
                if cluster_name in support_cluster["input"].keys():
                    cluster_id = support_cluster["input"][cluster_name]
                elif cluster_name in support_cluster["output"].keys():
                    cluster_id = support_cluster["output"][cluster_name]
                else:
                    cluster_id = None

            if cluster_id is None:
                continue

            all_attributes = cluster_attribute[cluster_name]

            for attribute in all_attributes:
                attr_id = t.uint16_t(attribute["attr_id"])
                attr_name = attribute["attr_name"]
                if check_id and attribute["cluster_id"] != cluster_id:
                    continue

                try:
                    result = await self.send_zcl_general(endpoint, t.ClusterId(cluster_id), 0x00, [attr_id])
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

                                success[attr_name] = {"type": value_type_id, "value": value}
                                # log.info("[RESPONSE] {} Values: {}".format(record_attribute, value))

                            # UNSUPPORTED_ATTRIBUTE, Write Only, other Status
                            else:
                                failure[attr_name] = record.status
                                # log.info("[RESPONSE] {} Status: {}".format(record_attribute, record.status))

                except asyncio.TimeoutError:
                    log.error("[ERROR] Read Attribute Fail! Cluster: {}({}) Attribute: {}"
                              .format(cluster_name, cluster_id, attr_name))
                    continue
        return success

    async def discover_all_attributes(self, ieee: t.EUI64) -> dict:
        """
        Discover the attributes of each cluster of a device (including all the endpoints)
        :param ieee: Device IEEE Address
        :return: All endpoints with all clusters' attributes
        """
        device = self.application_controller.devices[ieee]
        start_attr_id = 0x0000
        max_attr_id = 0xff

        manufacturer_specific_count = 0
        all_result = {}
        for endpoint in device.non_zdo_endpoints:
            endpoint_id = endpoint.endpoint_id
            all_result[endpoint_id] = {}

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            if support_cluster is None:
                continue

            for cluster_kind in support_cluster.keys():
                for cluster_name, cluster_id in support_cluster[cluster_kind].items():
                    if cluster_name not in all_result[endpoint_id].keys():
                        all_result[endpoint_id][cluster_name] = []
                    if cluster_name == "light_color":
                        start_attr_id = 0x0010

                    if cluster_name == "Unknown":
                        cluster_ids = cluster_id
                        cluster = None
                    else:
                        cluster_ids = [cluster_id]
                        try:
                            cluster = endpoint.get_cluster(cluster_name)
                        except AttributeError:
                            cluster = endpoint.get_cluster_from_id(cluster_id)
                        if cluster is None:
                            continue

                    for cid in cluster_ids:
                        try:

                            payload = b''
                            payload += serialize(start_attr_id, t.uint16_t)
                            payload += serialize(max_attr_id, t.uint8_t)

                            result = await self.request_raw(endpoint, cid, 0x0C,
                                                            frame_type=foundation.FrameType.GLOBAL_COMMAND,
                                                            payload_bytes=payload,
                                                            direction=foundation.Direction.Client_to_Server)
                        except asyncio.exceptions.TimeoutError:
                            log.error("[ERROR] Device: {} Endpoint: {} Cluster {} Discover Fail"
                                      .format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], endpoint.endpoint_id, cluster_name))
                            continue

                        try:
                            attributes = result.attribute_info
                        except AttributeError:
                            continue

                        for attribute in attributes:
                            record_attr = {"attr_type": attribute.datatype,
                                           "attr_id": attribute.attrid}
                            if cluster is not None:
                                record_attr["attr_name"] = get_attribute_name(cluster, attribute.attrid)
                            else:
                                manufacturer_specific_count += 1
                                record_attr["attr_name"] = "Manufacturer-Specific{}".format(manufacturer_specific_count)
                                record_attr["cluster_id"] = cid
                            all_result[endpoint_id][cluster_name].append(record_attr)

                            # log.info("[RESPONSE] TYPE:{} ATTRID: {}".format(foundation.DATA_TYPES[
                            # attribute.datatype][1], attribute.attrid))
        return all_result

    async def support_attribute_collection(self):
        """
        When Zigbee Network formed and device join, record all supported attributes
        :return: None
        """
        attributes = await self.get_support_attribute()

        for ieee in self.application_controller.devices.keys():

            # 如果为协调器或者已经记录过属性的设备，则不探索
            if ieee == self.coordinator_ieee or str(ieee) in attributes.keys():
                continue

            log.info(
                "[A2-COMMISSIONING GET] [{}] Discover Supported Attribute".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

            result = await self.discover_all_attributes(ieee)

            log.info("[A2-COMMISSIONING GET] [{}] Discover Supported Attribute Complete".format(
                ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

            attributes[str(ieee)] = result

        with open(os.path.join(self.attribute_db, "support_attribute.json"), "w") as f2:
            json.dump(attributes, f2, indent=4)

    async def get_support_command(self, ieee: t.EUI64, endpoint: zigpy.endpoint.Endpoint):
        support_command_path = "{}/{}_{}.json".format(self.command_db, str(ieee), endpoint.endpoint_id)
        if not os.path.exists(support_command_path):
            return None
        with open(support_command_path, "r", encoding='utf-8') as f:
            support_command = json.load(f)
        return support_command

    async def discover_cluster_commands(self, ieee: t.EUI64, cluster_name: str, cluster_id: int = None):
        """

        :param ieee: IEEE Extend Address of a Zigbee Device
        :param cluster_name: The cluster name that need to discover command
        :param cluster_id: The cluster id that need to discover command
        When cluster_name is unknown, cluster_id need to specified
        :return: Received Commands + Generated Commands of a Zigbee cluster
        """
        device = self.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            support_cluster = await self.get_support_cluster(ieee, endpoint)

            if cluster_name == "Unknown":
                if cluster_id not in support_cluster["input"][cluster_name] or \
                        cluster_id not in support_cluster["output"][cluster_name]:
                    continue

            else:
                if cluster_name in support_cluster["input"].keys():
                    if support_cluster["input"][cluster_name] != cluster_id:
                        continue
                elif cluster_name in support_cluster["output"].keys():
                    if support_cluster["output"][cluster_name] != cluster_id:
                        continue
                else:
                    continue

            try:
                payload = b''
                start_cmd_id = 0x00
                end_cmd_id = 0xff
                payload += serialize(start_cmd_id, t.uint8_t)
                payload += serialize(end_cmd_id, t.uint8_t)

                # Discover_Commands_Received
                result = await self.request_raw(endpoint, cluster_id, 0x11,
                                                frame_type=foundation.FrameType.GLOBAL_COMMAND,
                                                payload_bytes=payload,
                                                direction=foundation.Direction.Client_to_Server)

                # Discover_Commands_Generated
                result_generated = await self.request_raw(endpoint, cluster_id, 0x13,
                                                          frame_type=foundation.FrameType.GLOBAL_COMMAND,
                                                          payload_bytes=payload,
                                                          direction=foundation.Direction.Client_to_Server)

            except asyncio.exceptions.TimeoutError:
                log.error("[ERROR] Device: {} Endpoint: {} Cluster {} Discover Commands Fail"
                          .format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], endpoint.endpoint_id, cluster_name))
                continue

            try:
                # log.info(result)
                commands = result.command_ids
            except AttributeError:
                commands = []
                # log.error("No received commands fetched!")

            try:
                # log.info(result_generated)
                commands_generated = result_generated.command_ids
            except AttributeError:
                commands_generated = []
                # log.error("No generated commands fetched!")

            return [commands, commands_generated]

    async def support_command_collection(self, ieee: t.EUI64):
        """

        :param ieee: IEEE Extend Address of a Zigbee Device
        :return:
        """
        device = self.application_controller.devices[ieee]
        log.info(
            "[A2-COMMISSIONING GET] [{}] Discover Supported Command".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

        for endpoint in device.non_zdo_endpoints:
            support_cluster = await self.get_support_cluster(ieee, endpoint)
            if support_cluster is None:
                continue

            support_commands = await self.get_support_command(ieee, endpoint)
            if support_commands is not None:
                continue

            support_commands = {"input": {}, "output": {}}

            for cluster_kind, clusters in support_cluster.items():
                for cluster_name, cluster_ids in clusters.items():

                    # 1. 如果cluster name是"Unknown",则是一个MS Cluster ID的列表
                    if cluster_name == "Unknown":
                        for cluster_id in cluster_ids:
                            try:
                                all_commands = await self.discover_cluster_commands(ieee, cluster_name, cluster_id)
                            except zigpy.exceptions.DeliveryError:
                                all_commands = [[], []]

                            if all_commands is None:
                                continue

                            if cluster_id not in support_commands[cluster_kind].keys():
                                support_commands[cluster_kind][cluster_id] = []

                            if not support_commands[cluster_kind][cluster_id]:
                                support_commands[cluster_kind][cluster_id].extend(sorted(all_commands))
                            else:
                                for sublist in all_commands:
                                    support_commands[cluster_kind][cluster_id] = sorted(list(set(support_commands[cluster_kind][cluster_id] + sublist)))
                    else:
                        if cluster_ids not in support_commands[cluster_kind].keys():
                            support_commands[cluster_kind][cluster_ids] = []

                        try:
                            all_commands = await self.discover_cluster_commands(ieee, cluster_name, cluster_ids)
                        except zigpy.exceptions.DeliveryError:
                            all_commands = []

                        if not all_commands or all_commands is None:
                            result = get_cluster_command(cluster_name)
                            if result is not None:
                                if not support_commands[cluster_kind][cluster_ids]:
                                    support_commands[cluster_kind][cluster_ids].extend(sorted(result))
                                else:
                                    support_commands[cluster_kind][cluster_ids] = sorted(
                                        list(set(support_commands[cluster_kind][cluster_ids] + result)))
                                continue

                        if not support_commands[cluster_kind][cluster_ids]:
                            support_commands[cluster_kind][cluster_ids].extend(sorted(all_commands))
                        else:
                            for sublist in all_commands:
                                support_commands[cluster_kind][cluster_ids] = sorted(
                                    list(set(support_commands[cluster_kind][cluster_ids] + sublist)))

            with open(os.path.join(self.command_db, "{}_{}.json".format(str(ieee), endpoint.endpoint_id)), "w") as f:
                json.dump(support_commands, f, indent=4)

        log.info(
            "[A2-COMMISSIONING GET] [{}] Discover Supported Command Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

    async def get_interesting_case(self, ieee: t.EUI64, endpoint: zigpy.endpoint.Endpoint):
        interesting_case_path = "{}/{}_{}.json".format(self.case_db, str(ieee), endpoint.endpoint_id)
        if os.path.exists(interesting_case_path):
            with open(interesting_case_path, "r", encoding='utf-8') as f:
                interesting_case = json.load(f)
        else:
            interesting_case = {}
        return interesting_case

    async def send_zdo_packet(self, ieee: t.EUI64) -> str:
        """
        Sending ZDO packets including Node & Simple Descriptor Request, Read Attributes of Model Information

        :param ieee: Device IEEE Address
        :return: Status(Success or Fail)
        """
        action = input_with_timeout("Action:\n", 10, "")
        if action == "":
            return "Fail"

        # time2 = time.time()

        if action == "simple":
            # log.info("[{}] Endpoints: {}".format(device.nwk, device.non_zdo_endpoints))
            try:
                # log.info("Sending Simple Descriptor Request")
                await self.request_simple_descriptor(ieee)
                # log.info("Passed Time{}".format(time2 - time1))
            except asyncio.exceptions.TimeoutError:
                return "Fail"

        if action == "node":
            try:
                # log.info("Sending Node Descriptor Request")
                await self.request_node_descriptor(ieee)
                # log.info("Passed Time{}".format(time2 - time1))
            except asyncio.exceptions.TimeoutError:
                return "Fail"

        if action == "model":
            try:
                log.info("[REQUEST] [{}] Requesting Model".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
                await self.discover_cluster_attributes(ieee, "basic")
                log.info("[COMPLETE] [{}] Requesting Model Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
            except asyncio.exceptions.TimeoutError:
                return "Fail"

        return "Success"

    async def send_zcl_general(self, endpoint: zigpy.endpoint.Endpoint, cluster_id: t.uint16_t,
                               command_id: int, *args, flag: bool = False, tsn=None, **kwargs):
        # Only request
        command = foundation.GENERAL_COMMANDS[command_id]

        if command.direction == foundation.Direction.Server_to_Client:
            log.error("This is reply")
            return "Fail"

        request = b''
        for element in list(*args):
            # log.info("[DEBUG] {}".format(type(element)))
            request = request + element.serialize()

        if tsn is None:
            tsn = endpoint.device.get_sequence()

        # log.info("[REQUEST] Sending {}".format(command.name))

        frame_control = foundation.FrameControl(
            frame_type=foundation.FrameType.GLOBAL_COMMAND,
            is_manufacturer_specific=False,
            direction=foundation.Direction.Client_to_Server,
            disable_default_response=False,
            reserved=0b0000
        )

        header = foundation.ZCLHeader(
            frame_control=frame_control,
            manufacturer=None,
            tsn=tsn,
            command_id=command.id
        )

        # log.info("Sending request header: {}".format(header))
        # log.info("Sending request: {}".format(request))

        data = header.serialize() + request
        cluster_id = t.ClusterId(cluster_id)

        result = await endpoint.request(cluster_id, header.tsn, data, expect_reply=True, command_id=command_id)

        if flag:
            self.general_packets = self.general_packets + 1

        return result

    async def request_raw(self, endpoint: zigpy.endpoint.Endpoint, cluster_id: int, command_id: int, frame_type: int,
                          payload_bytes: bytes, direction: int, tsn=None, flag: bool = False):

        cluster_id = t.ClusterId(cluster_id)

        if direction == foundation.Direction.Server_to_Client:
            log.error("[ERROR] Select Reply Function!")
            return

        if tsn is None:
            tsn = endpoint.device.get_sequence()

        frame_control = foundation.FrameControl(
            frame_type=frame_type,
            is_manufacturer_specific=False,
            direction=direction,
            disable_default_response=False,
            reserved=0b0000
        )

        header = foundation.ZCLHeader(
            frame_control=frame_control,
            manufacturer=None,
            tsn=tsn,
            command_id=command_id
        )

        data = header.serialize() + payload_bytes

        try:
            result = await endpoint.request(cluster_id, header.tsn, data, expect_reply=True, command_id=command_id)
        except AttributeError:
            result = None

        if flag:
            self.total_packets += 1

        return result

    async def acquire_cluster_info(self, device_name: str, cluster_name: str = None, flag: str = "zdo"):
        ieee, device = await self.find_similar_device(device_name)

        if ieee not in self.application_controller.devices.keys() or ieee == self.coordinator_ieee:
            return

        if flag == "zdo":
            await self.send_zdo_packet(ieee)

        elif flag == "cluster" and cluster_name is not None:
            try:
                log.info("[CLUSTER: {}] Reading Attributes".format(cluster_name))
                result = await self.discover_cluster_attributes(ieee, cluster_name)
                log.info("[CLUSTER: {}] Reading Attributes Complete".format(cluster_name))
                log.info("[RESULT] Attributes: {}".format(result))

            except asyncio.exceptions.TimeoutError:
                log.error("Can't read cluster: {}".format(cluster_name))

    async def validate_crash(self, device_name: str, cluster_name: str):

        start_attr_id = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009]
        max_attr_id = 0x30  # 0x30

        for i in range(10):
            payload = b''
            payload += serialize(start_attr_id[i], t.uint16_t)
            payload += serialize(max_attr_id, t.uint8_t)

            log.info("[PAYLOAD] {}".format(payload))
            ieee, device = await self.find_similar_device(device_name)
            for endpoint in device.non_zdo_endpoints:
                support_cluster = await self.get_support_cluster(ieee, endpoint)
                try:
                    cluster = endpoint.get_cluster(cluster_name)
                except AttributeError:
                    if cluster_name in support_cluster["output"].keys():
                        cluster = endpoint.get_cluster_from_id(support_cluster["output"][cluster_name])
                    else:
                        cluster = None

                if cluster is None:
                    continue

                try:
                    await self.request_raw(endpoint, cluster.cluster_id, 0x0c,
                                           foundation.FrameType.GLOBAL_COMMAND,
                                           payload, foundation.Direction.Client_to_Server)

                except asyncio.exceptions.TimeoutError:
                    log.error("[ERROR] Payload:{}".format(payload))

    async def run(self):
        log.info("******************************[Stage 1] Coordinator Initialize Phase*****************************")
        await self.initialize()
        if self.reset_dongle:
            log.info("[INITIALIZE] Reset the Zigbee Network")
            await self.reset_nwk()

        log.info("[INITIALIZE] Record the Zigbee Network Information")
        await self.get_nwk_info()

        print("\n")
        log.info("*********************************[IV-A] Pairing Phase Analysis *********************************")

        try:
            log.info("Pairing the Zigbee Devices")
            while True:
                await self.send_permit()
                flag = input_with_timeout("[Quit Pairing?]: ", 7, "")
                if flag == "yes":
                    break
                if flag == "devices":
                    for ieee in self.application_controller.devices.keys():
                        if ieee == self.coordinator_ieee:
                            continue
                        log.info(str(ieee) + "-" + ZIGBEE_DEVICE_MAC_MAP[str(ieee)])
                await asyncio.sleep(5)

            await self.generate_pairing_graph()

            log.info("[IV-A2] Endpoint Information Collection")

            for ieee in self.application_controller.devices.keys():
                if ieee == self.coordinator_ieee:
                    continue

                if not find_files_with_prefix(self.cluster_db, str(ieee)):
                    # IV-A2: Record the supported cluster of each device
                    await self.support_cluster_collection(ieee)

                if not find_files_with_prefix(self.command_db, str(ieee)):
                    # IV-A3: Record the supported commands of each cluster
                    await self.support_command_collection(ieee)

            # IV-A3: Record the supported attributes of each cluster
            await self.support_attribute_collection()

            log.info("[IV-A2] Endpoint Information Collection Done!")
        except KeyboardInterrupt:
            await self.clean()


if __name__ == "__main__":
    arguments = parse_args(sys.argv[1:], "Preparing the environment")
    snoff_dongle = ZHAGateway(arguments)
    asyncio.run(snoff_dongle.run())
