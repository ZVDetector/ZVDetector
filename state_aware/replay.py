import os
import sys
import json

sys.path.append(os.getcwd())

import pandas as pd
import numpy as np
from scapy.all import *
from scapy.config import conf

conf.dot15d4_protocol = "zigbee"

from utils import *
from graph_construct.build import ZGraph
from util.logger import get_logger
from conf import *

log = get_logger()


class ZProcess:
    def __init__(self):
        self.feature_list = ["index", "timestamp", "size", "protocols",
                             "src_ip", "dst_ip", "udp_srcport", "udp_dstport", "channel",
                             "wpan_type", "wpan_seq", "pan_dst", "wpan_src", "wpan_dst",
                             "zigbee_type", "zigbee_src", "zigbee_dst", "extend_src", "data"]

        self.feature_number = len(self.feature_list)
        self.base_dir = os.getcwd()
        self.graph = ZGraph("neo4j", "avs01046")
        self.device2mac = {v: k for k, v in ZIGBEE_DEVICE_MAC_MAP.items()}
        self.zigbee_json = os.path.join(self.base_dir, "dataset/Benign_Traffic/json/device_flow_zigbee.json")
        self.zigbee_pcap = os.path.join(self.base_dir, "dataset/Benign_Traffic/pcap/zigbee_traffic.pcap")
        self.zwave_json = os.path.join(self.base_dir, "dataset/Benign_Traffic/json/device_flow_zwave.json")
        self.zwave_pcap = os.path.join(self.base_dir, "dataset/Benign_Traffic/pcap/zwave_traffic.pcap")

    def process_traffic(self, device_name):
        command = 'tshark -r {}/pcap/{}.pcap -T fields -E separator=$ ' \
                  '-e frame.number -e frame.time_epoch -e frame.len -e frame.protocols ' \
                  '-e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e zep.channel_id ' \
                  '-e wpan.frame_type -e wpan.seq_no -e wpan.dst_pan -e wpan.src16 -e wpan.dst16 ' \
                  '-e zbee_nwk.frame_type -e zbee_nwk.src -e zbee_nwk.dst -e zbee.sec.src64 -e data ' \
                  '>{}/csv/{}.csv'

        dir_name = device_name.replace(" ", "_")
        device_dir = os.path.join(self.base_dir, dir_name)

        command = command.format(device_dir, dir_name, device_dir, dir_name)
        os.system(command)

        print("Pcap has been converted to csv!")
        filepath = find_subdirectories(self.base_dir, dir_name) + "/csv"
        file = find_files_with_name(filepath, dir_name + ".csv")
        process_csv(file, self.feature_list)
        return file

    def get_device_actions(self, device_name: str):

        # process_csv = self.process_traffic(device_name)
        # data = pd.read_csv(process_csv)
        device_dir = device_name.replace(" ", "_")
        pcsv = self.base_dir + "/" + device_dir + "/csv/" + device_dir + "P.csv"
        save_json = self.base_dir + "/" + device_dir + "/json/" + device_dir + ".json"

        data = pd.read_csv(pcsv)
        data = data.drop(columns=["Unnamed: 0"])
        action_map = {}
        index = 0

        while index != data.shape[0]:
            tmp_action = []
            base_count = 0
            device_info = data.iloc[index]["wpan_src"]
            if device_info not in action_map:
                action_map[device_info] = []
            while data.iloc[index]["wpan_type"] == "0x00000003" or data.iloc[index]["wpan_type"] == "0x00000001":
                if data.iloc[index + 1]["wpan_type"] != "0x00000002" or data.iloc[index]["wpan_seq"] != \
                        data.iloc[index + 1]["wpan_seq"]:
                    break

                if data.iloc[index]["wpan_type"] == "0x00000001":
                    if data.iloc[index]["zigbee_type"] == "0x00000000":
                        flag = "Zigbee Data"
                    elif data.iloc[index]["zigbee_type"] == "0x00000001":
                        flag = "Zigbee Command"
                    else:
                        flag = "IEEE 802.15.4 Data"
                else:
                    flag = "IEEE 802.15.4 Command"

                if base_count == 0:
                    tmp_action.append((index, int(data.iloc[index]["size"]), flag, data.iloc[index]["wpan_src"], data.iloc[index]["wpan_dst"]))
                    tmp_action.append((index + 1, int(data.iloc[index + 1]["size"]), "Ack", data.iloc[index + 1]["wpan_src"], data.iloc[index+1]["wpan_dst"]))
                    base_count += 1
                    index += 2
                else:
                    if data.iloc[index]["wpan_seq"] == data.iloc[index - 2]["wpan_seq"] + 1:
                        tmp_action.append((index, int(data.iloc[index]["size"]), flag, data.iloc[index]["wpan_src"], data.iloc[index]["wpan_dst"]))
                        tmp_action.append((index + 1, int(data.iloc[index + 1]["size"]), "Ack"))
                        index += 2
                    else:
                        break
            print("[-] Processing {} packet done!".format(index))
            if tmp_action:
                action_map[device_info].append(tmp_action)
            else:
                index += 1

        tf = open(save_json, "w")
        json.dump(action_map, tf)
        tf.close()

        return save_json

    def graph_represent(self):
        # csv = pd.read_csv(os.path.join(self.base_dir, "Dataset/Benign_Traffic/csv/zwave_trafficP.pcap"))
        file = open("fuzz.log", "a")

        with open(self.zigbee_json) as f:
            data = json.load(f)

        for device in data.keys():
            for i, action in enumerate(data[device]):
                for j, packet in enumerate(action):
                    if type(packet[-2]) == float:
                        data[device][i][j][-2] = "None"
                    if type(packet[-1]) == float:
                        data[device][i][j][-1] = "None"

        for device in data.keys():
            if device == "0x00000000":
                self.graph.CreateNode("Broadcast", {"Device_Address": device})
                log.info("[+] Broadcast Node {} created".format(device))
                # file.write("[+] Broadcast Node {} created! \n".format(device))
            else:
                self.graph.CreateNode("Device", {"Device_Address": device})
                log.info("[+] Device Node {} created".format(device))
                # file.write("[+] Device Node {} created! \n".format(device))

        for device in data.keys():
            relation_attr = {"Action_Sequence": []}
            for action in data[device]:
                action_string = ""
                source_address = action[0][-2]
                destination_address = action[0][-1]

                if source_address == "'0x00000000":
                    source_node = self.graph.MatchSingleNode("Broadcast", {"Device_Address": source_address})
                else:
                    source_node = self.graph.MatchSingleNode("Device", {"Device_Address": source_address})

                if destination_address == "0x00000000":
                    destination_node = self.graph.MatchSingleNode("Broadcast", {"Device_Address": destination_address})
                else:
                    destination_node = self.graph.MatchSingleNode("Device", {"Device_Address": destination_address})

                for index, packet in enumerate(action):
                    action_string += packet_serialization(packet)
                    if index != len(action) - 1:
                        action_string += "->"

                self.graph.UpdateRelationship(source_node, destination_node, "Action", relation_attr, action_string)
                # file.write("[+] Device Action {} <-> {} updated! \n".format(source_address, destination_address))
                log.info("[+] Device Action {} <-> {} updated!".format(source_address, destination_address))

        file.close()

    def get_command_packets(self, device_name, option):

        if option == "zigbee":
            json_path = self.zigbee_json
            pcap_path = self.zigbee_pcap
        elif option == "zwave":
            json_path = self.zwave_json
            pcap_path = self.zwave_pcap
        else:
            log.error("[*] Protocol is not supported!")
            return "Not supported"

        device_addr = self.device2mac[device_name]
        device_dir = device_name.replace(" ", "_")
        with open(json_path) as f:
            data = json.load(f)

        traffic = rdpcap(pcap_path)
        save_dir = self.base_dir + "/Dataset/{}/pcap/command".format(device_dir)

        action_set = {}
        for action in data[device_addr]:
            select_index = []
            action_string = ""
            for index, packet in enumerate(action):
                action_string += packet_serialization(packet[1:])
                select_index.append(packet[0])
                if index != len(action) - 1:
                    action_string += "->"

            if action_string in action_set:
                action_set[action_string] += 1
                continue

            selected_packets = [traffic[i] for i in select_index]
            action_set[action_string] = 1
            command_pcap = save_dir + "/{}.pcap".format(len(action_set))
            wrpcap(command_pcap, selected_packets)
            log.info("[+] Device {} action pcap {} generated!".format(device_name, len(action_set)))

        return save_dir

    def replay_command(self, device_name, option):
        self.get_command_packets(device_name, option)
        rdpcap(replay_dir + "/1.pcap")


if __name__ == "__main__":

    device_name = "Aqara Motion Sensor"
    zins = ZProcess()
    zins.convert_to_csv(device_name)
    zins.get_device_actions(device_name)
    zins.graph_represent()
    for device_name in zins.device2mac.keys():
        zins.replay_command(device_name, "zigbee")
    packets = rdpcap("/Fuzz/Experiment/dataset/Aqara_Motion_Sensor/pcap/command/1.pcap")
    packets[0].show()
    sendp(packets, iface="en0")
    hex_str2 = "166c756d692e73656e736f725f6d6f74696f6e2e617132"
    hex_str = "210121d10b0328150421a80105215800062400000000000a2100006410000b210b00"
    byte_str = bytes.fromhex(hex_str)
    str_result = byte_str.decode("utf-8")
    print(str_result)
