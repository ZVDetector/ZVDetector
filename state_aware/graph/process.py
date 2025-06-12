import os
import sys
import json
import time

sys.path.append(os.path.dirname(os.getcwd()))

import logging
import numpy as np
import pandas as pd
import warnings
from py2neo import Node
from graph import ProtocolGraph
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from util.utils import *
from collections import deque
from state_aware.ID import *

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO)
logging.getLogger("py2neo.client").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
log = logging.getLogger(__name__)

TSHARK_CID_FIELD = {
    "basic": "zbee_zcl_general.basic.cmd.srv_rx.id",
    "identify": "zbee_zcl_general.identify.cmd.srv_rx.id",
    "groups": "zbee_zcl_general.groups.cmd_srv_rx.id",
    "scenes": "zbee_zcl_general.scenes.cmd.srv_rx.id",
    "on_off": "zbee_zcl_general.onoff.cmd.srv_rx.id",
    "level": "zbee_zcl_general.level_control.cmd.srv_rx.id",
    "light_color": "zbee_zcl_lighting.color_control.cmd.srv_rx.id",
    "alarms": ["zbee_zcl_general.alarms.cmd.srv_rx.id", "zbee_zcl_general.alarms.cmd.srv_tx.id"],
    "rssi_location": ["zbee_zcl_general.rssi_location.cmd.srv_rx.id", "zbee_zcl_general.rssi_location.cmd.srv_tx.id"],
    "commissioning": ["zbee_zcl_general.commissioning.cmd.srv_rx.id", "zbee_zcl_general.commissioning.cmd.srv_tx.id"],
    "ota": ["zbee_zcl_general.ota.cmd.srv_rx.id", "zbee_zcl_general.ota.cmd.srv_tx.id"],
    "power_profile": ["zbee_zcl_general.pwrprof.cmd.srv_rx.id", "zbee_zcl_general.pwrprof.cmd.srv_tx.id"],
    "appliance_control": ["zbee_zcl_general.applctrl.cmd.srv_rx.id", "zbee_zcl_general.applctrl.cmd.srv_tx.id"],
    "poll_control": ["zbee_zcl_general.poll.cmd.srv_rx.id", "zbee_zcl_general.poll.cmd.srv_tx.id"],
    "green_power": ["zbee_zcl_general.gp.cmd.srv_rx.id", "zbee_zcl_general.gp.cmd.srv_tx.id"],
    "electrical_measurement": ["zbee_zcl_meas_sensing.elecmes.cmd.srv_rx.id",
                               "zbee_zcl_meas_sensing.elecmes.cmd.srv_tx.id"],
    "smartenergy_metering": ["zbee_zcl_se.met.cmd.srv_rx.id", "zbee_zcl_se.met.cmd.srv_tx.id"]
}

CID_FEATURE_NAME = {
    "basic": "BasicCID",
    "identify": "IdentifyCID",
    "groups": "GroupsCID",
    "scenes": "ScenesCID",
    "on_off": "OnOffCID",
    "level": "LevelControlCID",
    "light_color": "ColorCID",
    "alarms": ["AlarmsCID", "AlarmsCIDTX"],
    "rssi_location": ["RssiCID", "RssiCIDTX"],
    "commissioning": ["CommissionCID", "CommissionCIDTX"],
    "ota": ["OtaCID", "OtaCIDtx"],
    "power_profile": ["PowerProfileCID", "PowerProfileCIDTX"],
    "appliance_control": ["AppControlCID", "AppControlCIDTX"],
    "poll_control": ["PollControlCID", "PollControlCIDTX"],
    "green_power": ["GreenPowerCID", "GreenPowerCIDTX"],
    "electrical_measurement": ["EMCID", "EMCIDTX"],
    "smartenergy_metering": ["SMCID", "SMCIDTX"]
}


class FuzzGraph:
    def __init__(self):
        self.all_pcap = [device.replace(" ", "_") for device in ZIGBEE_DEVICE_MAC_MAP.values()]
        self.all_csv = []
        self.csv_base_dir = os.path.join(os.getcwd(), "csv")
        self.zigbee_features = ["Time", "Length", "WpanFrameType", "WpanSeqNo", "SrcPANID", "DstPANID", "ExtendedPANID",
                                "WpanCID", "SrcExtendAddr", "DstExtendAddr", "NwkSrcAddr", "NwkDstAddr", "NwkFrameType",
                                "NwkCID", "NwkMulticast", "NwkSecurity", "ExtendAddr", "ApsFrameType", "ApsCID",
                                "ApsSeqNo", "ApsSrcEp", "ApsDstEp", "ApsCluster", "ApsProfile", "ApsCounter",
                                "ZdpCluster", "ZdpSeqNo", "ZclFrameType", "ZclMS", "ZclRes", "ZclSeqNo", "ZclCID",
                                "FcsOK"]

        self.print_features = ["Time", "Length"]
        self.sequence_features = ["Time", "WpanSeqNo", "ApsSeqNo", "ZdpSeqNo", "ZclSeqNo", "ApsCounter", "FcsOK"]
        self.device2ieee = {value: key for key, value in ZIGBEE_DEVICE_MAC_MAP.items()}
        self.device2cid = {}
        self.commissioning_index = {}
        self.commissioning_begin_node = None
        self.communication_begin_node = {}
        self.message_count = {}

        self.dependent_time_threshold = 0.015

        self.link_key = "5A6967426565416C6C69616E63653039"
        self.network_key = "20007a5ce740a1abbb413ba47119dfb9"

        self.graph = ProtocolGraph('http://localhost:7474', "neo4j", "avs01046")
        self.initialize()

    def initialize(self):
        clear_folder(self.csv_base_dir)
        self.graph.graph_db.run("MATCH (n) DETACH DELETE n")

        label = "State"
        attribute = {"state": "Permit Join Request"}

        self.commissioning_begin_node = self.graph.MatchSingleNode(label, attribute)
        if self.commissioning_begin_node is None:
            self.graph.CreateNode([label], attribute)
            self.commissioning_begin_node = self.graph.MatchSingleNode(label, attribute)

    def get_cid_field(self, ieee: str):
        """
        Analyze the cluster-specific features which can be captured by the tshark
        :param ieee: IEEE Address of a device
        :return:
            tshark_field: The command script that capture the cluster-specific features of each device
            feature_list: The names of cluster-specific features
        """
        cluster_db = os.path.join(os.path.dirname(os.getcwd()), "library", "cluster_db")
        all_endpoint_cluster = find_files_with_prefix(cluster_db, ieee)

        tshark_field = ""
        feature_list = []

        for cluster_file in all_endpoint_cluster:
            with open(cluster_file, "r", encoding='utf-8') as f1:
                support_cluster = json.load(f1)
                all_cluster_name = set()
                all_cluster_name.update(support_cluster["input"].keys())
                all_cluster_name.update(support_cluster["output"].keys())

                for cluster_name in all_cluster_name:
                    if cluster_name == "Unknown" or cluster_name not in CID_FEATURE_NAME.keys():
                        continue

                    if isinstance(CID_FEATURE_NAME[cluster_name], list):
                        if is_sublist(CID_FEATURE_NAME[cluster_name], feature_list):
                            continue
                        feature_list.extend(CID_FEATURE_NAME[cluster_name])
                    else:
                        if CID_FEATURE_NAME[cluster_name] in feature_list:
                            continue
                        feature_list.append(CID_FEATURE_NAME[cluster_name])

                    if isinstance(TSHARK_CID_FIELD[cluster_name], list):
                        for field in TSHARK_CID_FIELD[cluster_name]:
                            tshark_field += "-e {} ".format(field)
                    else:
                        tshark_field += "-e {} ".format(TSHARK_CID_FIELD[cluster_name])

        tshark_field += "> {}"
        return tshark_field, feature_list

    def pcap2csv(self):
        """
        Converting the pcap into csv using tshark
        :return:
        """
        command = "tshark -r {} -o 'uat:zigbee_pc_keys:\"{}\",\"Normal\",\"\"' " \
                  "-o 'uat:zigbee_pc_keys:\"{}\",\"Normal\",\"\"' " \
                  "-T fields -E separator=$ -e frame.time_relative -e frame.len -e wpan.frame_type " \
                  "-e wpan.seq_no -e wpan.src_pan -e wpan.dst_pan -e zbee_beacon.ext_panid -e wpan.cmd " \
                  "-e wpan.src64 -e wpan.dst64 " \
                  "-e zbee_nwk.src -e zbee_nwk.dst -e zbee_nwk.frame_type -e zbee_nwk.cmd.id " \
                  "-e zbee_nwk.multicast -e zbee_nwk.security -e zbee.sec.src64 " \
                  "-e zbee_aps.type -e zbee_aps.cmd.id -e zbee_aps.cmd.seqno " \
                  "-e zbee_aps.src -e zbee_aps.dst -e zbee_aps.cluster -e zbee_aps.profile -e zbee_aps.counter " \
                  "-e zbee_aps.zdp_cluster -e zbee_zdp.seqno " \
                  "-e zbee_zcl.type -e zbee_zcl.ms -e zbee_zcl.ddr -e zbee_zcl.cmd.tsn -e zbee_zcl.cmd.id " \
                  "-e wpan.fcs_ok "

        for filename in self.all_pcap:
            device_name = filename.replace("_", " ")

            input_pcap_path = "{}/pcap/{}.pcap".format(os.getcwd(), filename)
            if not os.path.exists(input_pcap_path):
                continue

            log.info("[+] Processing Traffic of {}".format(device_name))
            save_path = "{}/{}.csv".format(self.csv_base_dir, filename)

            add_command, add_features = self.get_cid_field(self.device2ieee[device_name])

            new_command = command + add_command
            commands = new_command.format(input_pcap_path, self.link_key, self.network_key, save_path)
            execute(commands)

            all_features = self.zigbee_features + add_features

            self.filter_traffic(filename, save_path, all_features)
            self.all_csv.append(save_path)

    # FIXME: 实现LLM对消息格式的覆盖
    def check_message_type(self, message: dict):
        """
        Acquiring the message type of certain message
        :param message: A dict that contains the all features of a message
        :return: The message type name
        """
        if "WpanFrameType" in message.keys():
            wpan_frametype = int(message["WpanFrameType"], 16)
            if wpan_frametype != 0x1 and wpan_frametype != 0x3:
                return WpanFrameType_MAP[wpan_frametype]

        if "NwkFrameType" in message.keys():
            nwk_frametype = int(message["NwkFrameType"], 16)
            if nwk_frametype != 0x0 and nwk_frametype != 0x1:
                return NwkFrameType_MAP[nwk_frametype]

        if "ApsFrameType" in message.keys():
            aps_frametype = int(message["ApsFrameType"], 16)
            if aps_frametype != 0x0 and aps_frametype != 0x1:
                return ApsFrameType_MAP[aps_frametype]

        if "WpanCID" in message.keys():
            wpan_cid = int(message["WpanCID"], 16)
            if wpan_cid in WpanCID_MAP.keys():
                return WpanCID_MAP[wpan_cid]
        elif "NwkCID" in message.keys():
            nwk_cid = int(message["NwkCID"], 16)
            if nwk_cid in NwkCID_MAP.keys():
                return NwkCID_MAP[nwk_cid]
        elif "ApsCID" in message.keys():
            aps_cid = int(message["ApsCID"], 16)
            if aps_cid in ApsCID_MAP.keys():
                return ApsCID_MAP[aps_cid]
        elif "ZclCID" in message.keys():
            zcl_cid = int(message["ZclCID"], 16)
            if zcl_cid in ZclCID_MAP.keys():
                return ZclCID_MAP[zcl_cid]
        elif "ZdpCluster" in message.keys():
            cluster_id = int(message["ZdpCluster"], 16)
            if cluster_id in ZdpCluster_MAP.keys():
                return ZdpCluster_MAP[cluster_id]

        return None

    def filter_traffic(self, filename: str, csv_path: str, features: list):
        """
        Filter all noisy traffic and preprocess each feature value
        :param filename: csv filename
        :param csv_path: csv filepath
        :param features: all csv features
        :return:
        """

        def convert_hex(value, bits):
            if value == "":
                return ""
            # 将十六进制字符串转换为整数
            int_value = int(value, 16)
            # 将整数转换为最小必要长度的十六进制字符串，并添加 '0x' 前缀
            if bits == 4:
                return f'0x{int_value:01X}'
            elif bits == 8:
                return f'0x{int_value:02X}'
            elif bits == 16:
                return f'0x{int_value:04X}'
            else:
                return value

        df = pd.read_csv(csv_path, sep='delimiter')
        data = [df.columns[0].split("$")]
        for i in range(df.shape[0]):
            row = df.iloc[i][0].split("$")
            device_addr = row[features.index("ExtendAddr")]
            if ',' in device_addr:
                device_addr = device_addr.split(",")[0]

            # Filter Other Device Traffic
            if device_addr in ZIGBEE_DEVICE_MAC_MAP.keys():
                except_device = [device for device in self.all_pcap if device != filename]
                if ZIGBEE_DEVICE_MAC_MAP[device_addr].replace(" ", "_") in except_device:
                    continue

            # Filter Bad FCS
            try:
                if int(row[features.index("FcsOK")]) == 0:
                    continue
            except ValueError:
                continue

            data.append(row)

        new_df = pd.DataFrame(columns=features, data=data)

        col01 = ["WpanFrameType", "NwkFrameType", "ApsFrameType", "ZclFrameType"]
        col02 = ["WpanCID", "NwkCID", "ApsCID", "ZclCID"] + features[features.index("FcsOK") + 1:]
        col04 = ["SrcPANID", "DstPANID", "NwkSrcAddr", "NwkDstAddr", "ApsCluster", "ApsProfile", "ZdpCluster"]

        for col in col01:
            new_df[col] = new_df[col].apply(convert_hex, args=[4])
        for col in col02:
            new_df[col] = new_df[col].apply(convert_hex, args=[8])
        for col in col04:
            new_df[col] = new_df[col].apply(convert_hex, args=[16])

        new_df.to_csv(csv_path, index=False)

        new_df = pd.read_csv(csv_path)

        else_case = []
        for row_index in range(new_df.shape[0]):
            row = new_df.iloc[row_index]
            count_not_null = sum(
                [1 for col in col02 + ['ZdpCluster'] if not pd.isnull(row[col])])
            message = row.dropna().to_dict()

            message_type = self.check_message_type(message)
            if message_type == "Beacon":
                if "ExtendedPANID" not in message.keys():
                    else_case.append(row_index)
                    continue

            if "ZclFrameType" in message.keys():
                count_not_null += 1

            if "WpanFrameType" in message.keys():
                wpan_frametype = int(message["WpanFrameType"], 16)
                if wpan_frametype != 0x01 and wpan_frametype != 0x03:
                    count_not_null += 1

            if "NwkFrameType" in message.keys():
                nwk_frametype = int(message["NwkFrameType"], 16)
                # Command ACK
                if nwk_frametype != 0x01 and nwk_frametype != 0x02:
                    count_not_null += 1

            if "ApsFrameType" in message.keys():
                aps_frametype = int(message["ApsFrameType"], 16)
                if aps_frametype != 0x01 and aps_frametype != 0x02:
                    count_not_null += 1

            if count_not_null == 0:
                else_case.append(row_index)

        select_index = [i for i in new_df.index if i not in else_case]
        new_df = new_df.iloc[select_index]
        new_df.to_csv(csv_path, index=False)

    def check_sequence_dependency(self, last_message: dict, now_message: dict):
        """
        Based on some fields, it is determined whether it is an Ack/Aps Ack of the message,
        or it is a consecutively sent message, or it is retransmitted

        If the Aps layer counter is consistent, it is considered to be an Aps Ack answer to the corresponding message
        
        :param last_message:  One Message
        :param now_message: Another Message
        :return: The dependency between these two messages
        """
        for key in self.sequence_features:
            if key == "Time" or key not in last_message.keys() or key not in now_message.keys():
                continue
            if last_message[key] == now_message[key]:
                return "same"
            elif last_message[key] == now_message[key] - 1:
                return "+1"
        return None

    def check_retransmission(self, last_message: dict, now_message: dict):
        """
        判断两条信息之间是否存在重传的关系
        :param last_message:
        :param now_message:
        :return:
        """
        result = self.check_sequence_dependency(last_message, now_message)
        if result == "same" and self.check_message_type(last_message) == self.check_message_type(now_message):
            return True
        return False

    def get_basic_info(self, message_row: pd.Series):
        """
        获取一条消息的关键属性，消息类型和构建在图中的边属性
        图中的边属性应当去除那些数值型的连续变量，例如counter
        :param message_row: 每行的特征属性，除去连续型数值特征
        :param device: 设备名称
        :return:
        """
        message_attributes = message_row.dropna().to_dict()
        message_type = self.check_message_type(message_attributes)

        # 将sequence number从属性中剥离，获取构建到图中的边属性
        relation_attributes = {k: message_attributes[k] for k in message_attributes.keys()
                               if k not in self.sequence_features}

        return message_attributes, relation_attributes, message_type

    def count_total_messages(self):
        total = 0
        for element in self.message_count.values():
            total += len(element["messages"].keys())
        return total

    def commission_analysis(self, df: pd.DataFrame, device: str):
        """
        配对阶段分析，通过各个设备的csv文件进行分析
        :param df:
        :param device:
        :return:
        """
        if device not in self.message_count.keys():
            self.message_count[device] = {"messages": {}}

        start_commission_index = 0
        all_commission_index = []

        last_node = self.commissioning_begin_node
        last_message_type = "Permit Joint Request"

        # Reach the beginning node of commissioning phase
        for index in range(df.shape[0]):
            row = df.iloc[index]
            attributes, relation_attributes, message_type = self.get_basic_info(row)
            if message_type is None:
                continue

            relation_attributes["device"] = device
            # Reach the Permit Join Request Packet
            if start_commission_index == 0 and message_type != "Permit Join Request":
                continue
            if start_commission_index != 0 and message_type != "Permit Join Request":
                break

            all_commission_index.append(index)
            start_commission_index = index
            self.graph.GraphShow(device, "Commissioning Phase", self.graph.Count(), self.graph.SingleCount(device),
                                 self.count_total_messages(), len(self.message_count[device]["messages"].keys()))

        last_message_valid = False
        for index in range(start_commission_index + 1, df.shape[0]):
            row = df.iloc[index]
            attributes, relation_attributes, message_type = self.get_basic_info(row)
            if message_type is None:
                continue

            relation_attributes["device"] = device
            message_graph_type = message_type.replace(" ", "_")

            if message_type not in Commissioning_Phase_Message and message_type not in ACK_Message:
                last_message_valid = False
                continue

            if message_type in Commissioning_Phase_Message:
                message_valid = True
            else:
                message_valid = False

            if message_valid is False and last_message_valid is False:
                continue

            last_message_valid = message_valid

            all_commission_index.append(index)
            if message_graph_type not in self.message_count[device]["messages"]:
                self.message_count[device]["messages"][message_graph_type] = 1
            else:
                self.message_count[device]["messages"][message_graph_type] += 1

            if message_type not in ACK_Message:
                relationships = self.graph.MatchRelationship(message_graph_type, relation_attributes)
                if relationships:
                    # match_begin_node = relationships[0]['a']
                    match_end_node = relationships[0]['b']
                    if last_message_type == message_type:
                        self.graph.CreateRelationship(match_end_node, match_end_node,
                                                      message_graph_type, relation_attributes)
                    elif last_message_type not in LER_Message:
                        self.graph.CreateRelationship(last_node, match_end_node,
                                                      message_graph_type, relation_attributes)

                    last_message_type = message_type
                    last_node = match_end_node

                    self.graph.GraphShow(device, "Commissioning Phase", self.graph.Count(),
                                         self.graph.SingleCount(device),
                                         self.count_total_messages(),
                                         len(self.message_count[device]["messages"].keys()))
                    continue

                if message_type in Leave_Message:
                    if device not in self.communication_begin_node.keys():
                        continue
                    else:
                        self.graph.CreateRelationship(self.communication_begin_node[device],
                                                      self.commissioning_begin_node,
                                                      message_graph_type, relation_attributes)
                        last_message_type = message_type
                        last_node = self.commissioning_begin_node
                        self.graph.GraphShow(device, "Commissioning Phase", self.graph.Count(),
                                             self.graph.SingleCount(device),
                                             self.count_total_messages(),
                                             len(self.message_count[device]["messages"].keys()))
                        continue

                if message_type in Rejoin_Message:
                    next_node = self.graph.CreateNode(["State"], {"state": message_graph_type,
                                                                  "device": device,
                                                                  "phase": "Rejoining"})

                    self.graph.CreateRelationship(self.communication_begin_node[device], next_node,
                                                  message_graph_type, relation_attributes)
                    last_message_type = message_type
                    last_node = next_node
                    self.graph.GraphShow(device, "Commissioning Phase", self.graph.Count(),
                                         self.graph.SingleCount(device),
                                         self.count_total_messages(),
                                         len(self.message_count[device]["messages"].keys()))
                    continue

            next_node = self.graph.CreateNode(["State"], {"state": message_graph_type,
                                                          "device": device,
                                                          "phase": "Commissioning"})

            self.graph.CreateRelationship(last_node, next_node, message_graph_type, relation_attributes)
            last_node = next_node
            last_message_type = message_type

            self.graph.GraphShow(device, "Commissioning Phase", self.graph.Count(), self.graph.SingleCount(device),
                                 self.count_total_messages(), len(self.message_count[device]["messages"].keys()))

            if message_type in End_Message:
                last_node["phase"] = "Commissioning Complete"
                self.communication_begin_node[device] = last_node
                self.graph.graph_db.push(last_node)
                last_message_valid = False

        self.commissioning_index[device] = all_commission_index

    def check_oldest_message(self, message_window: deque, node_window: deque, dependent_window: deque, device: str):
        if len(message_window) != message_window.maxlen:
            return

        de_relation = {}
        for i in range(len(dependent_window)):
            if dependent_window[i] not in de_relation:
                de_relation[dependent_window[i]] = 1
            else:
                de_relation[dependent_window[i]] += 1

        # 1. 如果消息窗口中仍有消息和最老的消息之间产生依赖，则无需处理最老的消息
        if de_relation[dependent_window[0]] != 1:
            return

        # 2. 否则，需要构建该节点向初始通信节点的闭环

        oldest_node = node_window[0]
        self.graph.CreateRelationship(oldest_node, self.communication_begin_node[device], "Automatic", {})
        return

    def check_final_message(self, message_window: deque, node_window: deque, dependent_window: deque, device: str):
        dependent_map = {}
        for i in range(len(dependent_window)):
            if dependent_window[i] not in dependent_map:
                dependent_map[dependent_window[i]] = 1
            else:
                dependent_map[dependent_window[i]] += 1

        for i in range(len(message_window)):
            if dependent_map[dependent_window[i]] == 1:
                self.graph.CreateRelationship(node_window[i], self.communication_begin_node[device], "Automatic", {})
            else:
                continue

            self.graph.GraphShow(device, "Communication Phase", self.graph.Count(), self.graph.SingleCount(device),
                                 self.count_total_messages(), len(self.message_count[device]["messages"].keys()))

    def communication_analysis(self, df: pd.DataFrame, device: str):

        message_window = deque(maxlen=5)  # 存储前面五条消息
        node_window = deque(maxlen=5)  # 存储前面五条信息对应的最后节点(如果有Ack节点则更新，无更新节点为消息节点本身)
        dependent_window = deque(maxlen=5)
        dependent_counter = 0

        for row_index in range(0, df.shape[0]):
            row = df.iloc[row_index]
            now_message, relation_attributes, message_type = self.get_basic_info(row)
            if message_type is None:
                continue
            message_graph_type = message_type.replace(" ", "_")
            relation_attributes["device"] = device

            # 1. 如果是commission的数据包，则不分析
            if message_graph_type in Commissioning_Phase_Message or row_index in self.commissioning_index[device]:
                continue

            relation_attributes["phase"] = "Communication"

            # 2. 判断是否为重传数据包，如果是则不构建在图中
            whether_retransmission = False
            for index, message in enumerate(reversed(message_window)):
                if self.check_retransmission(message, now_message):
                    whether_retransmission = True
                    break

            if whether_retransmission:
                continue

            if message_graph_type not in self.message_count[device]["messages"]:
                self.message_count[device]["messages"][message_graph_type] = 1
            else:
                self.message_count[device]["messages"][message_graph_type] += 1

            # 3. 如果是Ack，则不保存到message window中，并且根据依赖关系构建到那个协议状态节点的后面
            if message_type == "Ack":
                for index, message in enumerate(reversed(message_window)):

                    # 3.1 需要保证上一条信息和这一个Ack是对应关系
                    if self.check_sequence_dependency(message, now_message) != "same":
                        continue
                    next_node = self.graph.CreateNode(["State"], {"state": message_graph_type})
                    self.graph.CreateRelationship(node_window[-index - 1], next_node,
                                                  message_graph_type, relation_attributes)

                    # 3.2 该消息的Ack替代其作为时间窗口的当前协议状态节点
                    node_window[-index - 1] = next_node

                    self.graph.GraphShow(device, "Communication Phase", self.graph.Count(),
                                         self.graph.SingleCount(device),
                                         self.count_total_messages(),
                                         len(self.message_count[device]["messages"].keys()))

            # 4. 如果不是Ack，则对其和Message Window中的message进行依赖性分析。
            else:
                whether_seqno_dependent = False
                for index, message in enumerate(reversed(message_window)):

                    # 4.1 如果构成序列号依赖，则构建到那个message对应的协议状态节点后面
                    if self.check_sequence_dependency(message, now_message) != "same":
                        continue

                    next_node = self.graph.CreateNode(["State"], {"state": message_graph_type})
                    self.graph.CreateRelationship(node_window[-index - 1], next_node,
                                                  message_graph_type, relation_attributes)

                    self.check_oldest_message(message_window, node_window, dependent_window, device)

                    message_window.append(now_message)
                    node_window.append(next_node)
                    dependent_window.append(dependent_window[-index - 1])

                    whether_seqno_dependent = True

                    self.graph.GraphShow(device, "Communication Phase", self.graph.Count(),
                                         self.graph.SingleCount(device),
                                         self.count_total_messages(),
                                         len(self.message_count[device]["messages"].keys()))
                    break

                # 如果不构成序列号依赖
                if not whether_seqno_dependent:

                    # 4.2 判断是否存在时间顺序上的依赖
                    if message_window and now_message["Time"] - message_window[-1]["Time"] \
                            <= self.dependent_time_threshold:
                        next_node = self.graph.CreateNode(["State"], {"state": "{}".format(message_type)})
                        self.graph.CreateRelationship(node_window[-1], next_node,
                                                      message_graph_type, relation_attributes)

                        self.check_oldest_message(message_window, node_window, dependent_window, device)
                        message_window.append(now_message)
                        node_window.append(next_node)
                        dependent_window.append(dependent_window[-1])
                        self.graph.GraphShow(device, "Communication Phase", self.graph.Count(),
                                             self.graph.SingleCount(device),
                                             self.count_total_messages(),
                                             len(self.message_count[device]["messages"].keys()))

                    else:
                        # 4.3 和时间窗口中的任何message都不构成依赖关系，则判断是否已经存在过
                        relationships = self.graph.MatchRelationship2(dict(self.communication_begin_node[device]),
                                                                      message_graph_type, now_message)

                        self.check_oldest_message(message_window, node_window, dependent_window, device)
                        message_window.append(now_message)
                        dependent_window.append(dependent_counter)
                        dependent_counter += 1

                        # 4.3.1 如果存在，则匹配是否为通信节点起始的边
                        if relationships:
                            node_window.append(relationships[0]['b'])
                        else:
                            # 4.3.2 如果不存在，则创建从通信起始节点开始的边
                            next_node = self.graph.CreateNode(["State"], {"state": "{}".format(message_type)})
                            self.graph.CreateRelationship(self.communication_begin_node[device], next_node,
                                                          message_graph_type, relation_attributes)
                            node_window.append(next_node)

                        self.graph.GraphShow(device, "Communication Phase", self.graph.Count(),
                                             self.graph.SingleCount(device),
                                             self.count_total_messages(),
                                             len(self.message_count[device]["messages"].keys()))

        self.check_final_message(message_window, node_window, dependent_window, device)

    def generate_fuzzing_graph(self):
        pass

    def construct(self):
        log.info("[V-B1: PROTOCOL STATE AWARENESS] Basic Protocol Graph Construction")

        self.pcap2csv()

        for index, csv_path in enumerate(self.all_csv):
            df = pd.read_csv(csv_path)
            device_name = os.path.splitext(os.path.basename(str(csv_path)))[0]

            log.info("[***] Starting Commission Analysis -> {}".format(device_name))
            progress_bar(2)

            self.commission_analysis(df, device_name)
            log.info("[***] Commission Analysis for {} Done".format(device_name))

            log.info("[***] Starting Communication Analysis -> {}".format(device_name))
            progress_bar(3)

            self.communication_analysis(df, device_name)
            log.info("[***] Communication Analysis for {} Done".format(device_name))

        os.system("clear")
        log.info("[V-B1: PROTOCOL STATE AWARENESS] Basic Protocol Graph Construction Complete!")


if __name__ == "__main__":
    graph = FuzzGraph()
    graph.construct()
