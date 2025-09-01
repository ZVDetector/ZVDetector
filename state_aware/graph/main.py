import os
import sys
import json
import time
import itertools

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import logging
import numpy as np
import pandas as pd
import warnings
from state_aware.graph.graph import ProtocolGraph
from util.conf import ZIGBEE_DEVICE_MAC_MAP, NEO4J_URL, NEO4J_PASSWORD
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

# request_response_dict = {
#     "setpoint_raise_lower": "none",
#     "set_weekly_schedule": "default",
#     "get_weekly_schedule": "get_weekly_schedule_response"
# }


class FuzzGraph:
    def __init__(self):
        self.all_pcap = [device.replace(" ", "_") for device in ZIGBEE_DEVICE_MAC_MAP.values()]
        self.all_csv = []
        self.csv_base_dir = os.path.join(os.path.dirname(__file__), "csv")
        self.dependency_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "result/dependency")
        self.correlation_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "result/correlation")
        self.fuzzing_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "result/fuzzing")
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
        self.all_dependency = {}
        self.all_zwave_dependency = {}

        self.dependent_time_threshold = 0.015
        self.correlation_permutations_done_number = 5
        self.correlation_permutations_number = 6
        self.link_key = "5A6967426565416C6C69616E63653039"
        self.network_key = "20007a5ce740a1abbb413ba47119dfb9"

        self.graph = ProtocolGraph(NEO4J_URL, "neo4j", NEO4J_PASSWORD)
        self.rejoin_message = ["leave", "rejoin_request"]
        self.exploration_ignored_messages = {"APS ACK", "ack", "unsupported"}
        self.commission_message = []
        self.rejoin_message = []

    def get_cid_field(self, ieee: str):
        """
        Analyze the cluster-specific features which can be captured by the tshark
        :param ieee: IEEE Address of a device
        :return:
            tshark_field: The command script that capture the cluster-specific features of each device
            feature_list: The names of cluster-specific features
        """
        cluster_db = os.path.join(os.path.dirname(os.path.dirname(__file__)), "library", "cluster_db")
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

            input_pcap_path = "{}/pcap/{}.pcap".format(os.path.dirname(__file__), filename)
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
                    next_node, _ = self.graph.CreateNode(["State"], {"state": message_graph_type,
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

            next_node, _ = self.graph.CreateNode(["State"], {"state": message_graph_type,
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
                    next_node, _ = self.graph.CreateNode(["State"], {"state": message_graph_type})
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

                    next_node, _ = self.graph.CreateNode(["State"], {"state": message_graph_type})
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
                        next_node, _ = self.graph.CreateNode(["State"], {"state": "{}".format(message_type)})
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
                            next_node, _ = self.graph.CreateNode(["State"], {"state": "{}".format(message_type)})
                            self.graph.CreateRelationship(self.communication_begin_node[device], next_node,
                                                          message_graph_type, relation_attributes)
                            node_window.append(next_node)

                        self.graph.GraphShow(device, "Communication Phase", self.graph.Count(),
                                             self.graph.SingleCount(device),
                                             self.count_total_messages(),
                                             len(self.message_count[device]["messages"].keys()))

        self.check_final_message(message_window, node_window, dependent_window, device)

    def no_consider_messages(self):
        """
        Commission and Rejoin phase messages are built independently and not considered in communication phase graph construction
        """
        phases = ["commission", "rejoin"]
        base_path = os.path.join(self.dependency_dir, "causal")

        no_consider_messages = []
        for phase in phases:
            causal_path = os.path.join(base_path, f"{phase}.json")
            temp_list = []
            with open(causal_path, "r") as f:
                phase_dict = json.load(f)

            for value in phase_dict.values():
                temp_list.extend(value)

            if phase == "commission":
                self.commission_message = list(set(temp_list))
            elif phase == "rejoin":
                self.rejoin_message = list(set(temp_list))

            no_consider_messages.extend(list(set(temp_list)))

        return no_consider_messages

    def acquire_dependency_dict(self):
        if self.all_dependency:
            return

        layers = ["ZCL", "ZDP", "NWK", "MAC", "APS"]
        dependency_counter = 0
        for layer in layers:
            dict_path = os.path.join(self.dependency_dir, layer, "result_unique.json")
            with open(dict_path, "r") as f:
                dependency_dict = json.load(f)

            self.all_dependency[layer] = {}

            for request, response in dependency_dict.items():
                if request not in self.commission_message and response not in self.commission_message:
                    if request not in self.all_dependency:
                        self.all_dependency[layer][request] = response
                        dependency_counter += 1

        log.info(f"[Dependency] {dependency_counter} dependency loaded!")

    # def acquire_zwave_dependency_dict(self):
    #     layers = ["ZWave"]

    def check_merge_sequence(self, msg: str, msg2: str, sequence_cache: list):
        for index1, sequence in enumerate(sequence_cache):
            for index2, message in enumerate(sequence):
                if index2 == len(sequence) - 1:
                    continue

                if msg == message:
                    if msg2 == sequence[index2 + 1]:
                        return index1 + 1, True

        return None, False

    def commission_integration(self):
        """
        After analyzing commission messages, integrate commission phase dependency into state graph
        """
        log.info("[Dependency] Dependency building for the commission phase!")

        commission_file = os.path.join(self.dependency_dir, "causal/commission.json")

        if not os.path.exists(commission_file):
            log.error("Check commission file has been configured correctly!")
            return

        if not self.commission_message and os.path.exists(commission_file):
            with open(commission_file, "r") as f:
                commission_messages = json.load(f)

            for key, msg_list in commission_messages.items():
                for msg in msg_list:
                    if msg not in self.commission_message:
                        self.commission_message.append(msg)

        # --- Step 1: Create initial state nodes of commission and communication phase---
        sp0, _ = self.graph.CreateNode(["State"], {"state": "sp0"})

        sc0, _ = self.graph.CreateNode(["State"], {"state": "Sc0"})

        log.info("Ensured special nodes Sp0 (unconnected) and Sc0 (communication) exist.")

        path_cache = {}

        msg_sequence_cache = []

        # Counter for new intermediate state nodes
        node_counter = 1

        # --- Step 2: Iterate through each commissioning sequence ---
        for phase_name, message_sequence in commission_messages.items():
            print(f"\nProcessing sequence: '{phase_name}'")

            # Start every sequence from the Sp0 node
            current_node = sp0

            # --- Step 3: Iterate through each message in the sequence ---
            for i, message in enumerate(message_sequence):
                is_last_message = (i == len(message_sequence) - 1)
                path_key = (current_node, message)

                flag = False

                if i != len(message_sequence) - 1:
                    node_index, flag = self.check_merge_sequence(message, message_sequence[i+1], msg_sequence_cache)

                if path_key in path_cache:
                    # Path already exists, reuse it
                    next_node = path_cache[path_key]
                    log.info(f"[Dependency] Reusing path: ('{current_node['state']}') -[{message}]-> ('{next_node['state']}')")
                    current_node = next_node
                elif flag:
                    for cache in path_cache.keys():
                        if message == cache[1] and path_cache[cache]["phase"] == "commission" + str(node_index):
                            next_node = path_cache[cache]
                            log.info(
                                f"[Dependency] Redirected path: ('{current_node['state']}') -[{message}]-> ('{next_node['state']}')")
                            self.graph.CreateRelationship(current_node, next_node, "message", {"message": message})
                            current_node = next_node
                else:
                    # Path does not exist, create a new one
                    if is_last_message:
                        # If it's the last message, the target is always Sc0
                        target_node = sc0
                    else:
                        # Otherwise, create a new intermediate state node
                        new_node_name = f"Spi_{node_counter}"
                        target_node, _ = self.graph.CreateNode(["State"], {"state": new_node_name, "phase": phase_name})
                        node_counter += 1

                    # Create the relationship
                    self.graph.CreateRelationship(current_node, target_node, "message", {"message": message})

                    log.info(f"[Dependency] Creating new transition: ('{current_node['state']}') -[{message}]-> ('{target_node['state']}')")

                    # Update the cache with the new path
                    path_cache[path_key] = target_node
                    current_node = target_node

            msg_sequence_cache.append(message_sequence)

        log.info("\n[Dependency] Protocol state graph (commission phase) is built successfully!")

    def dependency_integration(self, commission_build: bool = False):
        """
        Builds a basic protocol state graph in Neo4j based on the given dependency dictionary.

        :param graph: A py2neo Graph instance.
        :param dependency_dict: A dictionary containing request-response dependencies.
        """
        # Start a transaction
        self.graph.Clear()

        self.commission_integration()

        if commission_build:
            return

        log.info("[Dependency] Dependency building for the communication phase!")

        # --- Step 1: Create or get the initial communication node Sc0 ---
        # Use merge to ensure the Sc0 node is unique

        sc0 = self.graph.MatchSingleNode("State", {"state": "Sc0"})

        log.info("[Dependency] Ensuring initial node Sc0 exists.")

        # Counter for creating unique node names
        node_counter = 1

        log.info("[Dependency] Processing Request-Response relationships.")

        self.acquire_dependency_dict()

        # --- Step 2: Iterate through each request in the dictionary ---
        for layer, layer_dependency in self.all_dependency.items():
            for request, response in layer_dependency.items():
                log.info(f"\n [Dependency] Processing Request: {request} -> Response: {response}")

                # --- Create the request edge from Sc0 to a new state Sci ---
                sci_name = f"S{node_counter}"
                sci, _ = self.graph.CreateNode(["State"], {"state": sci_name, "phase": "communication"})

                # Create relationship: (Sc0) -[:message {message: request}]-> (Sci)
                self.graph.CreateRelationship(sc0, sci, "message", {"message": request, "layer": layer})
                log.info(f"[Dependency] Created node {sci_name} and relationship: (Sc0) -[{request}]-> ({sci_name})")
                node_counter += 1

                # --- Create the APS ACK edge ---
                if response == "none":
                    # Path1: Response is 'none', APS ACK goes directly back to Sc0
                    # Create relationship: (Sci) -[:message {message: "APS ACK"}]-> (Sc0)
                    self.graph.CreateRelationship(sci, sc0, "message", {"message": "APS ACK"})
                    log.info(f"[Dependency] Response is 'none'. Created relationship: ({sci_name}) -[APS ACK]-> (Sc0)")

                    # Path 2: The Unsupported Response
                    scj_name = f"S{node_counter}"
                    scj, _ = self.graph.CreateNode(["State"], {"state": scj_name, "phase": "communication"})

                    # Create relationship: (Sci) -[:message {message: "APS ACK"}]-> (Scj)
                    self.graph.CreateRelationship(sci, scj, "message", {"message": "APS ACK"})
                    log.info(
                        f"[Dependency] Created node {scj_name} and relationship: ({sci_name}) -[APS ACK]-> ({scj_name})")
                    node_counter += 1

                    sck2_name = f"S{node_counter}"
                    sck2, _ = self.graph.CreateNode(["State"], {"state": sck2_name, "phase": "communication"})

                    # Relationship: (Scj) -[:message {message: "unsupported"}]-> (Sck2)
                    self.graph.CreateRelationship(scj, sck2, "message", {"message": "unsupported", "layer": layer})

                    # Relationship: (Sck2) -[:message {message: "ack"}]-> (Sc0)

                    self.graph.CreateRelationship(sck2, sc0, "message", {"message": "ack"})
                    print(
                        f"  - [Unsupported Path] Created node {sck2_name} and relationships: ({scj_name}) -[unsupported]-> ({sck2_name}) -[ack]-> (Sc0)")
                    node_counter += 1

                else:
                    # Case (2): Response is not 'none', APS ACK goes to a new state Scj
                    scj_name = f"S{node_counter}"
                    scj, _ = self.graph.CreateNode(["State"], {"state": scj_name, "phase": "communication"})

                    # Create relationship: (Sci) -[:message {message: "APS ACK"}]-> (Scj)
                    self.graph.CreateRelationship(sci, scj, "message", {"message": "APS ACK"})
                    log.info(f"[Dependency] Created node {scj_name} and relationship: ({sci_name}) -[APS ACK]-> ({scj_name})")
                    node_counter += 1

                    # --- From Scj, build two parallel response paths ---

                    # Path 1: The Expected Response
                    sck1_name = f"S{node_counter}"
                    sck1, _ = self.graph.CreateNode(["State"], {"state": sck1_name, "phase": "communication"})

                    # Relationship: (Scj) -[:message {message: response}]-> (Sck1)
                    self.graph.CreateRelationship(scj, sck1, "message", {"message": response, "layer": layer})

                    # Relationship: (Sck1) -[:message {message: "ack"}]-> (Sc0)
                    self.graph.CreateRelationship(sck1, sc0, "message", {"message": "ack"})
                    print(
                        f"  - [Expected Path] Created node {sck1_name} and relationships: ({scj_name}) -[{response}]-> ({sck1_name}) -[ack]-> (Sc0)")
                    node_counter += 1

                    # Path 2: The Unsupported Response
                    sck2_name = f"S{node_counter}"
                    sck2, _ = self.graph.CreateNode(["State"], {"state": sck2_name, "phase": "communication"})

                    # Relationship: (Scj) -[:message {message: "unsupported"}]-> (Sck2)
                    self.graph.CreateRelationship(scj, sck2, "message", {"message": "unsupported", "layer": layer})

                    # Relationship: (Sck2) -[:message {message: "ack"}]-> (Sc0)

                    self.graph.CreateRelationship(sck2, sc0, "message", {"message": "ack"})
                    print(
                        f"  - [Unsupported Path] Created node {sck2_name} and relationships: ({scj_name}) -[unsupported]-> ({sck2_name}) -[ack]-> (Sc0)")
                    node_counter += 1

        # Commit the transaction
        log.info("\n[Dependency] Protocol state graph (communication phase) is built successfully!")

    def basic_strategy(self):
        """
         Basic strategy is designed to explore all single edges of the state graph, as they may trigger
         potential state transitions when combined with mutation strategies
        """
        start_time = time.perf_counter()

        # Cypher Query：
        # 1. MATCH path = (start:State ...)-[...]-(start): Find all paths starting from the start node and returning to the start node
        # 2. [r IN relationships(path) | r.message]: Extract the message attributes of all relationships (edges) in the path and form a list
        # 3. *1..6: Limiting the maximum path depth to 6 is a safety measure to prevent infinite loops or long query times in complex graphs

        cypher_query = """
            MATCH path = (start:State {state: $p1})-[r:message*1..6]->(start)
            WHERE ALL(intermediateNode IN nodes(path)[1..-1] WHERE intermediateNode <> start)
            RETURN [rel IN relationships(path) | rel.message] AS messages
            """

        log.info("[Basic Strategy] Explore all single edges of the state graph...")
        query_results = self.graph.CypherQuery(cypher_query, "Sc0")

        all_filtered_paths = []
        log.info(f"[Basic Strategy] Explore complete! Found {len(query_results)} raw paths. Filtering results...")

        dependency_path = []

        for record in query_results:
            raw_path_messages = record['messages']

            dependency_path.append(raw_path_messages)

            filtered_path = [
                message for message in raw_path_messages
                if message not in self.exploration_ignored_messages
            ]

            if filtered_path:
                all_filtered_paths.append(filtered_path)

        end_time = time.perf_counter()

        execution_time = end_time - start_time
        log.info(f"[Basic Strategy] Exploring time: {execution_time:.4f} seconds")

        return dependency_path, deduplicate_list_of_lists(all_filtered_paths)

    def break_dependency_skipping_strategy(self):
        """
        Strategy A: Break Dependency Skipping
        """
        log.info("[Strategy A] Exploring execution path using breaking dependency skipping strategy...")
        start_time = time.perf_counter()
        dependency_file = os.path.join(self.fuzzing_dir, "path.txt")
        if not os.path.exists(dependency_file):
            log.error(f"[Error] Please check dependency file: {dependency_file} exists!")

        dependency_path = read_list_from_file(dependency_file)

        generated_messages = []
        for path in dependency_path:
            messages = [message.strip() for message in path.split(",")]
            n = len(messages)

            if n <= 1:
                continue

            for k in range(1, n):
                for i in range(n - k + 1):
                    # messages[:i]: 前面i部分不破坏依赖, message[i-1] -> message[i+k] 破坏依赖的部分，直接跳过message[i: i+k]
                    subsequence = messages[:i] + messages[i + k:]
                    is_valid = any(msg not in self.exploration_ignored_messages for msg in subsequence)

                    if is_valid:
                        generated_messages.append(subsequence)
                        log.info(f"[Strategy A] Find execution path: {subsequence}")

        generated_messages = deduplicate_list_of_lists_no_same(generated_messages)
        log.info("[Strategy A] Filtering same execution path complete!")

        save_generated_messages = []
        for message_sequence in generated_messages:
            save_generated_messages.append(",".join(message_sequence))

        write_list_to_file(os.path.join(self.fuzzing_dir, "strategy-a.txt"), save_generated_messages)

        end_time = time.perf_counter()
        execution_time = end_time - start_time
        log.info(f"[Strategy A] Exploring time: {execution_time:.4f} seconds.")

    def correlation_insertion_strategy(self):
        """
        Strategy B: Correlation Effect Insertion
        """
        log.info("[Strategy B] Exploring execution path using correlation insertion strategy...")

        start_time = time.perf_counter()

        msg_all_corr_file = os.path.join(self.correlation_dir, "msg_all_corr.json")
        if not os.path.exists(msg_all_corr_file):
            log.error(f"[Error] Please check correlations are analyzed!")

        with open(msg_all_corr_file, "r") as f:
            msg_all_corr = json.load(f)

        corr_messages = list(msg_all_corr.keys())

        all_dependency_path_file = os.path.join(self.fuzzing_dir, "path.txt")
        all_dependency_path = read_list_from_file(all_dependency_path_file)

        all_generated_messages = []

        for dependency_path in all_dependency_path:
            base_traversed_messages = []
            path_messages = dependency_path.split(",")
            log.info(f"[Strategy B] Exploring dependency path: {dependency_path}...")

            for message in path_messages:
                # Whether commission messages exists
                base_traversed_messages.append(message)
                if message in self.exploration_ignored_messages or message not in corr_messages:
                    continue

                # [[A, B], [A, C]]  -> [D]: [[A, B, D], [A, C, D]]   [D, E]: []
                for r in range(self.correlation_permutations_done_number, self.correlation_permutations_number):
                    perms = itertools.permutations(msg_all_corr[message], r)
                    for perm in perms:
                        tmp_generated_messages = base_traversed_messages + list(perm)
                        all_generated_messages.append(tmp_generated_messages)
                        log.info(f"[Strategy B] Find correlation path: {tmp_generated_messages}")

            log.info(f"[Strategy B] Dependency path: {dependency_path} has been explored!")

        save_generated_messages = []
        for each_generated_message in all_generated_messages:
            save_generated_messages.append(",".join(each_generated_message))

        write_list_to_file(os.path.join(self.fuzzing_dir, "strategy-b.txt"), save_generated_messages)

        end_time = time.perf_counter()
        execution_time = end_time - start_time

        log.info(f"[Strategy B] Exploring time: {execution_time:.4f} seconds.")

    def potential_state_discovery(self):
        """
        According to three strategies, explore the unknown state transitions guided by message sequences
        that form each relationship type(dependency & correlation)
        """
        all_paths, basic_messages = self.basic_strategy()

        save_basic_messages = []
        all_dependency_path = []

        for basic_msg_list in basic_messages:
            save_basic_messages.append(",".join(basic_msg_list))

        for single_path in all_paths:
            all_dependency_path.append(",".join(single_path))

        write_list_to_file(os.path.join(self.fuzzing_dir, "basic.txt"), save_basic_messages)
        write_list_to_file(os.path.join(self.fuzzing_dir, "path.txt"), all_dependency_path)

        self.break_dependency_skipping_strategy()
        self.correlation_insertion_strategy()

    async def generate_fuzzing_graph(self, analysis_done: bool = False, basic_build: bool = False):
        log.info("[PROTOCOL STATE AWARENESS] Basic Protocol Graph Construction ")

        log.info("[PROTOCOL STATE AWARENESS] Starting Dependency Analysis...")

        if not analysis_done:
            self.pcap2csv()

            for index, csv_path in enumerate(self.all_csv):
                df = pd.read_csv(csv_path)
                device_name = os.path.splitext(os.path.basename(str(csv_path)))[0]

                log.info("[***] Commission Phase: Starting Dependency Analysis -> {}".format(device_name))
                progress_bar(2)

                self.commission_analysis(df, device_name)
                log.info("[***] Commission Phase: Dependency Analysis for {} Done".format(device_name))

                log.info("[***] Communication Phase: Starting Dependency Analysis -> {}".format(device_name))
                progress_bar(3)

                self.communication_analysis(df, device_name)
                log.info("[***] Communication Phase: Dependency Analysis for {} Done".format(device_name))

        progress_bar(3)
        log.info("[PROTOCOL STATE AWARENESS] Starting Dependency Analysis Done!")

        if not basic_build:
            self.dependency_integration()

        log.info("[PROTOCOL STATE AWARENESS] Protocol Graph Construction Complete!")

        log.info("[PROTOCOL STATE AWARENESS] Protocol Graph Exploration Begin ...")

        self.potential_state_discovery()

        log.info("[PROTOCOL STATE AWARENESS] Protocol Graph Exploration Complete!")


if __name__ == "__main__":
    graph = FuzzGraph()
    graph.generate_fuzzing_graph(analysis_done=True, basic_build=False)
