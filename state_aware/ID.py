WpanFrameType_MAP = {
    0x0: "Beacon",
    0x1: "Data",
    0x2: "Ack",
    0x3: "Command",
    0x4: "Reserved",
    0x7: "Extend"
}

NwkFrameType_MAP = {
    0x0: "Data",
    0x1: "Command",
    0x2: "Ack",
    0x3: "Inter-PAN"
}

ApsFrameType_MAP = {
    0x0: "Data",
    0x1: "Command",
    0x2: "Aps-Ack",
    0x3: "Inter-PAN"
}

ZclFrameType_MAP = {
    0x0: "Profile-wide",
    0x1: "Cluster-Specific",
    0x2: "Global-Command"
}

WpanCID_MAP = {
    0x01: "Association Request",
    0x02: "Association Response",
    0x03: "Disassociation Notification",
    0x04: "Data Request",
    0x05: "PAN ID Conflict Notification",
    0x06: "Orphan Notification",
    0x07: "Beacon Request",
    0x08: "Coordinator Realignment",
    0x09: "GTS Request"
}

NwkCID_MAP = {
    0x01: "Route Request",
    0x02: "Route Reply",
    0x03: "Network Status",
    0x04: "Leave",
    0x05: "Route Record",
    0x06: "Rejoin Request",
    0x07: "Rejoin Response",
    0x08: "Link Status",
    0x09: "Network Report",
    0x0A: "Network Update",
    0x0b: "End Device Timeout Request",
    0x0c: "End Device Timeout Response",
    0x0d: "Link Power Data",
    0x0e: "Network Communication Request",
    0x0f: "Network Communication Response",
}

ApsCID_MAP = {
    0x05: "Transport Key",
    0x06: "Update Device",
    0x07: "Remove Device",
    0x08: "Request Key",
    0x09: "Switch Key",
    0x0e: "Tunnel",
    0x0f: "Verify Key",
    0x10: "Confirm Key",
    0x11: "Relay Message Downstream",
    0x12: "Relay Message Upstream"
}

ZclCID_MAP = {
    0x00: "Read_Attributes",
    0x01: "Read_Attributes_rsp",
    0x02: "Write_Attributes",
    0x03: "Write_Attributes_Undivided",
    0x04: "Write_Attributes_rsp",
    0x05: "Write_Attributes_No_Response",
    0x06: "Configure_Reporting",
    0x07: "Configure_Reporting_rsp",
    0x08: "Read_Reporting_Configuration",
    0x09: "Read_Reporting_Configuration_rsp",
    0x0A: "Report_Attributes",
    0x0B: "Default_Response",
    0x0C: "Discover_Attributes",
    0x0D: "Discover_Attributes_rsp",
    0x11: "Discover_Commands_Received",
    0x12: "Discover_Commands_Received_rsp",
    0x13: "Discover_Commands_Generated",
    0x14: "Discover_Commands_Generated_rsp",
    0x15: "Discover_Attribute_Extended",
    0x16: "Discover_Attribute_Extended_rsp",
}

ZdpCluster_MAP = {
    0x0000: "Network Address Request",
    0x0001: "IEEE Address Request",
    0x0002: "Node Descriptor Request",
    0x0003: "Power Descriptor Request",
    0x0004: "Simple Descriptor Request",
    0x0005: "Active Endpoint Request",
    0x0006: "Match Descriptor Request",
    0x0013: "Device Announcement",
    0x0015: "System Server Discovery Request",
    0x001F: "Parent Announcement",
    0x0020: "End Device Bind Request",
    0x0021: "Bind Request",
    0x0022: "Unbind Request",
    0x002b: "Clear All Bindings Request",
    0x0031: "LQI Request",
    0x0032: "Routing Request",
    0x0033: "Binding Request",
    0x0034: "Leave Request",
    0x0035: "Direct Join Request",
    0x0036: "Permit Join Request",
    0x0038: "Network Update Request",
    0x0039: "Network Enhanced Update Request",
    0x003a: "Network IEEE Joining List Request",
    0x003c: "Network Beacon Survey Request",
    0x0040: "Start Key Negotiation Request",
    0x0041: "Retrieve Authentication Token Request",
    0x0042: "Get Authentication Level Request",
    0x0043: "Set Configuration Request",
    0x0044: "Get Configuration Request",
    0x0045: "Start Key Update Request",
    0x0046: "Decommission Request",
    0x0047: "Challenge Request",
    0x8000: "Network Address Response",
    0x8001: "IEEE Address Response",
    0x8002: "Node Descriptor Response",
    0x8003: "Power Descriptor Response",
    0x8004: "Simple Descriptor Response",
    0x8005: "Active Endpoint Response",
    0x8006: "Match Descriptor Response",
    0x801F: "Parent Announcement Response",
    0x8015: "System Server Discovery Response",
    0x8021: "Bind Response",
    0x8022: "Unbind Response",
    0x802b: "Clear All Bindings Response",
    0x8031: "LQI Response",
    0x8032: "Routing Response",
    0x8033: "Binding Response",
    0x8034: "Leave Response",
    0x8036: "Permit Join Response",
    0x8038: "Network Update Response",
    0x8039: "Network Enhanced Update Response",
    0x803a: "Network IEEE Joining List Response",
    0x803c: "Network Beacon Survey Response",
    0x8040: "Start Key Negotiation Response",
    0x8041: "Retrieve Authentication Token Response",
    0x8042: "Get Authentication Level Response",
    0x8043: "Set Configuration Response",
    0x8044: "Get Configuration Response",
    0x8045: "Start Key Update Response",
    0x8046: "Decommission Response",
    0x8047: "Challenge Response",
}

ACK_Message = ["Ack", "Aps_Ack"]
Commissioning_Phase_Message = [WpanFrameType_MAP[0x0], ApsCID_MAP[0x05]]

Leave_Message = [NwkCID_MAP[0x04], ZdpCluster_MAP[0x0034]]

End_Message = [ZdpCluster_MAP[0x0013], ZdpCluster_MAP[0x001F]]

Rejoin_Message = [NwkCID_MAP[0x06], NwkCID_MAP[0x07]]

LER_Message = End_Message + Rejoin_Message + Leave_Message

Commissioning_Phase_Message.extend(WpanCID_MAP.values())
# Commissioning_Phase_Message.extend(ApsCID_MAP.values())
Commissioning_Phase_Message.extend(LER_Message)