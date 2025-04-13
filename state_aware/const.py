LAYERS = ["MAC", "NWK", "APS", "ZDP", "ZCL"]
FRAMES = [["ACK", "Data", "Command"], ["Data", "Command"], ["ACK", "Data", "Command"], ["Command"],
          ["General", "Command"]]
PARTS = [["header", "header", "payload"], ["header", "payload"], ["header", "header", "payload"], ["payload"],
         ["payload", "payload"]]

except_fields = ["id", "options", "options_mask", "options_override", "reserved", "undefined",
                 "direction_header", "endpoint_id", "device_id", "cluster_id", "user_id",
                 "version", "ieee_addr", "nwk_addr", "epid", "profile_id", "timeout", "status",
                 "data", "apscommand_identifier", "destination_address", "server_mask", "profile_id",
                 "src_ieeeaddress", "device_address", "dst_endp", "src_endp", "ieeeaddr", "src_address", "dst_address",
                 "extended address", "src_endpoint", "old_endpoint", "old_address", "endpoint",
                 "nwkaddr", "start_index", "panid", "short_address",  "destination_address",
                 "source_address", "device_short_address", "pan_id", "network_address", "nwkaddr_of_interest",
                 "nwkaddr, ieeeaddr", "src_addr", "ieeeaddress", "src_addr", "dst_addr", "extended_address"]

except_messages = ["ackframe", "data_frame", "nwkdata_frame_header", "aps_ack_frame_header", "aps_data_frame_header"]

common_used_cluster = ["Thermostat", "Metering", "GenericTunnel", "BacnetProtocolTunnel", "AnalogInput",
                       "ApplianceEventAlerts", "ApplianceStatistics", "ElectricalMeasurement", "DoorLock",
                       "WindowCovering", "RSSILocation", "IasZone", "IasAce", "IasWd", "LightLink", "Basic", "Identify",
                       "Groups", "Scenes", "OnOff", "LevelControl", "Color", "Ota", "Commissioning", "Alarms", "PowerProfile"]

