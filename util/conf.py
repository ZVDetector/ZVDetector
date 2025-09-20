ZIGBEE_DEVICE_MAC_MAP = {
    "00:15:8d:00:05:44:58:7e": "Aqara Vibration Sensor",
    "00:15:8d:00:05:72:a0:16": "Aqara Motion Sensor",
    "00:15:8d:00:04:9d:be:e7": "Aqara Water Leak Sensor",
    "00:15:8d:00:09:52:15:30": "Aqara Door Window Sensor",
    "00:15:8d:00:09:77:8a:b0": "Aqara Temperature_Humidity Sensor",
    "00:15:8d:00:05:2f:9d:ad": "Aqara Smart Cube",
    "54:ef:44:10:00:8c:45:bb": "Aqara Wireless Switch",
    "00:15:8d:00:05:3e:bb:0e": "Mijia Honeywell Smoke Sensor",
    "00:15:8d:00:01:58:72:00": "Aqara Smart Plug",
    "a4:c1:38:8d:4b:e3:c8:1d": "Tuya Smart Plug",
    "a4:c1:38:ba:81:3f:fc:88": "Tuya Smart Bulb",
    "a4:c1:38:2d:59:06:25:e1": "Tuya Switch",
    "a4:c1:38:b8:c2:f4:4e:e6": "Tuya OMEG Smart Valve",
    "b0:ce:18:14:03:68:57:34": "Sengled Smart Bulb",
    "b0:ce:18:d2:1a:22:56:fc": "Sengled Strip",
    "b0:ce:18:01:0e:51:ec:8d": "Sengled Dimmer Switch",
    "28:2c:02:bf:ff:ea:47:eb": "ThirdReality Smart Plug Gen2",
    "7c:b9:4c:63:3c:65:00:00": "ThirdReality Smart Bulb",
}

WIFI_DEVICE_MAC_MAP = {
    "B4:60:ED:5B:42:8E": "Mijia Smart Fan",
    "68:AB:BC:B0:B7:BD": "Mi Smart Plug WiFi",
    "E4:AA:EC:6C:B5:4D": "Mi 2K Camera",
    "CC:B5:D1:27:7C:04": "Mi LED Desk Lamp",
    "94:f8:27:AC:CC:18": "Mi 360 Camera",
    "00:7E:56:43:40:07": "OSPO Smart Plug",
    "58:B6:23:BE:61:61": "Philips Desk Lamp",
    'cc:50:e3:dc:f8:d7': 'HUAWEI Smart Plug',  # ORVIBO-S30C
    '54:EF:44:4A:CF:F1': 'Aqura Hub',  # AQARA_HUB-1E38
    'c4:4f:33:99:ab:a2': 'Tuya Smart Plug',  # ESP_99ABA2
    '50:ec:50:7a:b3:d0': 'Mijia Lamp',  # YEELINK-LIGHT-BSLAMP2_MIBTB3D0
    '44:23:7c:57:c9:94': 'Mijia Smart Plug',  # CHUANGMI-PLUG-M3_MIIO234553236'
    '64:90:c1:b5:76:bb': 'Mijia Floor-standing Fan',  # DMAKER-FAN-P8_MIAP76BB
    '64:90:c1:db:a9:f3': 'Mijia Humidifier',  # DEERMA-HUMIDIFIER-JSQ3_MIBTA9F3
    '5c:e5:0c:ba:c4:ff': 'Mijia Air Purifier',  # ZHIMI-AIRPURIFIER-MA2_MIIO315425924
    'a8:bb:50:22:d2:55': 'Philips Desk Lamp',  # WIZ_22D255
    'd0:49:00:47:5e:90': 'PICOOC Smart Blood Pressure Meter',  # UART-WIFI
    '00:e0:4c:8e:c9:52': 'WAYSDREAM Digital Photo Frame',  #
    '5c:e5:0c:a9:71:fa': 'Mijia Smart Camera',  # MIJIA_CAMERA_V3
    '48:46:c1:51:b6:46': 'HUAWEI Smart Camera',  # DEFAULT
    '80:ea:07:aa:40:3b': 'TP-Link surveillance cameras',  # TL-IPC43AN-4
    '48:3f:e9:8d:4d:e5': 'HUAWEI AI Speaker',  # AI SPEAKER MINI
    'ec:fa:5c:0a:f8:a3': 'XiaoMi AI Sound Box',  # MIAISOUNDBOX
}

ZIGBEE_TESTBED_DEVICES = ["Aqara Smart Plug", "Tuya Switch", "Tuya Smart Plug", "Tuya Smart Bulb",
                          "Sengled Dimmer Switch", "Sengled Smart Bulb", "Sengled Strip", "Tuya OMEG Smart Valve",
                          "ThirdReality Smart Bulb", "ThirdReality Smart Plug Gen2"]

COORDINATOR_IEEE = "00:12:4b:00:32:d4:40:05"

# NEO4J_URL = "bolt://localhost:7687" # WINDOWS, DOCKER
NEO4J_URL = "http://localhost:7474"  # MACOS
NEO4J_PASSWORD = "zvdetector"

ZIGBEE_LINK_KEY = "5A6967426565416C6C69616E63653039"
ZIGBEE_NETWORK_KEY = "20007a5ce740a1abbb413ba47119dfb9"

DEEPSEEK_API_KEY = "<Your Deepseek API Key>"
OPENAI_API_KEY = "<Your OPENAI API Key>"

SUPPORT_MODE = {
    "format_generated": True,
    "corr_discovery_done": True,
    "dependency_analysis_done": True,
    "basic_graph_done": False,
    "potential_state_discovery_done": True,
    "hidden_attributes_done": True,
    "attribute_permission_done": True
}

