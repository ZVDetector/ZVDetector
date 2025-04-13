# LLM Correlation Analysis Test Case
format1 = {
    "id": 3, 
    "direction_header": 1, 
    "saturation": "t.uint8_t",
    "transition_time": "t.uint16_t",
    "options_mask": "t.bitmap8",
    "options_override": "t.bitmap8"
}


format2 = {
    "id": 5, 
    "direction_header": 1, 
    "step_mode": {
        "t.enum8": [1, 3]
    },
    "step_size": "t.uint8_t",
    "transition_time": "t.uint8_t",
    "options_mask": "t.bitmap8",
    "options_override": "t.bitmap8"
}

format3 = {
    "id": 22, 
    "direction_header": 1, 
    "inter_pan_transaction_id": "t.uint32_t",
    "epid": "t.EUI64",
    "nwk_update_id": "t.uint8_t",
    "logical_channel": "t.uint8_t",
    "pan_id": "t.PanId",
    "nwk_addr": "t.NWK"
}

# Test Case1
corr.LLM.LLM_correlation("move_to_saturation", format1, "ZCL", "step_saturation", format2, "ZCL")

# Test Case2
corr.LLM.LLM_correlation("move_to_saturation", format1, "ZCL", "network_update", format3, "ZCL")
