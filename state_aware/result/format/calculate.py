import json
from zigpy.zcl.foundation import *
# with open("message_distribution.json", "r") as f:
#     result = json.load(f)
#
# count = sum(list(result.values()))
# print(count)


with open("ZCL/format(ZCL_Command).json", "r") as f:
    result = json.load(f)

total_count = 0
message_count = 0

for cluster, cvalue in result.items():
    if "Server" in cvalue.keys():
        server_cmd = cvalue["Server"]
        for cmd_name in server_cmd.keys():
            if "response" in cmd_name or 'rsp' in cmd_name:
                total_count += 1
        message_count += len(server_cmd.keys())

    if "Client" in cvalue.keys():
        client_cmd = cvalue["Client"]
        for cmd_name in client_cmd.keys():
            if "response" in cmd_name or 'rsp' in cmd_name:
                total_count += 1
        message_count += len(client_cmd.keys())

print(message_count)
print(total_count)