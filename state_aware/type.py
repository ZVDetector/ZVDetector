import zigpy.zcl.foundation as foundation
import zigpy.types.basic
from zigpy.zcl.foundation import ZCLAttributeAccess
import re

ACCESS_MAP = {
    ZCLAttributeAccess.Write_Optional: "*w",
    ZCLAttributeAccess.Write: "w",
    ZCLAttributeAccess.Read: "r",
    ZCLAttributeAccess.Report: "p",
    ZCLAttributeAccess.Scene: "s",
}


CLUSTER_REVISION_TYPE = {"id": foundation.ZCL_CLUSTER_REVISION_ATTR.__dict__["id"],
                         "access": ACCESS_MAP[foundation.ZCL_CLUSTER_REVISION_ATTR.__dict__["access"]],
                         "type": "t." + re.search(r"\'.*\.(.*?)\'",
                                                  str(foundation.ZCL_CLUSTER_REVISION_ATTR.__dict__["type"])).group(1)
                         }


REPORTING_STATUS_TYPE = {"id": foundation.ZCL_REPORTING_STATUS_ATTR.__dict__["id"],
                         "access": ACCESS_MAP[foundation.ZCL_REPORTING_STATUS_ATTR.__dict__["access"]],
                         "type": "t." + re.search(r"\'(.*)\'",
                                                  str(foundation.ZCL_REPORTING_STATUS_ATTR.__dict__["type"].__base__)).group(1)
                         }

FOUNDATION_ATTR_MAP = {
    "ZCL_REPORTING_STATUS_ATTR": REPORTING_STATUS_TYPE,
    "ZCL_CLUSTER_REVISION_ATTR": CLUSTER_REVISION_TYPE
}
