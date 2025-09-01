import os
import re
import sys
import requests
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup

sys.path.append(os.path.dirname(__file__))

from xiaomi_miot.core.miio2miot_specs import MIIO_TO_MIOT_SPECS
from xiaomi_miot.core.miot_local_devices import MIOT_LOCAL_MODELS
import zhaquirks.sengled.e1e_g7f
import zhaquirks.sengled


class MiotDevices():
    def __init__(self):
        self.miot_model = MIOT_LOCAL_MODELS
        self.miio_model = MIIO_TO_MIOT_SPECS.keys()
        self.base_url = "https://home.miot-spec.com/s/"

    def get_modelname(self):
        all_results = pd.DataFrame(columns=["model", "name"])
        for model in self.miot_model:
            extend_url = self.base_url + str(model)
            response = requests.get(extend_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_tag = soup.find('meta', attrs={'name': 'description'})
                if meta_tag['content'] is not None:
                    new_record = {"model": model, "name": meta_tag['content'].split(" ")[0]}
                    all_results.loc[len(all_results)] = new_record

        for model in self.miio_model:
            extend_url = self.base_url + str(model)
            response = requests.get(extend_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_tag = soup.find('meta', attrs={'name': 'description'})
                if meta_tag['content'] is not None:
                    new_record = {"model": model, "name": meta_tag['content'].split(" ")[0]}
                    all_results.loc[len(all_results)] = new_record

        all_results.to_csv('model.csv', index=False)


if __name__ == "__main__":
    miot = MiotDevices()
    miot.get_modelname()
