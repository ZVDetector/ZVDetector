# ZVDetector: State-Guided Vulnerability Detection System for Zigbee Devices

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/arch.png)

# Running Environment

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/testbed.png)

## Step 1: Fuzzer Configuration

For the fuzzer, you can also directly deploy on MACOS since Unix-like 

```ls -l /dev/ttyUSB*``` (Ubuntu)

```ls -l /dev/tty.usbserial*``` (MACOS)

USB port shows like: ```crw-rw-rw-  1 root  wheel  0x9000002 Jun 12 10:47 /dev/tty.usbserial-14110```

If you choose running fuzzer on the MACOS, better to create conda or virtualenv environment.

```conda create --name zvdetector python=3.9.18```

Install From Source
```
git clone https://github.com/ZVDetector/ZVDetector.git
```

Python Version 3.9.18 and Requirements

```
pip install -r requirements.txt 
pip install git+https://github.com/ZVDetector/zigpy.git
pip install git+https://github.com/ZVDetector/zigpy-znp.git
```

The following problems do not need to be solved
```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.
bellows 0.45.3 requires zigpy>=0.79.0, but you have zigpy 0.0.1 which is incompatible.
zha-quirks 0.0.112 requires zigpy>=0.62.0, but you have zigpy 0.0.1 which is incompatible.
zigpy-deconz 0.25.1 requires zigpy>=0.80.0, but you have zigpy 0.0.1 which is incompatible.
zigpy-xbee 0.21.0 requires zigpy>=0.70.0, but you have zigpy 0.0.1 which is incompatible.
zigpy-zigate 0.13.3 requires zigpy>=0.70.0, but you have zigpy 0.0.1 which is incompatible.
```

Download hugging face bert model ```sentence-transformers/msmarco-bert-base-dot-v5``` into the folder ```state_fuzzing/bert/bert_pytorch```
```
cd state_fuzzing/bert
mkdir bert_pytorch
git lfs install
git clone https://huggingface.co/sentence-transformers/msmarco-bert-base-dot-v5
mv msmarco-bert-base-dot-v5/* ./bert_pytorch
```

Configure your neo4j desktop and start it locally. You can run the desktop directly or start it from the command line.

```
cd Neo4j/bin
./neo4j start
```

Configure your username and password and remember them. Replace them  in ```util/conf.py```
```
NEO4J_URL = "bolt://localhost:7474" or NEO4J_URL = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "<Your Password>"
self.graph = ProtocolGraph(NEO4J_URL, NEO4J_USER, NEO4J_PASSWORD)
```
Configure your deepseek_api_key and openai_api_key in ```util/conf.py```.

```
DEEPSEEK_API_KEY = "<Your Deepseek API Key>"
OPENAI_API_KEY = "<Your OPENAI API Key>"
```

## Step 2: HA Configuration

1. Install Ubuntu 20.04 virtual machine

2. Confirm that KVM virtualisation is enabled.

```lsmod | grep kvm```

If the module is not loaded, you can execute the following command

``` (For Intel) sudo modprobe kvm_intel ```

``` (For AMD) sudo modprobe kvm_amd ```

3. Install Docker on Ubuntu

4. Install HA from docker-compose.yaml

```
cd home_assistant
docker-compose up -d
```
5. Build Zigbee Home Automation(ZHA) integrations

https://www.home-assistant.io/integrations/zha/

6. Message traffic record

(1) Plug in Nortek GoControl QuickStick HUSBZB-1

Choose port ```/dev/ttyUSB0``` for Zigbee instead of  ```/dev/ttyUSB1``` for Z-Wave

(2) Paring the devices

(3) Send the packets to device using GUI and capture the traffic using the following Step 3 method

## Step 3: Traffic Capture Settings

1. Download TiWsPc Tools and CC2531 Driver

TiWsPc Tools: http://www.ti.com/tool/TIMAC

CC2531 Driver Download Path: ```/driver```

2. Plug in CC2531 USB Dongle, click ‘Device Configuration’ to select and configure the CC2531 hardware.

3. The only parameter that needs to be configured is the channel in ‘Configuration’, which must match the channel used by the fuzzer to send packets.

The channel on which the fuzzer runs will be explained in the subsequent execution.

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc4.png)

4. Save packets to /state_aware/result/traffic as the ground truth of message formats. (Just for evaluation)

4.1 Display the captured packets in real time.

Specify the pipe method in TiWsPc to transfer the captured packets to Wireshark. 

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc1.PNG)

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc2.PNG)

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc3.PNG)

4.2 Decrypt Zigbee packets.

(1) First paste common-used factory-programmed Zigbee link key into Wireshark preference -> protocol -> Zigbee -> Pre-configured Keys.

A common-used key: 5a6967426565416c6c69616e63653039. Others can be obatined from online blogs. 

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc5.png)

Thus you can see the plaintext content of the messages during the pairing phase, but the communication phase is still encrypted.

(2) Obtain the traffic from the pairing(commissioning) phase. Locate the Transport Key message and copy the key value from its fields.

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/traffic.jpg)

(3) Paste the key value into wireshark preferences setup same as the first step.


## Quick Deployment

Build from Dockerfile or pull images from DockerHub

```
# Local Build
docker build -t zvdetector .
docker run -it -d --name fuzzing --privileged --device:/dev/ttyUSB0:/dev/ttyUSB0 --network host zvdetector

# Remote Build
docker pull thulh/zvdetector
docker run -it -d --name fuzzing --privileged --device:/dev/ttyUSB0:/dev/ttyUSB0 --network host thulh/zvdetector

```

# Compile Methods

## Start Fuzzing

Run ZVDetector just by using the following commands.

```
cd state_fuzzing
python fuzzer.py -c 20 -d 15 -l -o network.json <fuzzer USB port>
```
where ```-c``` specify the channel, ```-d``` specify the permit duration in paring phase, ```-l``` specify whether use the last moment state, ```-r``` specify whether reset the network, ```-i``` specify the input network file to flash,   ```-o``` specify the file path to store the network information. Load historical state can prevent reparing the device after rebooting the fuzzer. 

(1) Commissioning Phase

Pairing the device with fuzzer during the permit time windows.

Fuzzer will automatically analyze the cluster, node descriptor and simple descriptor of each device. Saved at ```/library```

(2) Communication Phase

Analyze the message formats, dependencies and correlations. 

If these are analyzed before, ZVDetector directly use the results. Saved at ```/state_aware/results```

Generate fuzzing graph in Neo4j graph database.

(3) Combined State Fuzzing

Device State Saved at ```/library/device_state_db```

Log Record at ```fuzz.log```

Crash Record at ```/state_fuzzing/crash```

Generated fuzzing message sequeces by strategy b and strategy c can be downloaded from https://cloud.tsinghua.edu.cn/d/45415aa112384fb0b8e6/
or can be generated by ```enabling potential_state_discovery_done=False``` in  ```util/conf.py```

Many results can be directly reused. If you want to rerun them, you can set the corresponding parameter in SUPPORT_MODE in the ```util/conf.py``` file.

```
SUPPORT_MODE = {
    "format_generated": True,
    "corr_discovery_done": True,
    "dependency_analysis_done": True,
    "basic_graph_done": False,
    "potential_state_discovery_done": True,
    "hidden_attributes_done": True,
    "attribute_permission_done": True
}
```

```format_generated```: Message Format generation

```corr_discovery_done```: Correlation analysis

```dependency_analysis_done```: Dependency analysis from pcap traffic

```basic_graph_done```: Basic Protocol state construction

```potential_state_discovery_done```: Discover potential protocol state by applying strategy (a)-(c)

```hidden_attributes_done```: Discover hidden attributes

```attribute_permission_done```: Analyze attribute permissions

# Fuzzing Videos

We have recorded the running process of ZVDetector in the link below. You may preview and download it.

https://chimn6bz7u.feishu.cn/wiki/BBnawnPIFitUhTkRK1Xcb3QUn2g

# Protocol Extension

We have already applied it to some ZWave tasks. See ```/extension``` Folder. 

We also encourage developers to collaborate to extend to other IoT protocols.

# Found Vulnerabilities

Tuya Zigbee Smart Plug(ID=3): CVE-2024-*****

Tuya Zigbee Smart Bulb(ID=4): CVE-2024-****, CVE-2024-*****

Sengled Zigbee Smart Switch(ID=5): CVE-2023-*****

Sengled Zigbee Smart Bulb(ID=6): CVE-2022-47100, CVE-2024-*****

Sengled Zigbee Smart Strip(ID=7): CVE-2022-47100, CVE-2024-*****

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/vulnerability.png)
