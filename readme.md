# ZVDetector: State-Guided Vulnerability Detection System for Zigbee Devices

![image](https://github.com/ZVDetector/ZVDetector/blob/master/arch.png)


# Found Vulnerabilities

![image](https://github.com/ZVDetector/ZVDetector/blob/master/testbed.png)

Tuya Zigbee Smart Plug(ID=3) - TS011F: CVE-2024-*****

Tuya Zigbee Smart Bulb(ID=4) TS0505B: CVE-2024-*****, CVE-2024-*****

Sengled Zigbee Smart Switch(ID=5): CVE-2023-*****

Sengled Zigbee Smart Bulb(ID=6): CVE-2022-47100, CVE-2024-*****

Sengled Zigbee Smart Strip(ID=7): CVE-2022-47100, CVE-2024-*****

![image](https://github.com/ZVDetector/ZVDetector/blob/master/vulnerability.png)

# Running Environment

![image](https://github.com/ZVDetector/ZVDetector/blob/master/testbed.png)

# Install From Source
```
git clone https://github.com/ZVDetector/ZVDetector.git
```

Docker will be available soon.

# Build Home Assistant (Docker)

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
