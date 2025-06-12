# ZVDetector: State-Guided Vulnerability Detection System for Zigbee Devices

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/arch.png)


# Found Vulnerabilities

Tuya Zigbee Smart Plug(ID=3) - TS011F: CVE-2024-*****

Tuya Zigbee Smart Bulb(ID=4) TS0505B: CVE-2024-*****, CVE-2024-*****

Sengled Zigbee Smart Switch(ID=5): CVE-2023-*****

Sengled Zigbee Smart Bulb(ID=6): CVE-2022-47100, CVE-2024-*****

Sengled Zigbee Smart Strip(ID=7): CVE-2022-47100, CVE-2024-*****

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/vulnerability.png)

# Running Environment

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/testbed.png)

## Step 1: Fuzzer Configuration

For the fuzzer, you can also directly deploy on MACOS since Unix-like 

```ls -l /dev/ttyUSB*``` (Ubuntu)

```ls -l /dev/tty.usbserial*``` (MACOS)

USB port shows like: ```crw-rw-rw-  1 root  wheel  0x9000002 Jun 12 10:47 /dev/tty.usbserial-14110```

Install From Source
```
git clone https://github.com/ZVDetector/ZVDetector.git
```

Python Environment 3.8.3 and Requirements

```pip install -r requirements.txt```


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

## Step 3: Traffic Capture Settings

1. Dowload TiWsPc Tools
http://www.ti.com/tool/TIMAC

2. Click ‘Device Configuration’ to select and configure the CC2531 USB Dongle hardware.

3. The only parameter that needs to be configured is the channel in ‘Configuration’, which must match the channel used by the fuzzer to send packets.

The channel on which the fuzzer runs will be explained in the subsequent execution.

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc4.PNG)

4. Save packets to /state_aware/result/traffic as the ground truth of message formats.

Q：Can the captured packets be displayed in real time?

A：Specify the pipe method in TiWsPc to transfer the captured packets to Wireshark. 

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc1.PNG)

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc2.PNG)

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc3.PNG)

Q: How to decrypt Zigbee packets?

A: 
First you can paste common-used factory-programmed Zigbee link key into Wireshark preference -> protocol -> Zigbee -> Pre-configured Keys.
A common-used key: 5a6967426565416c6c69616e63653039
Others can be obatined from online blogs.

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/tc5.PNG)

You need to obtain the traffic from the pairing(commissioning) phase.
Locate the Transport Key message and copy the key value from its fields.

![image](https://github.com/ZVDetector/ZVDetector/blob/master/figure/traffic.jpg)

Paste the key value into wireshark preferences setup.


# Quick Deployment
Docker will be available soon.

# Protocol Extension
We have already applied it to some ZWave tasks. See Z-Wave Folder.

We also encourage developers to collaborate to extend to other IoT protocols.
