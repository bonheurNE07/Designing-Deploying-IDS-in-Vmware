# 🛡️ Intrusion Detection and Prevention Systems (IDS/IPS) – VMware Virtual Lab

## ¶ Abstract

This project demonstrates the **design, deployment, configuration, and evaluation** of an Intrusion Detection and Prevention System (**IDS/IPS**) using **Suricata** inside a **VMware-based virtual lab**. The lab setup includes:

* **Ubuntu VM** running Suricata as the network-based IDS/IPS sensor
* **Kali Linux VM** acting as the attacker
* **Windows Host & GNS3 Server** as target systems

The objective is to show how IDS/IPS tools detect and prevent common network attacks, how Suricata is installed and tuned, and how attack simulations can be reproduced and validated. The report also includes best practices, observations, and recommendations for future improvements.

---

## ¶ Table of Contents

1. [Introduction](#-introduction)
2. [Objectives](#-objectives)
3. [Background and Terminology](#-background-and-terminology)
4. [System Architecture and Design Choices](#-system-architecture-and-design-choices)
5. [VMware Lab Topology and Networking Options](#-vmware-lab-topology-and-networking-options)
6. [Suricata: Installation, Configuration, and Rule Management](#-suricata-installation-configuration-and-rule-management)
7. [Detection Techniques, Rules, and Tuning](#-detection-techniques-rules-and-tuning)
8. [Simulation Scenarios and Validation](#-simulation-scenarios-and-validation)
9. [Observations, Results, and Analysis](#-observations-results-and-analysis)
10. [Incident Response Playbook](#-incident-response-playbook)
11. [Limitations, Risks, and Mitigations](#-limitations-risks-and-mitigations)
12. [Recommendations and Future Work](#-recommendations-and-future-work)
13. [References](#-references)

---

## ¶ Introduction

Virtualization tools like **VMware** allow the creation of isolated, reproducible environments for testing network security tools. This project sets up **Suricata** as a **Network Intrusion Detection System (NIDS)** to monitor traffic between a **Kali Linux attacker** and a **Windows target**.
The project focuses on:

* Installing and configuring Suricata
* Capturing and analyzing network traffic
* Writing and tuning IDS rules
* Running controlled attack scenarios and validating alerts

---

## ¶ Objectives

* Design a VMware-based lab suitable for IDS/IPS testing
* Install and configure Suricata with JSON logging enabled
* Demonstrate detection of attacks like **port scans**, **exploit attempts**, and **suspicious file downloads**
* Document simulation steps and expected results
* Analyze logs and evidence collected during attacks

---

## ¶ Background and Terminology

* **IDS (Intrusion Detection System):** Monitors network or host activity for suspicious behavior.
* **NIDS:** Network-based IDS (e.g., Suricata, Snort).
* **HIDS:** Host-based IDS (e.g., OSSEC, Wazuh).
* **IPS:** Intrusion Prevention System – actively blocks malicious traffic.
* **False Positive/Negative:** Incorrect detections or missed threats.
* **Promiscuous Mode:** Allows a NIC to capture all traffic for analysis.

---

## ¶ System Architecture and Design Choices

* **Kali Linux:** Attacker VM for scans and exploits
* **Ubuntu 24.04:** Suricata IDS/IPS sensor
* **Windows / GNS3 Server:** Target machines
* **VMware Workstation Pro:** Virtualization platform

The Suricata sensor is placed on the same virtual network as attacker and target to capture and inspect all traffic.

---

## ¶ VMware Lab Topology

* Internal host-only network for isolation
* Sensor VM configured in **promiscuous mode**
* Bridged mode used selectively to test real host interactions

**Networking Steps:**

1. Create internal network (LabNet)
2. Connect Kali, GNS3, and Ubuntu to LabNet
3. Enable promiscuous mode on Suricata sensor NIC
4. Ensure Suricata has raw interface access

---

## ¥ Suricata: Installation & Configuration

### Installation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y suricata suricata-update jq tcpdump
sudo systemctl enable --now suricata
sudo suricata-update
```

### Configuration

Edit `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: ens33
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

Enable JSON logging:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
      types: [alert, http, dns, tls, files, flow]
```

Test and restart:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

---

## ¶ Detection Rules & Tuning

Example custom rule (ICMP Ping Sweep):

```bash
alert icmp any any -> any any (msg:"ICMP Ping Sweep Detected"; itype:8; threshold:type both, track by_src, count 6, seconds 60; sid:1000002; rev:1;)
```

Other examples:

* Nmap SYN scan detection
* HTTP GET request alert
* Suspicious file download

Tuning involves baselining, triaging alerts, and adjusting noisy rules.

---

## ¶ Simulation Scenarios & Validation

**Scenario 1 – Port Scanning:**

```bash
nmap -sS -p1-1024 <target-ip>
```

✓ Expect TCP SYN scan alerts in `eve.json`.

**Scenario 2 – Suspicious File Download:**

```bash
curl -O http://<target-ip>/malware_test.pdf
```

✓ Expect alerts on file metadata and extraction logs.

---

## ⁜ Observations & Analysis

* Some signatures may trigger false positives
* Proper network capture configuration is essential
* CPU and thread tuning improves performance
* Logs can be correlated with `tcpdump` or `Wireshark` captures

---

## ¶ Incident Response Playbook

1. Identify & Validate alerts
2. Contain by isolating attacker VM
3. Collect evidence (EVE logs, PCAPs)
4. Analyze network and host events
5. Remediate and reset lab
6. Review and tune rules

---

## ⚠️ Limitations & Risks

* Virtualization artifacts may affect timing and signatures
* Scope limited to basic attacks, not advanced threats
* Avoid bridging lab network to production environments

---

## ⁛ Recommendations & Future Work

* Combine Suricata NIDS with HIDS (e.g., Sysmon, Wazuh)
* Use ELK/Splunk for centralized log visualization
* Automate rule updates with `suricata-update`
* Explore complex topologies with **GNS3** or **EVE-NG**

---

## ⁜ References

* [Suricata Documentation](https://docs.suricata.io/)
* [suricata-update Tool](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)
* [VMware Networking Docs](https://community.spiceworks.com/t/vmware-promiscuous-mode/260055/6)
* [Nmap Documentation](https://nmap.org/book/man.html)
* [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [Wireshark Docs](https://www.wireshark.org/docs/)
