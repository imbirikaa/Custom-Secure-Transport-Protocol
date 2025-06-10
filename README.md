# Advanced Secure File Transfer System
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Scapy](https://img.shields.io/badge/scapy-2.5.0-orange.svg)
![CustomTkinter](https://img.shields.io/badge/gui-customtkinter-green.svg)
![Cryptography](https://img.shields.io/badge/crypto-pycryptodome-red.svg)

A custom network protocol for secure and reliable file transfer, built from the ground up to demonstrate low-level networking, security, and performance analysis concepts.

---

## 📖 Project Overview

This project is an **Advanced Secure File Transfer System** developed for the Computer Networks course (BLM0326) at Bursa Teknik Üniversitesi. It features a custom, reliable network protocol built over UDP to transfer files securely between a client and a server.

The system provides a hands-on implementation of low-level networking concepts by manually handling data fragmentation, ensuring reliable delivery through a sliding window and acknowledgement mechanism, and integrating a robust security layer for confidentiality and integrity. The entire system is controlled via a modern Graphical User Interface (GUI) built with CustomTkinter that provides real-time visualization of the transfer process.

This repository contains the complete source code for the client, server, and a Man-in-the-Middle (MITM) attack simulation tool.



---

## ✨ Core Features

This application successfully implements all mandatory requirements outlined in the project description, plus bonus features.

#### Protocol & Reliability

* 📦 **Custom Application-Layer Protocol**: Uses a unique `FileTransferHeader` to manage file transfers, encapsulating all necessary metadata.

* 🧩 **Manual Fragmentation & Reassembly**: Manually fragments files of any size into smaller chunks and correctly reassembles them at the destination, even if packets arrive out of order.

* 🔄 **Reliable Delivery (Sliding Window & RTO)**: Implements a sliding window protocol with acknowledgements (ACKs) and a Retransmission Timeout (RTO) to ensure lost or dropped packets are automatically resent.

#### Security

* 🔒 **Confidentiality (AES-256)**: Encrypts the entire file content using AES-256 in CBC mode, making the data unreadable to network eavesdroppers.

* 🔐 **Data Integrity (SHA-256)**: Verifies a SHA-256 hash of the received file against the original hash to guarantee the file has not been tampered with or corrupted.

* 🔑 **Authentication**: Uses a pre-shared key model where the client is authenticated by its knowledge of the secret AES key.

#### Low-Level Networking & Visualization

* 🔬 **Custom Packet Crafting**: Utilizes the Scapy library to build custom packets from the IP layer upwards.

* 🧮 **Manual Checksum Demonstration**: Includes a function for manually calculating the standard IP header checksum and a self-test on the server GUI to prove its correctness.

* 🗺️ **Live Transfer Visualization (GUI)**: A modern GUI provides a real-time "Fragment Map" that visualizes the state of each packet (Sent, ACKed, Retransmitting).

* 📊 **Performance Metrics:** The client automatically measures and logs the Round-Trip Time (RTT) and effective bandwidth (in Mbps) for every transfer.

---

## 🛠️ Technology Stack

| Component | Technology / Library | Purpose | 
| :--- | :--- | :--- |
| **Language** | Python 3 | Core programming language. | 
| **Packet Crafting** | Scapy | Creating, sending, and sniffing custom network packets. | 
| **Graphical UI** | CustomTkinter | Building a modern, themed, and user-friendly GUI. | 
| **Cryptography** | PyCryptodome | AES-256 encryption and secure random number generation. | 
| **Hashing** | `hashlib` | Generating SHA-256 hashes for data integrity. | 

---

## 🚀 Setup and Usage Guide

Follow these steps to set up and run the application suite.

### Step 1: Prerequisites

Ensure you have Python 3 installed. Then, install the required libraries from `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Step 2: Network Configuration

Before running, configure the IP addresses and network interfaces at the top of each script (`client.py`, `server.py`, `MITM.py`).

**For a Host-VM setup (Windows Host + Kali VM):**

1. In VirtualBox, set the VM's network to **"Host-only Adapter"** and enable the DHCP server.
2. Find the IP addresses and interface names for both machines.
3. Update the scripts accordingly:

   * **`server.py` (on Windows):**
     ```python
     LOOPBACK_INTERFACE = "VirtualBox Host-Only Ethernet Adapter"
     SERVER_IP = '192.168.56.1' # Use the server's Host-Only IP
     ```

   * **`client.py` & `mitm_gui.py` (on Kali):**
     ```python
     LOOPBACK_INTERFACE = "eth0"
     SERVER_IP = '192.168.56.1' # Must be the server's IP
     ```

### Step 3: Running the Application

**Important:** On Linux, the scripts must be run with `sudo` to allow low-level network sniffing.

1. **Start the Server:** On the server machine, run the script.
   ```bash
   python server.py
   ```
   Click **"Start Server"**.

2. **Start the Client:** On the client machine, run with `sudo`.
   ```bash
   sudo python3 client.py
   ```
   Copy the AES key from the server, paste it into the client, select a file, and click **"Send File"**.

---

## 🔬 Demonstrating Project Requirements

This section provides a guide for demonstrating that all project goals have been met.

#### 1. Normal Transfer & Visualization

Run a normal file transfer. Narrate the process by pointing to the logs and the **Fragment Map** in the client GUI, explaining the color codes (blue for sent, green for ACKed).


#### 2. Security Analysis

* **Encryption Validation (Wireshark):**
  1. Start a Wireshark capture on the server's interface with the filter `udp.port == 5001`.
  2. Perform a transfer.
  3. Show the packet details in Wireshark and point out that the UDP payload is unreadable ciphertext.

* **Integrity Check (MITM Attack):**
  1. Start the server, then start the **`MITM.py`** tool (with `sudo` on Linux).
  2. Click **"Start 'One-Shot' Attack"**.
  3. Start a file transfer from the client.
  4. Show the server log, pointing to the **`ERROR: Decryption/Save error...`** message. Explain that the system correctly detected the tampered data and aborted the transfer.

#### 3. Low-Level Processing & Performance

* **Manual Checksum Proof:** On the server GUI, click the **"Run Checksum Test"** button and show the log output proving that your manual calculation matches Scapy's.

* **Performance Under Stress:** On the client machine (Kali), apply a packet loss rule with `tc`:
  ```bash
  sudo tc qdisc add dev eth0 root netem loss 5%
  ```
  Perform a transfer and point to the **red squares** in the Fragment Map, explaining that they represent retransmissions. After the transfer, show the degraded bandwidth and RTT stats in the log. Remember to remove the rule afterwards (`sudo tc qdisc del dev eth0 root`).
