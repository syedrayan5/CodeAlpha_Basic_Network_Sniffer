# Network Sniffer in Python

## Objective:
This project implements a basic network packet sniffer in Python using the `scapy` library. The sniffer captures and analyzes network traffic, providing insights such as source and destination IP addresses, as well as source and destination ports for TCP and UDP packets. The script works on Windows and can be customized to monitor specific network interfaces.

## Key Features:
- Capture and display network packets in real-time.
- Extract and display source and destination IP addresses.
- Extract and display source and destination ports for TCP and UDP packets.
- Allows the user to specify the network interface for sniffing (e.g., Wi-Fi, Ethernet).
- Option to stop the sniffer after capturing a fixed number of packets or after a specified duration.

## Libraries Used:
- **scapy**: A powerful Python library used for network packet sniffing and analysis. It allows manipulation of network layers and crafting of packets.

You can install this library using the following command:
pip install scapy

## Instructions for Usage:
- Install Required Libraries: To get started, you'll need to install scapy. Use the following command:
pip install scapy

- Download and Install Npcap:

- To capture packets on Windows, you need to install Npcap (a Windows packet capture library).
 - Download and install Npcap from Npcap website.
 - Ensure that the "Install Npcap in WinPcap API-compatible Mode" option is selected during installation.
 - Run the Script:

- Open a terminal with Administrator privileges (Right-click the terminal and choose "Run as Administrator").
Run the Python script using:
python sniffer.py

- Choose Network Interface:
The script will display a list of available network interfaces on your system.

- Enter the name of the interface you wish to sniff on, e.g., Ethernet or Wi-Fi.
- Sniffer Output:

The sniffer will capture and display packet details, such as:
Source IP and destination IP.
Source and destination ports for TCP and UDP packets.
You can also modify the script to capture a fixed number of packets or specify a timeout.
Stopping the Sniffer:

By default, the sniffer will run indefinitely, capturing packets in real-time.
To stop the sniffer, press Ctrl + C in the terminal.
