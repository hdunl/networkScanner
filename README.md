# Network Scanner Tool

## Introduction
This tool is designed to scan a network for active devices using ARP requests, leveraging Python's powerful threading and concurrency features to perform fast and efficient scans. It utilizes raw sockets and network protocols to analyze the network traffic.

## Requirements
The Network Scanner requires Python 3 and the following Python libraries:
- `threading`: Built-in Python module for threading.
- `scapy`: A powerful Python-based interactive packet manipulation program and library.
- `ipaddress`: Built-in Python module to create, manipulate and operate on IPv4 and IPv6 addresses and networks.
- `socket`: Built-in Python module that provides access to the BSD socket interface.
- `requests`: Simple HTTP library for Python, built for human beings.
- `concurrent.futures`: Built-in Python module for launching parallel tasks.

## Installation
To run the Network Scanner, you must have Python 3 installed on your system. If you don't have Python 3, download and install it from the official website.

Once Python is installed, you can install the required third-party libraries using `pip`. Run the following commands in your terminal:

```sh
pip install scapy
pip install requests
```

No installation is required for the `threading`, `ipaddress`, `socket`, and `concurrent.futures` modules as they are included in the Python Standard Library.

## Usage
After installing the required libraries, you can run the script from your terminal. Ensure you have the necessary permissions to send ARP requests on your network.

