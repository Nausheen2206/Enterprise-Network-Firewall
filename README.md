# Enterprise Network Firewall

A protocol filtering firewall simulation designed to control network traffic across enterprise infrastructure based on ICMP, TCP, and UDP protocols.

## Authors
* **Nausheen E** (24PW13)
* **Anjana Kannan** (24PW05)

---

## Project Overview
This project focuses on the design and simulation of a Protocol Filtering Firewall to secure and control network traffic. The system demonstrates how distinct traffic types—including ICMP ping requests, TCP web access, and UDP DNS queries—can be selectively allowed or blocked using Access Control Lists (ACLs) to enhance overall network security.

The simulated enterprise network implements standard structural designs including VLAN segmentation, inter-VLAN routing, and controlled internet access via Network Address Translation (NAT). By leveraging protocol-based filtering alongside secure remote management protocols, this project highlights how modern organizations can safeguard critical internal resources while maintaining necessary external network services.

---

## Core Features

### Protocol-Based Traffic Filtering
* **ICMP Control:** Rules to permit or deny ping requests and diagnostic messages.
* **TCP Control:** Fine-grained traffic management for web applications (HTTP/HTTPS) and secure terminal access.
* **UDP Control:** Traffic filtering for stateless connections such as DNS queries.

### Network Architecture and Security
* **Access Control Lists (ACLs):** Custom rulesets configured to regulate inbound and outbound interface traffic.
* **IP Filtering:** Native mechanisms for explicit blacklisting and whitelisting of host systems.
* **VLAN Segmentation:** Logical isolation of network segments to minimize broadcast domains and isolate departments.
* **Inter-VLAN Routing:** Core routing capabilities configured to handle authorized traffic passing between separate VLANs.

### Network Services and Infrastructure
* **NAT with PAT:** Network Address Translation combined with Port Address Translation to securely share public IP allocations.
* **DHCP Configuration:** Automated IP address distribution rules managed across specific subnets.
* **SSH-Based Secure Access:** Encrypted remote terminal channels configured for administrative device management.
* **Server Simulation:** Dedicated hosting environments configured to simulate real-world DNS and HTTP application services.

---

## Architecture and Technical Stack
* **Simulation Environment:** [e.g., Cisco Packet Tracer]
* **Routing Protocols:** Inter-VLAN Routing (Router-on-a-Stick / Layer 3 Switching)
* **Security Layer:** Standard and Extended Access Control Lists (ACLs)

---

## Installation and Deployment
1. Clone the repository to your system:
   ```bash
   git clone https://github.com
   cd Enterprise-Network-Firewall
   ```
2. Open the network topology configuration file inside your simulation software tool:
   * File path: `[e.g., topology/network_backup.pkt]`

---

## License
This project is developed for educational and evaluation purposes.