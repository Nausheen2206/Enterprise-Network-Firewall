"""
Enterprise Network Firewall Simulation
=======================================
Simulates: Protocol Filtering Firewall, ACL engine, VLAN segmentation,
Inter-VLAN routing, NAT/PAT, DHCP, DNS, HTTP services, SSH admin.
"""

import ipaddress
import random
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ─────────────────────────────────────────────
#  ENUMS & CONSTANTS
# ─────────────────────────────────────────────

class Protocol(Enum):
    TCP  = "TCP"
    UDP  = "UDP"
    ICMP = "ICMP"
    ANY  = "ANY"

class Action(Enum):
    ALLOW = "ALLOW"
    DENY  = "DENY"

VLAN_CONFIG = {
    10: {"name": "ADMIN", "network": "192.168.10.0/24", "gateway": "192.168.10.1"},
    20: {"name": "HR",    "network": "192.168.20.0/24", "gateway": "192.168.20.1"},
    30: {"name": "IT",    "network": "192.168.30.0/24", "gateway": "192.168.30.1"},
}

COLORS = {
    "reset":  "\033[0m",
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "purple": "\033[95m",
    "gray":   "\033[90m",
}

def c(color, text): return f"{COLORS[color]}{text}{COLORS['reset']}"


# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────

@dataclass
class Packet:
    src_ip:   str
    dst_ip:   str
    protocol: Protocol
    src_port: int = 0
    dst_port: int = 0
    payload:  str = ""

    def __str__(self):
        port_info = f":{self.dst_port}" if self.dst_port else ""
        return f"{self.src_ip} -> {self.dst_ip} [{self.protocol.value}{port_info}]"


@dataclass
class ACLRule:
    seq:      int
    action:   Action
    protocol: Protocol
    src_net:  str
    dst_net:  str
    dst_port: Optional[int] = None
    description: str = ""

    def matches(self, pkt: Packet) -> bool:
        if not self._ip_matches(pkt.src_ip, self.src_net):
            return False
        if not self._ip_matches(pkt.dst_ip, self.dst_net):
            return False
        if self.protocol != Protocol.ANY and self.protocol != pkt.protocol:
            return False
        if self.dst_port is not None and self.dst_port != pkt.dst_port:
            return False
        return True

    @staticmethod
    def _ip_matches(ip: str, net: str) -> bool:
        if net == "any":
            return True
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
        except ValueError:
            return ip == net


@dataclass
class NATEntry:
    inside_local:  str
    inside_global: str = "203.0.113.2"
    protocol:      Protocol = Protocol.TCP
    local_port:    int = 0
    global_port:   int = 0
    state:         str = "ACTIVE"
    created_at:    str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


@dataclass
class DHCPLease:
    ip:         str
    mac:        str
    hostname:   str
    vlan:       int
    gateway:    str
    dns:        str = "192.168.30.50"
    expires_at: str = "24h"


@dataclass
class LogEntry:
    timestamp: str
    action:    Action
    packet:    Packet
    acl_seq:   int
    reason:    str
    natted:    bool = False


# ─────────────────────────────────────────────
#  DHCP SERVER
# ─────────────────────────────────────────────

class DHCPServer:
    def __init__(self):
        self.leases: dict = {}
        self._pools: dict = {}
        self._init_pools()
        self._seed_leases()

    def _init_pools(self):
        for vlan_id, cfg in VLAN_CONFIG.items():
            net = ipaddress.ip_network(cfg["network"], strict=False)
            self._pools[vlan_id] = [str(h) for h in list(net.hosts())[9:200]]

    def _seed_leases(self):
        devices = [
            ("AA:BB:CC:DD:EE:01", "admin-pc1", 10),
            ("AA:BB:CC:DD:EE:02", "admin-pc2", 10),
            ("AA:BB:CC:DD:EE:03", "hr-pc3",    20),
            ("AA:BB:CC:DD:EE:04", "hr-pc4",    20),
            ("AA:BB:CC:DD:EE:05", "it-pc5",    30),
        ]
        for mac, hostname, vlan in devices:
            self.request_lease(mac, hostname, vlan)

    def request_lease(self, mac: str, hostname: str, vlan_id: int) -> Optional[DHCPLease]:
        if mac in self.leases:
            return self.leases[mac]
        pool = self._pools.get(vlan_id, [])
        used = {l.ip for l in self.leases.values()}
        available = [ip for ip in pool if ip not in used]
        if not available:
            return None
        ip = available[0]
        cfg = VLAN_CONFIG[vlan_id]
        lease = DHCPLease(ip=ip, mac=mac, hostname=hostname,
                          vlan=vlan_id, gateway=cfg["gateway"])
        self.leases[mac] = lease
        return lease

    def show_leases(self):
        print(c("bold", "\n+-- DHCP Lease Table " + "-"*46 + "+"))
        print(f"  {'IP':<18} {'MAC':<20} {'Hostname':<18} {'VLAN':<8} Gateway")
        print("  " + "-"*70)
        for lease in self.leases.values():
            vlan_name = VLAN_CONFIG[lease.vlan]["name"]
            print(f"  {lease.ip:<18} {lease.mac:<20} {lease.hostname:<18} "
                  f"VLAN{lease.vlan}({vlan_name})   {lease.gateway}")


# ─────────────────────────────────────────────
#  DNS SERVER
# ─────────────────────────────────────────────

class DNSServer:
    def __init__(self):
        self.records: dict = {
            "enterprise.local": "192.168.30.50",
            "admin.local":      "192.168.10.1",
            "hr.local":         "192.168.20.1",
            "it.local":         "192.168.30.1",
            "dhcp.local":       "192.168.10.100",
            "web.local":        "192.168.30.50",
            "google.com":       "142.250.80.46",
            "cloudflare.com":   "104.16.133.229",
        }

    def resolve(self, hostname: str) -> Optional[str]:
        return self.records.get(hostname.lower())

    def query(self, pkt: Packet) -> str:
        hostname = pkt.payload or "enterprise.local"
        result = self.resolve(hostname)
        if result:
            return c("green", f"  [DNS] {hostname} -> {result}")
        return c("red", f"  [DNS] NXDOMAIN: '{hostname}' not found")

    def show_records(self):
        print(c("bold", "\n+-- DNS Zone Records " + "-"*36 + "+"))
        print(f"  {'Hostname':<28} IP Address")
        print("  " + "-"*48)
        for name, ip in self.records.items():
            print(f"  {name:<28} {ip}")


# ─────────────────────────────────────────────
#  HTTP SERVER
# ─────────────────────────────────────────────

class HTTPServer:
    PAGES = {
        "/":          ("200 OK",        "Welcome to Enterprise Portal"),
        "/admin":     ("200 OK",        "Admin Dashboard - Restricted"),
        "/hr":        ("200 OK",        "HR Self-Service Portal"),
        "/it":        ("200 OK",        "IT Helpdesk Portal"),
        "/forbidden": ("403 Forbidden", "Access Denied"),
    }

    def handle(self, pkt: Packet) -> str:
        path = pkt.payload or "/"
        status, body = self.PAGES.get(path, ("404 Not Found", "Page not found"))
        color = "green" if status.startswith("2") else "red"
        return c(color, f"  [HTTP] {status} - {body}  (from {pkt.src_ip})")


# ─────────────────────────────────────────────
#  NAT/PAT ENGINE
# ─────────────────────────────────────────────

class NATEngine:
    PUBLIC_IP = "203.0.113.2"

    def __init__(self):
        self.table: list = []
        self._next_port = 1024

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def translate(self, pkt: Packet) -> Optional[NATEntry]:
        if not self._is_private(pkt.src_ip):
            return None
        if self._is_private(pkt.dst_ip):
            return None
        global_port = self._next_port
        self._next_port += 1
        entry = NATEntry(
            inside_local=pkt.src_ip,
            protocol=pkt.protocol,
            local_port=pkt.src_port or random.randint(49152, 65535),
            global_port=global_port,
        )
        self.table.append(entry)
        return entry

    def show_table(self):
        print(c("bold", "\n+-- NAT/PAT Translation Table " + "-"*44 + "+"))
        print(f"  {'Inside Local':<18} {'Inside Global':<18} {'Proto':<6} "
              f"{'L-Port':<8} {'G-Port':<8} State")
        print("  " + "-"*68)
        for e in self.table:
            print(f"  {e.inside_local:<18} {e.inside_global:<18} "
                  f"{e.protocol.value:<6} {e.local_port:<8} {e.global_port:<8} "
                  f"{c('green', e.state)}")
        if not self.table:
            print("  (no translations yet)")


# ─────────────────────────────────────────────
#  FIREWALL / ACL ENGINE
# ─────────────────────────────────────────────

class Firewall:
    def __init__(self):
        self.acl_rules = self._build_acl()
        self.blacklist  = {"10.10.10.99", "10.10.10.100"}
        self.whitelist  = {"192.168.10.0/24"}
        self.nat        = NATEngine()
        self.log: list  = []
        self.stats      = defaultdict(int)

    def _build_acl(self) -> list:
        return [
            ACLRule(10,  Action.DENY,  Protocol.ANY,  "10.10.10.99/32",  "any",
                    description="Blacklisted host"),
            ACLRule(20,  Action.ALLOW, Protocol.ICMP, "192.168.30.0/24", "any",
                    description="IT VLAN can ping anywhere"),
            ACLRule(30,  Action.DENY,  Protocol.ICMP, "192.168.20.0/24", "any",
                    description="Block HR ICMP outbound"),
            ACLRule(40,  Action.ALLOW, Protocol.TCP,  "192.168.10.0/24", "any",
                    dst_port=22, description="Admin SSH whitelisted"),
            ACLRule(50,  Action.DENY,  Protocol.TCP,  "any",             "any",
                    dst_port=22, description="Block SSH from non-admin"),
            ACLRule(60,  Action.ALLOW, Protocol.TCP,  "192.168.0.0/8",   "192.168.30.50/32",
                    dst_port=80, description="Internal HTTP to server"),
            ACLRule(70,  Action.ALLOW, Protocol.UDP,  "192.168.0.0/8",   "192.168.30.50/32",
                    dst_port=53, description="Internal DNS queries"),
            ACLRule(80,  Action.DENY,  Protocol.TCP,  "any",             "any",
                    dst_port=23, description="Block Telnet (insecure)"),
            ACLRule(90,  Action.DENY,  Protocol.TCP,  "any",             "any",
                    dst_port=21, description="Block FTP (insecure)"),
            ACLRule(100, Action.ALLOW, Protocol.TCP,  "192.168.0.0/8",   "any",
                    dst_port=443, description="Allow HTTPS outbound"),
            ACLRule(110, Action.ALLOW, Protocol.UDP,  "192.168.30.10/32","8.8.8.8/32",
                    dst_port=53, description="IT DNS to external"),
            ACLRule(120, Action.ALLOW, Protocol.ICMP, "192.168.10.0/24", "any",
                    description="Admin VLAN can ping"),
            ACLRule(999, Action.DENY,  Protocol.ANY,  "any",             "any",
                    description="Implicit deny all"),
        ]

    def evaluate(self, pkt: Packet):
        for rule in self.acl_rules:
            if rule.matches(pkt):
                return rule.action, rule
        return Action.DENY, self.acl_rules[-1]

    def process(self, pkt: Packet) -> dict:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        action, rule = self.evaluate(pkt)
        nat_entry = None
        if action == Action.ALLOW:
            nat_entry = self.nat.translate(pkt)
        entry = LogEntry(timestamp=ts, action=action, packet=pkt,
                         acl_seq=rule.seq, reason=rule.description,
                         natted=nat_entry is not None)
        self.log.append(entry)
        self.stats[action.value] += 1
        return {"action": action, "rule": rule, "nat_entry": nat_entry, "log": entry}

    def show_acl(self):
        print(c("bold", "\n+-- Access Control List " + "-"*57 + "+"))
        print(f"  {'Seq':<5} {'Action':<7} {'Proto':<6} {'Source':<22} "
              f"{'Destination':<18} {'Port':<6} Description")
        print("  " + "-"*82)
        for r in self.acl_rules:
            act_color = "green" if r.action == Action.ALLOW else "red"
            port_str = str(r.dst_port) if r.dst_port else "any"
            print(f"  {r.seq:<5} {c(act_color, r.action.value):<15} "
                  f"{r.protocol.value:<6} {r.src_net:<22} {r.dst_net:<18} "
                  f"{port_str:<6} {r.description}")

    def show_log(self, last_n: int = 20):
        print(c("bold", f"\n+-- Traffic Log (last {last_n}) " + "-"*50 + "+"))
        for entry in self.log[-last_n:]:
            act_color = "green" if entry.action == Action.ALLOW else "red"
            nat_tag = c("cyan", " [NAT]") if entry.natted else ""
            print(f"  {c('gray', entry.timestamp)}  "
                  f"{c(act_color, f'{entry.action.value:<6}')}  "
                  f"{entry.packet}{nat_tag}")
            print(f"  {'':13}  seq:{entry.acl_seq} - {entry.reason}")

    def show_stats(self):
        total = sum(self.stats.values())
        print(c("bold", "\n+-- Firewall Statistics ----+"))
        print(f"  Allowed  : {c('green', str(self.stats['ALLOW']))}")
        print(f"  Denied   : {c('red',   str(self.stats['DENY']))}")
        print(f"  Total    : {total}")
        print(f"  NAT hits : {c('cyan',  str(len(self.nat.table)))}")


# ─────────────────────────────────────────────
#  L3 SWITCH — INTER-VLAN ROUTING
# ─────────────────────────────────────────────

class L3Switch:
    def __init__(self):
        self.routing_table: list = []
        self._build_routes()

    def _build_routes(self):
        for vlan_id, cfg in VLAN_CONFIG.items():
            self.routing_table.append({
                "network": cfg["network"],
                "gateway": cfg["gateway"],
                "iface":   f"Vlan{vlan_id}",
                "vlan":    vlan_id,
            })
        self.routing_table.append({
            "network": "0.0.0.0/0",
            "gateway": "10.0.0.1",
            "iface":   "GigabitEthernet0/1",
            "vlan":    None,
        })

    def route(self, dst_ip: str) -> Optional[dict]:
        best, best_prefix = None, -1
        for route in self.routing_table:
            try:
                net = ipaddress.ip_network(route["network"], strict=False)
                if ipaddress.ip_address(dst_ip) in net:
                    if net.prefixlen > best_prefix:
                        best_prefix = net.prefixlen
                        best = route
            except ValueError:
                continue
        return best

    def get_vlan(self, ip: str) -> Optional[int]:
        route = self.route(ip)
        return route["vlan"] if route else None

    def show_routing_table(self):
        print(c("bold", "\n+-- L3 Switch Routing Table " + "-"*38 + "+"))
        print(f"  {'Network':<22} {'Gateway':<18} {'Interface':<26} VLAN")
        print("  " + "-"*68)
        for r in self.routing_table:
            vlan_str = str(r["vlan"]) if r["vlan"] else "--"
            print(f"  {r['network']:<22} {r['gateway']:<18} {r['iface']:<26} {vlan_str}")


# ─────────────────────────────────────────────
#  SSH ADMIN MODULE
# ─────────────────────────────────────────────

class SSHAdmin:
    ALLOWED_SUBNET = "192.168.10.0/24"
    CREDENTIALS    = {"admin": "Admin@1234"}

    @classmethod
    def authenticate(cls, src_ip: str, username: str, password: str) -> bool:
        try:
            in_subnet = ipaddress.ip_address(src_ip) in \
                        ipaddress.ip_network(cls.ALLOWED_SUBNET, strict=False)
        except ValueError:
            in_subnet = False
        return in_subnet and cls.CREDENTIALS.get(username) == password

    @classmethod
    def show_banner(cls, src_ip: str, username: str = "admin", password: str = "Admin@1234"):
        ok = cls.authenticate(src_ip, username, password)
        if ok:
            print(c("green",  f"  [SSH] Authentication successful from {src_ip}"))
            print(c("cyan",   "  [SSH] Welcome to Enterprise Firewall -- IOS 15.7"))
            print(c("gray",   "  [SSH] Session: AES-256 / RSA-2048 / SHA-2"))
        else:
            print(c("red",    f"  [SSH] Authentication FAILED from {src_ip}"))
            print(c("red",    "  [SSH] Source not in Admin VLAN or bad credentials"))


# ─────────────────────────────────────────────
#  ENTERPRISE NETWORK ORCHESTRATOR
# ─────────────────────────────────────────────

class EnterpriseNetwork:
    def __init__(self):
        self.firewall = Firewall()
        self.switch   = L3Switch()
        self.dhcp     = DHCPServer()
        self.dns      = DNSServer()
        self.http     = HTTPServer()
        self.ssh      = SSHAdmin()

    def _header(self, title: str):
        print("\n" + c("bold", "=" * 64))
        print(c("bold", f"  {title}"))
        print(c("bold", "=" * 64))

    def send_packet(self, pkt: Packet, verbose: bool = True) -> dict:
        if verbose:
            print(f"\n  {c('gray', '>>')} {c('cyan', str(pkt))}")
        route = self.switch.route(pkt.dst_ip)
        if verbose and route:
            print(f"      {c('gray', 'Route:')} via {route['iface']}")
        result = self.firewall.process(pkt)
        action, rule, nat_entry = result["action"], result["rule"], result["nat_entry"]
        if verbose:
            color  = "green" if action == Action.ALLOW else "red"
            symbol = "ALLOW" if action == Action.ALLOW else "DENY "
            print(f"      {c(color, symbol)}  seq:{rule.seq} - {rule.description}")
            if nat_entry:
                print(f"      {c('cyan', 'NAT:')} {pkt.src_ip}:{nat_entry.local_port} "
                      f"-> {nat_entry.inside_global}:{nat_entry.global_port}")
            if action == Action.ALLOW:
                if pkt.protocol == Protocol.UDP and pkt.dst_port == 53:
                    print(self.dns.query(pkt))
                elif pkt.protocol == Protocol.TCP and pkt.dst_port == 80:
                    print(self.http.handle(pkt))
        return result

    # ── Demo Scenarios ─────────────────────────────────

    def demo_acl_filtering(self):
        self._header("DEMO 1 -- Protocol Filtering ACL Engine")
        packets = [
            Packet("192.168.10.10", "8.8.8.8",          Protocol.TCP,  49152, 80,  "GET /"),
            Packet("192.168.10.10", "192.168.30.50",    Protocol.UDP,  51200, 53,  "enterprise.local"),
            Packet("192.168.20.10", "8.8.8.8",          Protocol.ICMP, 0,     0,   "ping"),
            Packet("192.168.30.10", "8.8.8.8",          Protocol.ICMP, 0,     0,   "ping"),
            Packet("192.168.20.10", "192.168.30.10",    Protocol.TCP,  50100, 22,  "SSH attempt"),
            Packet("192.168.10.10", "192.168.30.10",    Protocol.TCP,  49200, 22,  "Admin SSH"),
            Packet("10.10.10.99",   "192.168.10.10",    Protocol.TCP,  9999,  80,  "attack"),
            Packet("192.168.10.10", "192.168.30.50",    Protocol.TCP,  49300, 23,  "telnet"),
            Packet("192.168.30.10", "203.0.113.100",    Protocol.TCP,  55000, 443, "HTTPS out"),
            Packet("192.168.20.10", "192.168.30.50",    Protocol.TCP,  50200, 21,  "FTP attempt"),
        ]
        for pkt in packets:
            self.send_packet(pkt)

    def demo_vlan_routing(self):
        self._header("DEMO 2 -- VLAN Segmentation & Inter-VLAN Routing")
        self.switch.show_routing_table()
        print(c("bold", "\n  IP -> VLAN Mapping:"))
        test_ips = ["192.168.10.10","192.168.10.11",
                    "192.168.20.10","192.168.20.11",
                    "192.168.30.10","192.168.30.50"]
        for ip in test_ips:
            vlan_id = self.switch.get_vlan(ip)
            if vlan_id:
                name = VLAN_CONFIG[vlan_id]["name"]
                print(f"  {ip:<22} -> VLAN {vlan_id} ({name})")
        print(c("bold", "\n  Inter-VLAN packet (HR -> IT HTTP server):"))
        self.send_packet(Packet("192.168.20.10", "192.168.30.50",
                                Protocol.TCP, 50100, 80, "GET /hr"))

    def demo_nat_pat(self):
        self._header("DEMO 3 -- NAT/PAT (Port Address Translation)")
        internal = [
            ("192.168.10.10", "142.250.80.46",    Protocol.TCP, 443),
            ("192.168.20.10", "104.16.133.229",   Protocol.TCP, 443),
            ("192.168.30.10", "8.8.8.8",          Protocol.UDP, 53),
            ("192.168.10.11", "203.0.113.99",     Protocol.TCP, 80),
        ]
        for src, dst, proto, port in internal:
            pkt = Packet(src, dst, proto, random.randint(49152, 65535), port)
            self.send_packet(pkt)
        self.firewall.nat.show_table()

    def demo_dhcp(self):
        self._header("DEMO 4 -- DHCP Dynamic Addressing")
        new_devices = [
            ("FF:EE:DD:CC:BB:10", "new-admin-laptop",    10),
            ("FF:EE:DD:CC:BB:20", "new-hr-workstation",  20),
            ("FF:EE:DD:CC:BB:30", "new-it-server",       30),
        ]
        for mac, hostname, vlan in new_devices:
            lease = self.dhcp.request_lease(mac, hostname, vlan)
            if lease:
                print(f"  {c('green','[OK]')} Assigned {lease.ip} to "
                      f"{lease.hostname} (VLAN {vlan}, GW:{lease.gateway})")
        self.dhcp.show_leases()

    def demo_dns_http(self):
        self._header("DEMO 5 -- DNS Resolution & HTTP Services")
        self.dns.show_records()
        print(c("bold", "\n  DNS Queries:"))
        for hostname in ["enterprise.local", "admin.local", "google.com", "unknown.xyz"]:
            pkt = Packet("192.168.10.10", "192.168.30.50",
                         Protocol.UDP, 51000, 53, hostname)
            result = self.send_packet(pkt, verbose=False)
            if result["action"] == Action.ALLOW:
                print(self.dns.query(pkt))
        print(c("bold", "\n  HTTP Requests:"))
        for path in ["/", "/admin", "/hr", "/forbidden", "/missing"]:
            pkt = Packet("192.168.10.10", "192.168.30.50",
                         Protocol.TCP, 49500, 80, path)
            result = self.send_packet(pkt, verbose=False)
            if result["action"] == Action.ALLOW:
                print(self.http.handle(pkt))

    def demo_ssh(self):
        self._header("DEMO 6 -- SSH Secure Administration")
        cases = [
            ("192.168.10.10", "admin", "Admin@1234"),
            ("192.168.20.10", "admin", "Admin@1234"),
            ("203.0.113.50",  "admin", "Admin@1234"),
            ("192.168.10.11", "admin", "wrongpass"),
        ]
        for src_ip, user, pwd in cases:
            print(f"\n  Attempt: {src_ip} user={user}")
            pkt = Packet(src_ip, "192.168.30.50", Protocol.TCP, 55000, 22)
            result = self.send_packet(pkt, verbose=False)
            if result["action"] == Action.ALLOW:
                self.ssh.show_banner(src_ip, user, pwd)
            else:
                rule = result["rule"]
                print(c("red", f"  [FW] SSH blocked -- {rule.description} (seq {rule.seq})"))

    def demo_blacklist_whitelist(self):
        self._header("DEMO 7 -- IP Blacklisting & Whitelisting")
        print(c("bold", "  Blacklisted hosts:"))
        for ip in sorted(self.firewall.blacklist):
            pkt = Packet(ip, "192.168.10.10", Protocol.TCP, 9999, 80)
            self.send_packet(pkt)
        print(c("bold", "\n  Whitelisted (Admin VLAN -- SSH):"))
        for ip in ["192.168.10.10", "192.168.10.11"]:
            pkt = Packet(ip, "192.168.30.50", Protocol.TCP, 55001, 22)
            self.send_packet(pkt)

    def run_all_demos(self):
        banner = c("bold", """
+================================================================+
|    Enterprise Network -- Protocol Filtering Firewall Sim       |
|    VLANs * ACL Engine * NAT/PAT * DHCP * DNS * HTTP * SSH     |
+================================================================+""")
        print(banner)
        self.demo_acl_filtering()
        self.demo_vlan_routing()
        self.demo_nat_pat()
        self.demo_dhcp()
        self.demo_dns_http()
        self.demo_ssh()
        self.demo_blacklist_whitelist()
        self._header("SUMMARY")
        self.firewall.show_stats()
        self.firewall.show_acl()
        self.firewall.show_log(last_n=20)
        self.firewall.nat.show_table()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    net = EnterpriseNetwork()
    net.run_all_demos()

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

# ─────────────────────────────────────────────
#  GUI APPLICATION
# ─────────────────────────────────────────────

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Firewall Dashboard")
        self.root.geometry("1200x700")

        self.net = EnterpriseNetwork()

        self._setup_style()
        self._build_layout()

        self.running = False

    # ───────────────── UI STYLE ─────────────────

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook", background="#1e1e1e")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("TButton", padding=6)

    # ───────────────── LAYOUT ─────────────────

    def _build_layout(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        # Sidebar
        sidebar = ttk.Frame(main_frame, width=200)
        sidebar.pack(side="left", fill="y")

        # Main area
        content = ttk.Frame(main_frame)
        content.pack(side="right", fill="both", expand=True)

        self._build_sidebar(sidebar)
        self._build_topbar(content)
        self._build_tabs(content)

    # ───────────────── SIDEBAR ─────────────────

    def _build_sidebar(self, parent):
        ttk.Label(parent, text="Controls", font=("Arial", 12, "bold")).pack(pady=10)

        self.demo_var = tk.StringVar()
        demos = [
            "ACL Filtering",
            "VLAN Routing",
            "NAT/PAT",
            "DHCP",
            "DNS & HTTP",
            "SSH",
            "Blacklist"
        ]

        combo = ttk.Combobox(parent, values=demos, textvariable=self.demo_var)
        combo.pack(pady=5)

        ttk.Button(parent, text="Run Demo", command=self.run_demo_thread).pack(pady=5)

        ttk.Button(parent, text="Manual Inject", command=self.open_packet_window).pack(pady=10)

    # ───────────────── TOP BAR ─────────────────

    def _build_topbar(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x")

        self.health_label = ttk.Label(top, text="Allowed: 0 | Denied: 0")
        self.health_label.pack(anchor="e", padx=10, pady=5)

    def update_health(self):
        stats = self.net.firewall.stats
        self.health_label.config(
            text=f"Allowed: {stats['ALLOW']} | Denied: {stats['DENY']}"
        )

    # ───────────────── TABS ─────────────────

    def _build_tabs(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        # Tab 1: Live Monitor
        self.tab1 = ttk.Frame(notebook)
        notebook.add(self.tab1, text="Live Monitor")

        self.log_text = tk.Text(self.tab1, bg="black", fg="white")
        self.log_text.pack(fill="both", expand=True)

        # Color tags
        self.log_text.tag_config("ALLOW", foreground="green")
        self.log_text.tag_config("DENY", foreground="red")

        # Tab 2: Tables
        self.tab2 = ttk.Frame(notebook)
        notebook.add(self.tab2, text="Network Tables")

        self._build_tables(self.tab2)

        # Tab 3: Config
        self.tab3 = ttk.Frame(notebook)
        notebook.add(self.tab3, text="Configuration")

        self.config_text = tk.Text(self.tab3)
        self.config_text.pack(fill="both", expand=True)

        self.load_config()

    # ───────────────── TABLES ─────────────────

    def _build_tables(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        self.dhcp_table = self.create_table(frame, ["IP", "MAC", "Host", "VLAN"])
        self.dns_table = self.create_table(frame, ["Hostname", "IP"])
        self.nat_table = self.create_table(frame, ["Local", "Global", "Port"])

        self.refresh_tables()

    def create_table(self, parent, cols):
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=6)
        for c in cols:
            tree.heading(c, text=c)
        tree.pack(fill="x", pady=5)
        return tree

    def refresh_tables(self):
        # DHCP
        for row in self.net.dhcp.leases.values():
            self.dhcp_table.insert("", "end",
                values=(row.ip, row.mac, row.hostname, row.vlan))

        # DNS
        for name, ip in self.net.dns.records.items():
            self.dns_table.insert("", "end", values=(name, ip))

        # NAT
        for e in self.net.firewall.nat.table:
            self.nat_table.insert("", "end",
                values=(e.inside_local, e.inside_global, e.global_port))

    # ───────────────── CONFIG TAB ─────────────────

    def load_config(self):
        self.config_text.delete(1.0, tk.END)

        self.config_text.insert(tk.END, "=== ACL RULES ===\n")
        for r in self.net.firewall.acl_rules:
            self.config_text.insert(tk.END,
                f"{r.seq} {r.action.value} {r.protocol.value} {r.src_net} -> {r.dst_net}\n")

        self.config_text.insert(tk.END, "\n=== VLAN CONFIG ===\n")
        for vid, cfg in VLAN_CONFIG.items():
            self.config_text.insert(tk.END, f"{vid}: {cfg}\n")

    # ───────────────── LOGGING ─────────────────

    def log(self, msg, tag=None):
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)

    # ───────────────── THREADING ─────────────────

    def run_demo_thread(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self.run_demo).start()

    def run_demo(self):
        demo = self.demo_var.get()

        mapping = {
            "ACL Filtering": self.net.demo_acl_filtering,
            "VLAN Routing": self.net.demo_vlan_routing,
            "NAT/PAT": self.net.demo_nat_pat,
            "DHCP": self.net.demo_dhcp,
            "DNS & HTTP": self.net.demo_dns_http,
            "SSH": self.net.demo_ssh,
            "Blacklist": self.net.demo_blacklist_whitelist
        }

        func = mapping.get(demo)
        if not func:
            messagebox.showerror("Error", "Select a demo")
            self.running = False
            return

        # Hook into firewall log
        original_process = self.net.firewall.process

        def wrapped(pkt):
            result = original_process(pkt)
            action = result["action"].value
            self.log(str(pkt), action)
            self.update_health()
            return result

        self.net.firewall.process = wrapped

        func()

        self.net.firewall.process = original_process
        self.refresh_tables()

        self.running = False

    # ───────────────── MANUAL PACKET ─────────────────

    def open_packet_window(self):
        win = tk.Toplevel(self.root)
        win.title("Inject Packet")

        entries = {}

        fields = ["Src IP", "Dst IP", "Port", "Protocol"]
        for f in fields:
            ttk.Label(win, text=f).pack()
            e = ttk.Entry(win)
            e.pack()
            entries[f] = e

        def send():
            try:
                pkt = Packet(
                    entries["Src IP"].get(),
                    entries["Dst IP"].get(),
                    Protocol[entries["Protocol"].get()],
                    5000,
                    int(entries["Port"].get())
                )
                res = self.net.send_packet(pkt, verbose=False)
                self.log(str(pkt), res["action"].value)
                self.update_health()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(win, text="Send", command=send).pack(pady=10)


# ─────────────────────────────────────────────
#  RUN APP
# ─────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

import tkinter as tk
from tkinter import ttk, messagebox


# ─────────────────────────────────────────────
#  GUI APPLICATION
# ─────────────────────────────────────────────

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Firewall Dashboard")
        self.root.geometry("1200x700")

        self.net = EnterpriseNetwork()

        self._setup_style()
        self._build_layout()

        self.running = False

    # ───────────────── UI STYLE ─────────────────

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook", background="#1e1e1e")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("TButton", padding=6)

    # ───────────────── LAYOUT ─────────────────

    def _build_layout(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        # Sidebar
        sidebar = ttk.Frame(main_frame, width=200)
        sidebar.pack(side="left", fill="y")

        # Main area
        content = ttk.Frame(main_frame)
        content.pack(side="right", fill="both", expand=True)

        self._build_sidebar(sidebar)
        self._build_topbar(content)
        self._build_tabs(content)

    # ───────────────── SIDEBAR ─────────────────

    def _build_sidebar(self, parent):
        ttk.Label(parent, text="Controls", font=("Arial", 12, "bold")).pack(pady=10)

        self.demo_var = tk.StringVar()
        demos = [
            "ACL Filtering",
            "VLAN Routing",
            "NAT/PAT",
            "DHCP",
            "DNS & HTTP",
            "SSH",
            "Blacklist"
        ]

        combo = ttk.Combobox(parent, values=demos, textvariable=self.demo_var)
        combo.pack(pady=5)

        ttk.Button(parent, text="Run Demo", command=self.run_demo_thread).pack(pady=5)

        ttk.Button(parent, text="Manual Inject", command=self.open_packet_window).pack(pady=10)

    # ───────────────── TOP BAR ─────────────────

    def _build_topbar(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x")

        self.health_label = ttk.Label(top, text="Allowed: 0 | Denied: 0")
        self.health_label.pack(anchor="e", padx=10, pady=5)

    def update_health(self):
        stats = self.net.firewall.stats
        self.health_label.config(
            text=f"Allowed: {stats['ALLOW']} | Denied: {stats['DENY']}"
        )

    # ───────────────── TABS ─────────────────

    def _build_tabs(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        # Tab 1: Live Monitor
        self.tab1 = ttk.Frame(notebook)
        notebook.add(self.tab1, text="Live Monitor")

        self.log_text = tk.Text(self.tab1, bg="black", fg="white")
        self.log_text.pack(fill="both", expand=True)

        # Color tags
        self.log_text.tag_config("ALLOW", foreground="green")
        self.log_text.tag_config("DENY", foreground="red")

        # Tab 2: Tables
        self.tab2 = ttk.Frame(notebook)
        notebook.add(self.tab2, text="Network Tables")

        self._build_tables(self.tab2)

        # Tab 3: Config
        self.tab3 = ttk.Frame(notebook)
        notebook.add(self.tab3, text="Configuration")

        self.config_text = tk.Text(self.tab3)
        self.config_text.pack(fill="both", expand=True)

        self.load_config()

    # ───────────────── TABLES ─────────────────

    def _build_tables(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        self.dhcp_table = self.create_table(frame, ["IP", "MAC", "Host", "VLAN"])
        self.dns_table = self.create_table(frame, ["Hostname", "IP"])
        self.nat_table = self.create_table(frame, ["Local", "Global", "Port"])

        self.refresh_tables()

    def create_table(self, parent, cols):
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=6)
        for c in cols:
            tree.heading(c, text=c)
        tree.pack(fill="x", pady=5)
        return tree

    def refresh_tables(self):
        # DHCP
        for row in self.net.dhcp.leases.values():
            self.dhcp_table.insert("", "end",
                values=(row.ip, row.mac, row.hostname, row.vlan))

        # DNS
        for name, ip in self.net.dns.records.items():
            self.dns_table.insert("", "end", values=(name, ip))

        # NAT
        for e in self.net.firewall.nat.table:
            self.nat_table.insert("", "end",
                values=(e.inside_local, e.inside_global, e.global_port))

    # ───────────────── CONFIG TAB ─────────────────

    def load_config(self):
        self.config_text.delete(1.0, tk.END)

        self.config_text.insert(tk.END, "=== ACL RULES ===\n")
        for r in self.net.firewall.acl_rules:
            self.config_text.insert(tk.END,
                f"{r.seq} {r.action.value} {r.protocol.value} {r.src_net} -> {r.dst_net}\n")

        self.config_text.insert(tk.END, "\n=== VLAN CONFIG ===\n")
        for vid, cfg in VLAN_CONFIG.items():
            self.config_text.insert(tk.END, f"{vid}: {cfg}\n")

    # ───────────────── LOGGING ─────────────────

    def log(self, msg, tag=None):
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)

    # ───────────────── THREADING ─────────────────

    def run_demo_thread(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self.run_demo).start()

    def run_demo(self):
        demo = self.demo_var.get()

        mapping = {
            "ACL Filtering": self.net.demo_acl_filtering,
            "VLAN Routing": self.net.demo_vlan_routing,
            "NAT/PAT": self.net.demo_nat_pat,
            "DHCP": self.net.demo_dhcp,
            "DNS & HTTP": self.net.demo_dns_http,
            "SSH": self.net.demo_ssh,
            "Blacklist": self.net.demo_blacklist_whitelist
        }

        func = mapping.get(demo)
        if not func:
            messagebox.showerror("Error", "Select a demo")
            self.running = False
            return

        # Hook into firewall log
        original_process = self.net.firewall.process

        def wrapped(pkt):
            result = original_process(pkt)
            action = result["action"].value
            self.log(str(pkt), action)
            self.update_health()
            return result

        self.net.firewall.process = wrapped

        func()

        self.net.firewall.process = original_process
        self.refresh_tables()

        self.running = False

    # ───────────────── MANUAL PACKET ─────────────────

    def open_packet_window(self):
        win = tk.Toplevel(self.root)
        win.title("Inject Packet")

        entries = {}

        fields = ["Src IP", "Dst IP", "Port", "Protocol"]
        for f in fields:
            ttk.Label(win, text=f).pack()
            e = ttk.Entry(win)
            e.pack()
            entries[f] = e

        def send():
            try:
                pkt = Packet(
                    entries["Src IP"].get(),
                    entries["Dst IP"].get(),
                    Protocol[entries["Protocol"].get()],
                    5000,
                    int(entries["Port"].get())
                )
                res = self.net.send_packet(pkt, verbose=False)
                self.log(str(pkt), res["action"].value)
                self.update_health()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(win, text="Send", command=send).pack(pady=10)


# ─────────────────────────────────────────────
#  RUN APP
# ─────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()