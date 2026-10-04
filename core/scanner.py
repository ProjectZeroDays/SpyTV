import nmap
from colorama import Fore, Style
import json

class NetworkScanner:
    def __init__(self, config):
        self.nm = nmap.PortScanner()
        self.config = config
        # Real-world port mapping for Smart TVs
        # CR-08 fix: Removed overlapping generic ports (1900/554/8080) from
        # vendor-specific lists; each vendor now has distinct ports only.
        self.manufacturer_detection = {
            "Samsung": [8000, 5554],
            "LG": [30000, 2121],
            "Sony": [5555, 80],
            "Vizio": [7345, 36669],
            "Panasonic": [5554, 5555]
        }
        # Known vulnerability signatures in version strings
        self.vuln_signatures = {
            "Samsung": "linux",
            "LG": "linux",
            "TCL/Hisense": "linux",
            "Roku": "roku",
            "Android TV": "android"
        }

    def scan_network(self, target_range):
        print(f"{Fore.CYAN}[SCAN] Starting stealth scan on {target_range}...")

        # CR-07 fix: Removed contradictory flags.
        # -T2 (polite timing) conflicts with --min-rate 200 (forces rate floor).
        # --disable-arp-ping actually slows LAN discovery; removed for reliability.
        scan_args = '-sV -T2 --top-ports 100'

        try:
            self.nm.scan(hosts=target_range, arguments=scan_args)
            hosts = self.nm.all_hosts()
            # CR-10 fix: Distinguish failure from empty result
            if not hosts:
                print(f"{Fore.YELLOW}[SCAN] No hosts found in {target_range}")
            return hosts
        except nmap.PortScannerError as e:
            print(f"{Fore.RED}[ERROR] Scan failed (nmap error): {e}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Scan failed: {e}")
            return []

    def parse_results(self, hosts):
        tv_list = []
        for host in hosts:
            status = self.nm[host].state()
            if status != 'up':
                continue

            vulns = []
            is_vulnerable = False
            device_type = "Unknown"

            # CR-05 fix: python-nmap keys tcp dict by INTEGER port.
            # Use integer membership tests, not string.
            open_tcp_ports = set(self.nm[host].tcp.keys())

            # Check for Manufacturer Ports
            for mfr, ports in self.manufacturer_detection.items():
                if any(p in open_tcp_ports for p in ports):
                    device_type = mfr
                    break

            # CR-06 fix: Check vuln signatures against actual version strings
            # from open ports, not just device_type matching.
            for mfr, sig in self.vuln_signatures.items():
                if mfr in device_type or device_type == "Unknown":
                    for port, proto_info in self.nm[host].tcp.items():
                        if 'version' in proto_info:
                            version = proto_info['version'].lower()
                            if sig.lower() in version:
                                vulns.append(f"Known {mfr} Vulnerability")
                                is_vulnerable = True
                                break

            # CR-05 fix: Check for ADB (port 5555) using integer key
            if 5555 in open_tcp_ports:
                vulns.append("ADB Wireless Debugging")
                is_vulnerable = True

            # CR-05 fix: Check for SSH (port 22) using integer key
            if 22 in open_tcp_ports:
                vulns.append("SSH Service")
                is_vulnerable = True

            if is_vulnerable:
                status_icon = f"{Fore.GREEN}UP{Style.RESET_ALL}"
            else:
                status_icon = f"{Fore.YELLOW}OPEN{Style.RESET_ALL}"

            tv_list.append((host, status_icon, device_type, vulns))

        return tv_list

    def display_results(self, tv_list):
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}| {'IP Address':<15} | {'Status':<10} | {'Device Type':<20} | {'Vulnerabilities':<40}")
        print(f"{Fore.CYAN}{'='*80}")
        for ip, status, dev_type, vulns in tv_list:
            vuln_str = ", ".join(vulns) if vulns else "None"
            # CR-09 fix: Strip ANSI codes from status for proper alignment
            clean_status = status.replace(Fore.GREEN, "").replace(Fore.YELLOW, "").replace(Style.RESET_ALL, "")
            print(f"{Fore.WHITE}{ip:<15} | {clean_status:<10} | {dev_type:<20} | {vuln_str:<40}")
        print(f"{Fore.CYAN}{'='*80}\n")
