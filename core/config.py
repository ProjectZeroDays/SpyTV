import yaml
import os

def load_config():
    path = os.path.join("resources", "config.yaml")
    if os.path.exists(path):
        with open(path, 'r') as file:
            config = yaml.safe_load(file)
            return config if config else {}
    # CR-02 fix: Return sensible defaults instead of empty dict
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

CONFIG = load_config()
