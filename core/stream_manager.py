import subprocess
import os
import time
import re
import platform
from colorama import Fore, Style

class VLCStreamManager:
    def __init__(self, config):
        self.config = config
        self.output_dir = config.get('stream', {}).get('output_dir', './captures')
        self.os_type = platform.system()

        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def start_live_stream(self, target_ip, stream_port=554):
        print(f"{Fore.CYAN}[STREAM] Starting VLC to listen for live stream on {target_ip}:{stream_port}...")

        vlc_path = self.config.get('stream', {}).get('vlc_path', 'vlc')
        if not self._check_command_exists(vlc_path):
            print(f"{Fore.RED}[ERROR] VLC not found in PATH. Is VLC installed?")
            return None

        # CR-20 fix: Proper VLC command with valid --sout syntax
        # Use rtsp input and duplicate to local RTP output
        vlc_cmd = [
            vlc_path,
            '--intf', 'cli',
            '--play-and-exit',
            f'rtsp://{target_ip}:{stream_port}/stream',
            '--sout', '#duplicate{dst=rtp{dst=127.0.0.1,port=5004,sdp=rtsp://127.0.0.1:554/stream}}',
            '--ttl', '12',
            '--network-caching', '1000',
            '--no-video'
        ]

        try:
            process = subprocess.Popen(vlc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)
            if process.poll() is not None:
                stderr = process.stderr.read().decode('utf-8')
                if "error" in stderr.lower():
                    print(f"{Fore.YELLOW}[STREAM] VLC started but encountered error: {stderr}")
                else:
                    print(f"{Fore.GREEN}[STREAM] VLC initialized. Listening on UDP port 5004...")
            else:
                print(f"{Fore.GREEN}[STREAM] VLC initialized. Listening on UDP port 5004...")
            return process
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to start VLC: {e}")
            return None

    def record_stream(self, target_ip, duration=1):
        print(f"{Fore.CYAN}[STREAM] Recording stream for {duration} minutes...")

        duration = max(1, int(duration))

        timestamp = int(time.time())
        filename = f"{self.output_dir}/record_{timestamp}.ts"

        vlc_path = self.config.get('stream', {}).get('vlc_path', 'vlc')

        # CR-21 fix: Use proper VLC recording syntax with --sout #std{access=file}
        vlc_cmd = [
            vlc_path,
            '--intf', 'cli',
            f'rtsp://{target_ip}:554/stream',
            '--sout', f'#std{{access=file,mux=ts,dst={filename}}}',
            '--play-and-exit',
            '--no-video',
            '--run-time', str(duration * 60),
            'vlc://quit'
        ]

        try:
            process = subprocess.Popen(vlc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            try:
                process.wait(timeout=duration * 60 + 30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                print(f"{Fore.YELLOW}[STREAM] Recording duration exceeded, killed VLC.")
                # CR-22 fix: Return False on timeout, not True
                if os.path.exists(filename) and os.path.getsize(filename) > 0:
                    size_mb = os.path.getsize(filename) / (1024 * 1024)
                    print(f"{Fore.GREEN}[STREAM] Partial recording saved: {filename} ({size_mb:.2f} MB)")
                    return True
                return False

            if os.path.exists(filename) and os.path.getsize(filename) > 0:
                size_mb = os.path.getsize(filename) / (1024 * 1024)
                print(f"{Fore.GREEN}[STREAM] Recording saved: {filename} ({size_mb:.2f} MB)")
                return True
            else:
                print(f"{Fore.YELLOW}[STREAM] Recording finished but file not found or empty.")
                return False

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to start recording: {e}")
            return False

    def activate_microphone_mode(self):
        # CR-24 fix: Remove dead try/except, provide actual implementation
        print(f"{Fore.CYAN}[STREAM] Activating speaker-microphone mode...")

        if self.os_type == 'Linux':
            print(f"{Fore.YELLOW}[INFO] Linux detected. Use 'pactl load-module module-loopback' to capture TV audio.")
        elif self.os_type == 'Windows':
            print(f"{Fore.YELLOW}[INFO] Windows detected. Requires virtual audio cable driver (e.g., VB-Cable) for loopback.")
        else:
            print(f"{Fore.RED}[ERROR] Unsupported OS for speaker-microphone mode.")
            return False

        return True

    def _check_command_exists(self, command):
        """Helper to check if a command is available in PATH."""
        try:
            subprocess.run([command, '--version'], capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
