import json
import os
import datetime
from colorama import Fore, Style

class SessionManager:
    def __init__(self, log_file=None):
        self.sessions = []
        # CR-34 fix: Use config-provided log file path
        self.log_file = log_file or "./sessions.log"
        self._load_sessions()

    def _load_sessions(self):
        """Load existing sessions from disk on init."""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    self.sessions = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.sessions = []

    def add_session(self, session_data):
        # CR-34 fix: Add timestamp and proper status
        session_data['created_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
        session_data['status'] = 'Active'
        self.sessions.append(session_data)
        self.save_sessions()

    def save_sessions(self):
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.sessions, f, indent=4)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save sessions: {e}")

    def list_sessions(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}| {'IP Address':<15} | {'Exploit Type':<20} | {'Status':<10}")
        print(f"{Fore.CYAN}{'='*60}")
        for session in self.sessions:
            print(f"{Fore.WHITE}{session.get('ip',''):<15} | {session.get('type',''):<20} | {session.get('status','Active'):<10}")
        print(f"{Fore.CYAN}{'='*60}\n")
