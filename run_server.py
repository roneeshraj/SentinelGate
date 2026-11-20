"""
Launcher script for SentinelGate Platform.
Starts the Web Dashboard and Gateway on http://127.0.0.1:8888/
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.web.server import run_server

if __name__ == "__main__":
    port = 8888
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port=port)
