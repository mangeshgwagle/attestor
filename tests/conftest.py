"""Put the flat detector/ modules on sys.path so tests can import them directly."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTOR = os.path.join(ROOT, "detector")
if DETECTOR not in sys.path:
    sys.path.insert(0, DETECTOR)
