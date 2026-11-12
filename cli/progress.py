"""Low-overhead terminal progress rendering."""
import json
import sys
import time


class ProgressRenderer:
    def __init__(self, enabled=True, json_mode=False, quiet=False):
        self.enabled = enabled and not quiet
        self.json_mode = json_mode
        self.last_render = 0.0
        self.last_phase = None

    def callback(self, current, total, phase):
        now = time.monotonic()
        if not self.enabled:
            return
        if now - self.last_render < 0.15 and phase == self.last_phase and current != total:
            return
        self.last_render = now
        self.last_phase = phase
        event = {"phase": phase, "current": current, "total": total, "time": time.time()}
        if self.json_mode:
            print(json.dumps(event), file=sys.stderr, flush=True)
            return
        if total > 0:
            percent = min(100.0, current * 100.0 / total)
            width = 28
            filled = int(width * percent / 100)
            bar = "#" * filled + "-" * (width - filled)
            text = f"\r{phase:<12} [{bar}] {percent:6.2f}%"
        else:
            text = f"\r{phase:<12} {current} completed"
        print(text, end="", file=sys.stderr, flush=True)

    def finish(self):
        if self.enabled and not self.json_mode:
            print(file=sys.stderr)
