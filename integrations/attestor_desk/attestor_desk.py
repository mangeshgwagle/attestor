#!/usr/bin/env python3
"""Attestor, small and on the desktop.

A little always-on-top companion that sits in a corner, takes a folder, and
says what it found. It is the friendly face on the same engine the workbench
runs -- not a second analyser, and deliberately not a second opinion.

Three things it will not do, each for a reason learned the hard way:

  * It never says the code is safe. A clean scan means the rules that ran
    found nothing, which is a different claim, and `attestor_pro` refuses to blur
    them for a paying customer -- the cute one should not blur them either.
  * It treats `detect.py`'s exit status 2 as "findings", not "failure".
    Chaining on the exit code is what silently produced empty runs in the
    Terminal-Bench harness, and the same mistake here would show a happy face
    over a scan that actually reported defects.
  * It never scans without being asked. No folder watching, no background
    sweeps: it holds still until you hand it something.

Only the standard library, so there is nothing to install.
"""
from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DETECTOR = HERE.parent.parent / "detector"

# `detect.py` exits 0 when it found nothing and 2 when it found something.
# Both are successful runs. Anything else is a real failure.
CLEAN, FOUND = 0, 2

SCAN_TIMEOUT_SECONDS = 120
WORKBENCH_PORT = 8787

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

FACES = {
    "idle": "( o . o )",
    "thinking": "( - . - )",
    "clean": "( ^ . ^ )",
    "found": "( O ▁ O )",
    "sorry": "( x _ x )",
}


class DeskError(Exception):
    """A scan could not be run at all, as opposed to running and finding."""


def tally(findings):
    """Counts per severity plus a total, with every level always present."""
    counts = {name: 0 for name in SEVERITIES}
    for item in findings:
        level = str(item.get("severity", "INFO")).upper()
        counts[level] = counts.get(level, 0) + 1
    counts["TOTAL"] = sum(counts[name] for name in counts if name != "TOTAL")
    return counts


def mood(counts):
    """Which face to wear. Anything at all beats a smile."""
    if counts.get("TOTAL", 0) == 0:
        return "clean"
    return "found"


def worst(counts):
    """The highest severity actually present, or None."""
    for name in SEVERITIES:
        if counts.get(name):
            return name
    return None


def remark(counts, where=""):
    """What Attestor says out loud.

    Kept deliberately plain about the clean case: "nothing came back" is true,
    "you're safe" is not, and the difference is the whole reason the report
    layer exists.
    """
    place = pathlib.Path(where).name if where else "that"
    total = counts.get("TOTAL", 0)
    if not total:
        return ("I read every file in %s I had a rule for, and nothing came "
                "back. That is not the same as safe -- it is just quiet." % place)
    top = worst(counts)
    if total == 1:
        return "Found one thing in %s, and it is %s. Want to look?" % (place, top)
    return ("Found %d things in %s. The loudest is %s."
            % (total, place, top))


def scan(target, detector=None, timeout=SCAN_TIMEOUT_SECONDS):
    """Run the detector over `target` and return its findings.

    Raises DeskError when the scan could not run. A run that *did* happen and
    reported defects is a success, and returns them.
    """
    detector = pathlib.Path(detector or DETECTOR)
    entry = detector / "detect.py"
    if not entry.is_file():
        raise DeskError("no detector at %s" % entry)
    target = pathlib.Path(target)
    if not target.exists():
        raise DeskError("nothing to read at %s" % target)

    try:
        done = subprocess.run(
            [sys.executable, "-B", str(entry), "--json", str(target)],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(detector), **_quietly())
    except subprocess.TimeoutExpired:
        raise DeskError("that took longer than %ds, so I stopped" % timeout)
    except OSError as error:
        raise DeskError("could not start the detector: %s" % error)

    if done.returncode not in (CLEAN, FOUND):
        detail = (done.stderr or "").strip().splitlines()
        raise DeskError(detail[-1] if detail
                        else "the detector stopped with status %d"
                             % done.returncode)
    if not done.stdout.strip():
        return []
    try:
        parsed = json.loads(done.stdout)
    except json.JSONDecodeError:
        raise DeskError("the detector said something I could not read")
    return parsed if isinstance(parsed, list) else []


def _quietly():
    """Keep a console window from flashing up on Windows."""
    flag = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return {"creationflags": flag} if flag else {}


def free_port(preferred=WORKBENCH_PORT, tries=12):
    """The first free port at or after `preferred`.

    An Attestor may already be running -- there usually is one -- and taking its
    port away from it would be a rude way to say hello.

    Probed with a plain bind and deliberately *without* SO_REUSEADDR. On
    Windows that option lets a bind succeed on a port another socket already
    holds, so setting it turns this function into one that cheerfully reports
    every busy port as free; the first version did exactly that and picked
    8787 while the workbench was answering on it.
    """
    for offset in range(tries):
        candidate = preferred + offset
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
        return candidate
    raise DeskError("every port from %d up is busy" % preferred)


def workbench_running(port=WORKBENCH_PORT):
    """Is something already listening on the workbench port?"""
    with socket.socket() as probe:
        probe.settimeout(0.4)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def start_workbench(detector=None, port=None):
    """Launch the local workbench and return the URL it will answer on."""
    detector = pathlib.Path(detector or DETECTOR)
    entry = detector / "attestor_ui.py"
    if not entry.is_file():
        raise DeskError("no workbench at %s" % entry)
    port = port or free_port()
    subprocess.Popen(
        [sys.executable, "-B", str(entry), "--port", str(port)],
        cwd=str(detector), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, **_quietly())
    return "http://127.0.0.1:%d/" % port


# ---------------------------------------------------------------- the face --

def run_desk():                                     # pragma: no cover - GUI
    """The little window. Everything above this line works without a screen."""
    import threading
    import tkinter as tk
    import webbrowser
    from tkinter import filedialog

    INK, SKIN, SOFT = "#1c1b22", "#fdf3e3", "#7a6f5d"

    root = tk.Tk()
    root.title("Attestor")
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    root.configure(bg=SKIN)

    frame = tk.Frame(root, bg=SKIN, padx=14, pady=12,
                     highlightbackground=INK, highlightthickness=2)
    frame.pack(fill="both", expand=True)

    face = tk.Label(frame, text=FACES["idle"], font=("Consolas", 22, "bold"),
                    bg=SKIN, fg=INK)
    face.pack()
    bubble = tk.Label(frame, text="Hand me a folder and I'll read it.",
                      wraplength=230, justify="center", bg=SKIN, fg=SOFT,
                      font=("Segoe UI", 9))
    bubble.pack(pady=(6, 10))

    def say(text, which="idle"):
        face.configure(text=FACES.get(which, FACES["idle"]))
        bubble.configure(text=text)

    def on_scan():
        folder = filedialog.askdirectory(title="What should Attestor read?")
        if not folder:
            return
        say("Reading %s..." % pathlib.Path(folder).name, "thinking")
        buttons_state("disabled")

        def work():
            try:
                counts = tally(scan(folder))
            except DeskError as error:
                root.after(0, lambda: (say(str(error), "sorry"),
                                       buttons_state("normal")))
                return
            root.after(0, lambda: (say(remark(counts, folder), mood(counts)),
                                   buttons_state("normal")))

        threading.Thread(target=work, daemon=True).start()

    def on_workbench():
        if workbench_running():
            webbrowser.open("http://127.0.0.1:%d/" % WORKBENCH_PORT)
            say("One was already running, so I opened that one.", "clean")
            return
        try:
            url = start_workbench()
        except DeskError as error:
            say(str(error), "sorry")
            return
        root.after(1200, lambda: webbrowser.open(url))
        say("Starting the workbench on %s" % url.rstrip("/").split("//")[-1],
            "thinking")

    row = tk.Frame(frame, bg=SKIN)
    row.pack()
    made = []
    for label, action in (("Read a folder", on_scan),
                          ("Workbench", on_workbench),
                          ("Shh", root.destroy)):
        button = tk.Button(row, text=label, command=action, relief="flat",
                           bg=INK, fg=SKIN, font=("Segoe UI", 8, "bold"),
                           padx=8, pady=3, cursor="hand2",
                           activebackground=SOFT, activeforeground=SKIN)
        button.pack(side="left", padx=3)
        made.append(button)

    def buttons_state(state):
        for button in made[:2]:
            button.configure(state=state)

    # Borderless windows have no title bar to drag, so the whole face is one.
    drag = {"x": 0, "y": 0}

    def grab(event):
        drag["x"], drag["y"] = event.x, event.y

    def haul(event):
        root.geometry("+%d+%d" % (event.x_root - drag["x"],
                                  event.y_root - drag["y"]))

    for widget in (frame, face, bubble):
        widget.bind("<Button-1>", grab)
        widget.bind("<B1-Motion>", haul)

    root.update_idletasks()
    screen_w = root.winfo_screenwidth()
    root.geometry("+%d+%d" % (screen_w - root.winfo_width() - 40, 60))
    root.mainloop()


if __name__ == "__main__":                          # pragma: no cover
    run_desk()
