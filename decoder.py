import hashlib
import itertools
import string
import multiprocessing as mp
import threading
import time
from tkinter import *
from tkinter.scrolledtext import ScrolledText


# ========= CORE BRUTEFORCE LOGIC ========= #

def worker_batch(args):
    batch, target = args
    sha = hashlib.sha256
    for s in batch:
        if sha(s.encode()).hexdigest() == target:
            return s
    return None


def batch_gen(length, charset, target, batch):
    it = itertools.product(charset, repeat=length)
    while True:
        chunk = list(itertools.islice(it, batch))
        if not chunk:
            break
        yield ["".join(c) for c in chunk], target


def run_length(length, charset, target, threads, batch, gui):
    if gui.stop_requested:
        return False

    total = len(charset) ** length
    gui.reset_progress()
    gui.log(f"[L{length}] total candidates: {total:,}")

    with mp.Pool(processes=threads) as pool:
        done = 0
        for result in pool.imap_unordered(
            worker_batch,
            batch_gen(length, charset, target, batch)
        ):
            if gui.stop_requested:
                gui.log_meta(f"abort requested → terminating L{length}.")
                pool.terminate()
                pool.join()
                return False

            done += batch
            p = min(100.0, (done / total) * 100.0)
            gui.progress(f"L{length}", p, done, total)

            if isinstance(result, str):
                gui.log("")
                gui.banner(f"FOUND → {result}")
                gui.sound.found()
                pool.terminate()
                pool.join()
                return True

    return False


def start_bruteforce(gui, target, charset, max_len, threads, batch):
    def run():
        gui.set_status("RUNNING", accent="#39ff14")
        gui.sound.start()
        try:
            for l in range(1, max_len + 1):
                if gui.stop_requested:
                    gui.log_meta("scan aborted by operator.")
                    gui.set_status("ABORTED", accent="#ff0066")
                    return
                found = run_length(l, charset, target, threads, batch, gui)
                if found:
                    gui.set_status("COMPLETE", accent="#39ff14")
                    gui.log("")
                    gui.banner("SESSION COMPLETE")
                    return
            if not gui.stop_requested:
                gui.set_status("NOT FOUND", accent="#ff0066")
                gui.banner("NO MATCH IN SEARCH SPACE")
                gui.sound.not_found()
        finally:
            # reset UI state
            gui.running = False
            gui.stop_requested = False
            gui.start_btn.config(state=NORMAL)
            gui.stop_btn.config(state=DISABLED)

    threading.Thread(target=run, daemon=True).start()


# ========= SOUND ENGINE (NO EXTERNAL FILES) ========= #

class SoundFX:
    """
    Tiny sound engine:
    - Uses winsound.Beep on Windows
    - Falls back to ASCII bell + sleep elsewhere
    All sounds play on background threads so the UI never blocks.
    """
    def __init__(self):
        try:
            import winsound  # type: ignore
            self._winsound = winsound
            self.available = True
        except Exception:
            self._winsound = None
            self.available = False

    def _play_pattern(self, pattern):
        """
        pattern: list of (freq, duration_ms)
        freq <= 0 means 'pause'.
        """
        def runner():
            try:
                if self._winsound is not None:
                    for freq, dur in pattern:
                        if freq <= 0:
                            time.sleep(dur / 1000.0)
                        else:
                            self._winsound.Beep(int(freq), int(dur))
                else:
                    # Fallback: ASCII bell, often very subtle or silent
                    for freq, dur in pattern:
                        if freq > 0:
                            print("\a", end="", flush=True)
                        time.sleep(dur / 1000.0)
            except Exception:
                # Fail silently if sound isn't possible
                pass

        threading.Thread(target=runner, daemon=True).start()

    # --- public cues ---

    def boot(self):
        # Soft system online chirp
        self._play_pattern([
            (1200, 80),
            (0,    40),
            (1600, 110),
        ])

    def start(self):
        # Short ascending triad
        self._play_pattern([
            (900,  70),
            (1200, 70),
            (1500, 90),
        ])

    def progress(self):
        # Tiny high ping, used sparingly on milestones
        self._play_pattern([
            (1700, 50),
        ])

    def found(self):
        # Small success fanfare
        self._play_pattern([
            (1100, 80),
            (1500, 80),
            (1900, 120),
        ])

    def error(self):
        # Low descending error tone
        self._play_pattern([
            (450, 120),
            (300, 140),
        ])

    def not_found(self):
        # Subtle "search ended" cue
        self._play_pattern([
            (650, 80),
            (0,   60),
            (520, 90),
        ])


# ========= NEON HACKER GUI ========= #

class GUI:
    def __init__(self):
        self.win = Tk()
        self.win.title("NEON//SHA-256 CRACKLAB")
        self.win.geometry("1400x850")
        self.win.minsize(1200, 720)
        self.win.configure(bg="#02030a")

        # state flags
        self.running = False
        self.stop_requested = False

        # Sound engine
        self.sound = SoundFX()

        # Global palette
        self.bg_main = "#02030a"
        self.bg_panel = "#050812"
        self.bg_inner = "#050a10"
        self.accent_primary = "#39ff14"   # neon green
        self.accent_secondary = "#00f5ff" # neon cyan
        self.accent_alert = "#ff0066"     # magenta / alert

        # ==== TOP BAR / HEADER ====
        top_bar = Frame(self.win, bg=self.bg_panel, height=60)
        top_bar.pack(side=TOP, fill=X)

        self.header = Label(
            top_bar,
            text="NEON//SHA-256",
            fg=self.accent_primary,
            bg=self.bg_panel,
            font=("Consolas", 28, "bold")
        )
        self.header.pack(side=LEFT, padx=20, pady=10)

        self.sub_header = Label(
            top_bar,
            text="QUANTUM CRACK SUITE v2.0",
            fg=self.accent_secondary,
            bg=self.bg_panel,
            font=("Consolas", 12)
        )
        self.sub_header.pack(side=LEFT, padx=10)

        self.status_label = Label(
            top_bar,
            text="[ STATUS: IDLE ]",
            fg="#777777",
            bg=self.bg_panel,
            font=("Consolas", 12, "bold")
        )
        self.status_label.pack(side=RIGHT, padx=20)

        # ==== MAIN BODY ====
        main = Frame(self.win, bg=self.bg_main)
        main.pack(expand=True, fill=BOTH, padx=26, pady=20)

        # Left: control panel
        self.panel = Frame(main, bg=self.bg_panel, bd=0, highlightthickness=1,
                           highlightbackground="#101626")
        self.panel.pack(side=LEFT, fill=Y, padx=(0, 16), pady=4, ipadx=12, ipady=12)

        title = Label(
            self.panel,
            text="SESSION CONFIG",
            fg=self.accent_secondary,
            bg=self.bg_panel,
            font=("Consolas", 16, "bold")
        )
        title.pack(anchor="w", padx=15, pady=(2, 14))

        # Inputs
        self.hash_in = self.inp("Target SHA-256 Hash")
        self.charset_in = self.inp("Charset Mode (1-5)", "1")
        self.custom_charset = self.inp("Custom Charset", "")
        self.max_len = self.inp("Max Length", "10")
        self.threads = self.inp("CPU Threads (blank = auto)", "")
        self.batch = self.inp("Batch Size", "1000")

        # Mode legend
        legend_frame = Frame(self.panel, bg=self.bg_panel)
        legend_frame.pack(fill=X, padx=15, pady=(10, 6))

        legend_label = Label(
            legend_frame,
            text="CHARSET MODES",
            fg="#8888aa",
            bg=self.bg_panel,
            font=("Consolas", 10, "bold")
        )
        legend_label.pack(anchor="w")

        legend_text = (
            "1 → abc...\n"
            "2 → a-z, A-Z\n"
            "3 → letters + digits\n"
            "4 → full printable (no space)\n"
            "5 → custom charset"
        )
        legend = Label(
            legend_frame,
            text=legend_text,
            justify=LEFT,
            fg="#566080",
            bg=self.bg_panel,
            font=("Consolas", 9)
        )
        legend.pack(anchor="w", pady=(2, 0))

        # Buttons row
        btn_row = Frame(self.panel, bg=self.bg_panel)
        btn_row.pack(pady=16, padx=12, fill=X)

        self.start_btn = Button(
            btn_row,
            text="ENGAGE",
            fg=self.bg_main,
            bg=self.accent_primary,
            activebackground=self.accent_secondary,
            activeforeground=self.bg_main,
            font=("Consolas", 13, "bold"),
            relief=FLAT,
            width=11,
            command=self.start
        )
        self.start_btn.pack(side=LEFT, padx=(0, 10))

        self.stop_btn = Button(
            btn_row,
            text="STOP",
            fg="#ffffff",
            bg=self.accent_alert,
            activebackground="#ff2b7d",
            activeforeground="#ffffff",
            font=("Consolas", 13, "bold"),
            relief=FLAT,
            width=9,
            state=DISABLED,
            command=self.stop
        )
        self.stop_btn.pack(side=LEFT, padx=(0, 10))

        self.clear_btn = Button(
            btn_row,
            text="CLEAR LOG",
            fg=self.accent_secondary,
            bg="#050812",
            activebackground="#0b1224",
            activeforeground=self.accent_secondary,
            font=("Consolas", 11, "bold"),
            relief=FLAT,
            width=11,
            command=self.clear_log
        )
        self.clear_btn.pack(side=LEFT)

        # Left bottom: small info
        info = Label(
            self.panel,
            text="TIP: keep max length + charset realistic.\nSearch space grows exponentially.",
            fg="#555b76",
            bg=self.bg_panel,
            font=("Consolas", 8)
        )
        info.pack(anchor="w", padx=15, pady=(4, 0))

        # Right: console
        console_wrapper = Frame(main, bg=self.bg_main)
        console_wrapper.pack(side=RIGHT, expand=True, fill=BOTH)

        console_frame = Frame(console_wrapper, bg=self.bg_panel, bd=0,
                              highlightthickness=1, highlightbackground="#101626")
        console_frame.pack(expand=True, fill=BOTH, pady=4)

        console_header = Frame(console_frame, bg=self.bg_panel)
        console_header.pack(fill=X)

        console_title = Label(
            console_header,
            text="LIVE TERMINAL FEED",
            fg=self.accent_secondary,
            bg=self.bg_panel,
            font=("Consolas", 14, "bold")
        )
        console_title.pack(side=LEFT, padx=15, pady=10)

        console_hint = Label(
            console_header,
            text="> monitoring brute-force vectors...",
            fg="#555b76",
            bg=self.bg_panel,
            font=("Consolas", 9)
        )
        console_hint.pack(side=RIGHT, padx=15, pady=10)

        self.output = ScrolledText(
            console_frame,
            bg="#020308",
            fg=self.accent_primary,
            insertbackground=self.accent_secondary,
            borderwidth=0,
            font=("Consolas", 11),
            padx=14,
            pady=10
        )
        self.output.pack(expand=True, fill=BOTH)

        # Styling tags for emphasis
        self.output.tag_config("banner", foreground=self.accent_secondary,
                               font=("Consolas", 12, "bold"))
        self.output.tag_config("alert", foreground=self.accent_alert)
        self.output.tag_config("meta", foreground="#4e5a8a")
        self.output.tag_config("progress_label", foreground=self.accent_secondary)

        # progress throttling
        self._last_progress_percent = -1
        self._last_progress_ping = -1

        # Initial banner + boot sound
        self.banner("NEON//SHA-256 CRACKLAB ONLINE")
        if self.sound.available:
            self.log_meta("audio backend: winsound active.")
        else:
            self.log_meta("audio backend: fallback bell (may be inaudible on some systems).")
        self.log_meta("ready for target hash input.")
        self.sound.boot()

        self.win.mainloop()

    # ===== UI helpers ===== #

    def inp(self, label, default=""):
        frame = Frame(self.panel, bg=self.bg_panel)
        frame.pack(pady=5, fill=X)

        lab = Label(
            frame,
            text=label,
            fg=self.accent_secondary,
            bg=self.bg_panel,
            font=("Consolas", 11, "bold")
        )
        lab.pack(anchor="w", padx=15)

        box = Entry(
            frame,
            width=38,
            fg=self.accent_primary,
            bg=self.bg_inner,
            insertbackground=self.accent_secondary,
            highlightthickness=1,
            highlightbackground="#1b2338",
            highlightcolor=self.accent_secondary,
            font=("Consolas", 12)
        )
        box.insert(0, default)
        box.pack(anchor="w", padx=15, pady=(2, 0), ipady=2)
        return box

    def clear_log(self):
        self.output.delete("1.0", END)

    def banner(self, text):
        self.output.insert(END, "\n", ())
        self.output.insert(END, "══════════════════════════════════════════════\n", "banner")
        self.output.insert(END, f"  {text}\n", "banner")
        self.output.insert(END, "══════════════════════════════════════════════\n\n", "banner")
        self.output.see(END)

    def log(self, text):
        self.output.insert(END, f"› {text}\n")
        self.output.see(END)

    def log_meta(self, text):
        self.output.insert(END, f"[meta] {text}\n", "meta")
        self.output.see(END)

    def log_alert(self, text):
        self.output.insert(END, f"[!] {text}\n", "alert")
        self.output.see(END)
        self.sound.error()

    def reset_progress(self):
        self._last_progress_percent = -1
        self._last_progress_ping = -1

    def progress(self, label, p, done, total):
        ip = int(p)
        if ip == self._last_progress_percent:
            return
        self._last_progress_percent = ip

        self.output.insert(END, "[", ())
        self.output.insert(END, f"{label}", "progress_label")
        self.output.insert(END, f"] {ip:3d}%  {done:,}/{total:,}\n", ())
        self.output.see(END)

        # milestone pings at 25 / 50 / 75 / 100 %
        milestone = ip // 25
        if milestone > self._last_progress_ping and milestone > 0:
            self._last_progress_ping = milestone
            self.sound.progress()

    def set_status(self, text, accent=None):
        accent = accent or self.accent_secondary
        self.status_label.config(text=f"[ STATUS: {text} ]", fg=accent)

    def start(self):
        if self.running:
            self.log_meta("already running; stop current session first.")
            return

        target = self.hash_in.get().strip()
        if not target:
            self.log_alert("no target hash provided.")
            return

        m = self.charset_in.get().strip()
        if m == "1":
            charset = string.ascii_lowercase
        elif m == "2":
            charset = string.ascii_letters
        elif m == "3":
            charset = string.ascii_letters + string.digits
        elif m == "4":
            charset = "".join(c for c in string.printable if not c.isspace())
        elif m == "5":
            charset = self.custom_charset.get()
        else:
            charset = string.ascii_lowercase
            self.log_meta("unknown charset mode → defaulting to lowercase.")

        try:
            max_len = int(self.max_len.get())
            batch = int(self.batch.get())
        except ValueError:
            self.log_alert("max length and batch size must be integers.")
            return

        threads = int(self.threads.get()) if self.threads.get() else mp.cpu_count()

        self.banner("INITIALIZING BRUTE-FORCE VECTOR")
        self.log_meta(f"threads: {threads}")
        self.log_meta(f"charset size: {len(charset)}")
        self.log_meta(f"max length: {max_len}")
        self.log_meta(f"batch size: {batch}")
        self.log_meta(f"hash target: {target[:16]}...")

        self.running = True
        self.stop_requested = False
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)

        start_bruteforce(self, target, charset, max_len, threads, batch)

    def stop(self):
        if not self.running:
            return
        self.stop_requested = True
        self.set_status("ABORTING", accent=self.accent_alert)
        self.log_meta("stop signal sent to worker threads.")


if __name__ == "__main__":
    mp.freeze_support()
    GUI()
