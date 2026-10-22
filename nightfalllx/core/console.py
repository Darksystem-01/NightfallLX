from __future__ import annotations

from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style
    from colorama import init as _colorama_init

    _colorama_init(autoreset=False, strip=False, convert=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    class _Fore:
        CYAN = GREEN = YELLOW = RED = MAGENTA = WHITE = ""

    class _Style:
        BRIGHT = RESET_ALL = ""

    Fore = _Fore()
    Style = _Style()


class Console:
    def __init__(
        self,
        verbose: bool = True,
        quiet: bool = False,
        logfile: Path | None = None,
    ):
        self.verbose = verbose
        self.quiet = quiet
        self._fh = None
        if logfile:
            logfile.parent.mkdir(parents=True, exist_ok=True)
            self._fh = logfile.open("a", encoding="utf-8")

    def _emit(self, tag: str, msg: str, colour: str = "") -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {tag:<5} {msg}"
        if not self.quiet:
            if _HAS_COLOR and colour:
                print(f"{colour}{line}{Style.RESET_ALL}", flush=True)
            else:
                print(line, flush=True)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def banner(self, text: str) -> None:
        if self.quiet:
            return
        bar = "=" * max(len(text) + 4, 60)
        print(f"\n{Fore.CYAN}{bar}\n  {text}\n{bar}{Style.RESET_ALL}", flush=True)

    def head(self, text: str) -> None:
        self._emit("--", text, Fore.CYAN + Style.BRIGHT)

    def info(self, msg: str) -> None:
        self._emit("INFO", msg)

    def debug(self, msg: str) -> None:
        if self.verbose:
            self._emit("DBG", msg, Fore.MAGENTA)

    def good(self, msg: str) -> None:
        self._emit("OK", msg, Fore.GREEN + Style.BRIGHT)

    def warn(self, msg: str) -> None:
        self._emit("WARN", msg, Fore.YELLOW)

    def err(self, msg: str) -> None:
        self._emit("ERR", msg, Fore.RED)

    def crit(self, msg: str) -> None:
        self._emit("CRIT", msg, Fore.RED + Style.BRIGHT)

    def raw(self, msg: str) -> None:
        if self.verbose:
            self._emit("RAW", msg, Fore.WHITE)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
