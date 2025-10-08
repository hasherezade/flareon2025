import subprocess
import shutil
import re
from pathlib import Path
from typing import List, Tuple, Optional

# Regex: capture <address> and <rest of line>
_LINE_RE = re.compile(r'^\s*([0-9a-fA-F]+)\s*:\s*(.*)$')

class DisasmCLIWrapper:
    def __init__(self, cli_path: str | Path = "disasm-cli"):
        self.cli_path = Path(cli_path)
        self._resolved = self._resolve_cli(self.cli_path)
        self.last_output: str = ""
        self.last_stderr: str = ""

    @staticmethod
    def _resolve_cli(cli_path: Path) -> str:
        if cli_path.exists():
            return str(cli_path)
        found = shutil.which(str(cli_path))
        if not found:
            raise FileNotFoundError(f"Cannot find CLI at '{cli_path}'")
        return found

    def disasm(self, pe_file: str | Path, func_name: str,
               timeout: Optional[float] = 60.0,
               cwd: Optional[str | Path] = None,
               encoding: str = "utf-8") -> List[Tuple[int, str]]:
        cmd = [self._resolved, str(Path(pe_file)), func_name]
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            encoding=encoding,
            timeout=timeout,
        )
        self.last_output = proc.stdout
        self.last_stderr = proc.stderr
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr)

        results: List[Tuple[int, str]] = []
        for line in self.last_output.splitlines():
            m = _LINE_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            rest = m.group(2).strip()
            results.append((addr, rest))
        return results

