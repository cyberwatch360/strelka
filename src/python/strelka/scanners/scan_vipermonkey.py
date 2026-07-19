import json
import os
import subprocess
import tempfile

from strelka import strelka

# Substrings ViperMonkey writes to its combined stdout/stderr output that
# indicate a benign "nothing to analyze" or "couldn't parse" result rather
# than a real tool failure. ViperMonkey exits non-zero and never writes its
# -o JSON file in both cases, so these have to be distinguished by text.
NO_MACROS_STRINGS = ("No VBA macros found", "No VBA or XLM macros found")
PARSE_ERROR_STRING = "Parse Error"


class ScanVipermonkey(strelka.Scanner):
    """Emulates VBA macros in Office documents using ViperMonkey to surface
    deobfuscated strings and runtime actions (e.g. resolved Shell commands)
    that static macro analysis alone would miss.

    See https://github.com/decalage2/ViperMonkey.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/dev/shm/'.
        vmonkey_bin: Path to the vmonkey executable. ViperMonkey only runs
            under Python 2, so it's installed in an isolated interpreter
            separate from Strelka's own Python 3 environment.
            Defaults to '/opt/python2.7/bin/vmonkey'.
        size_limit: Maximum input file size (in bytes) that will be sent to
            ViperMonkey. Emulation time scales poorly with macro
            complexity. Defaults to 5000000 (5 MB).
        timeout: Maximum time (in seconds) ViperMonkey is allowed to run
            before being killed. Defaults to 180.
        limit: Maximum number of recorded actions to log. Defaults to 200.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/dev/shm/")
        vmonkey_bin = options.get("vmonkey_bin", "/opt/python2.7/bin/vmonkey")
        size_limit = options.get("size_limit", 5000000)
        timeout = options.get("timeout", 180)
        limit = options.get("limit", 200)

        if len(data) > size_limit:
            self.flags.append("file_size_limit")
            return

        with tempfile.TemporaryDirectory(dir=tmp_directory) as tmp_dir:
            input_path = os.path.join(tmp_dir, "sample")
            with open(input_path, "wb") as f:
                f.write(data)

            out_path = f"{input_path}.json"

            try:
                proc = subprocess.run(
                    [vmonkey_bin, "-o", out_path, input_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                self.flags.append("vipermonkey_timeout")
                return

            output = proc.stdout.decode(errors="replace") if proc.stdout else ""

            if not os.path.isfile(out_path):
                if any(s in output for s in NO_MACROS_STRINGS):
                    self.flags.append("no_macros_found")
                elif PARSE_ERROR_STRING in output:
                    self.flags.append("parse_error")
                else:
                    self.flags.append(f"return_code_{proc.returncode}")
                    self.event["error"] = output[-1000:]
                return

            with open(out_path, "r") as out_file:
                try:
                    report = json.load(out_file)
                except json.JSONDecodeError as e:
                    self.flags.append(f"vipermonkey_json_error_{e}")
                    return

            actions = report.get("actions", [])
            builtins = report.get("vba_builtins", [])
            shellcode = report.get("shellcode", [])

            self.event["total"] = {
                "actions": len(actions),
                "vba_builtins": len(builtins),
                "shellcode_blobs": len(shellcode),
            }
            if actions:
                self.event["actions"] = actions[:limit]
            if builtins:
                self.event["vba_builtins"] = builtins

            iocs = report.get("potential_iocs", [])
            if iocs:
                self.add_iocs(iocs)
