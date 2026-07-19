import os
import re
import subprocess
import tempfile

from strelka import strelka

# Substrings retdec-decompiler writes to stderr that indicate the output is
# known to be unreliable (e.g. non-machine-code input) rather than a normal
# per-function analysis warning.
DEGRADED_OUTPUT_WARNINGS = {
    "cannot be decompiled": "non_native_bytecode_detected",
    "Statically linked code was not detected": "no_static_code_detection",
}

FUNCTION_PROTOTYPES_BANNER = (
    "// ------------------- Function Prototypes --------------------"
)
FUNCTION_PROTOTYPE_RE = re.compile(r"\b(\w+)\s*\([^;]*\);$")


def parse_function_prototypes(c_text):
    """Extracts function signatures from RetDec's "Function Prototypes"
    banner section of decompiled C output.

    Prototypes named "function_<address>" are RetDec's placeholder for
    functions it couldn't resolve a symbol/library name for -- these are
    excluded since the address alone isn't informative outside of the
    full decompiled source, which is available in the emitted child file.

    Returns a tuple of (list of named function signatures, total prototype
    count).
    """
    start = c_text.find(FUNCTION_PROTOTYPES_BANNER)
    if start == -1:
        return [], 0

    end = c_text.find("\n// ---", start + len(FUNCTION_PROTOTYPES_BANNER))
    block = c_text[start:end] if end != -1 else c_text[start:]

    named = []
    total = 0
    for line in block.splitlines():
        line = line.strip()
        if not line or not line.endswith(";"):
            continue
        match = FUNCTION_PROTOTYPE_RE.search(line)
        if not match:
            continue
        total += 1
        if not match.group(1).startswith("function_"):
            named.append(line.rstrip(";"))

    return named, total


class ScanRetdec(strelka.Scanner):
    """Decompiles PE/ELF/Mach-O binaries to C pseudocode using RetDec
    (retdec-decompiler) and re-emits the decompiled source as a child file.

    See https://github.com/avast/retdec.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/dev/shm/'.
        size_limit: Maximum input file size (in bytes) that will be sent to
            the decompiler. Decompilation time scales poorly with binary
            size/complexity. Defaults to 5000000 (5 MB).
        timeout: Value (in seconds) passed to retdec-decompiler's own
            `--timeout` flag. Defaults to 240.
        limit: Maximum number of named function signatures to log.
            Defaults to 200.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/dev/shm/")
        size_limit = options.get("size_limit", 5000000)
        timeout = options.get("timeout", 240)
        limit = options.get("limit", 200)

        if len(data) > size_limit:
            self.flags.append("file_size_limit")
            return

        with tempfile.TemporaryDirectory(dir=tmp_directory) as tmp_dir:
            input_path = os.path.join(tmp_dir, "sample")
            with open(input_path, "wb") as f:
                f.write(data)

            try:
                proc = subprocess.run(
                    [
                        "retdec-decompiler",
                        input_path,
                        "--cleanup",
                        "--timeout",
                        str(timeout),
                    ],
                    cwd=tmp_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=timeout + 30,
                )
            except subprocess.TimeoutExpired:
                self.flags.append("retdec_timeout")
                return

            stderr = proc.stderr.decode(errors="replace") if proc.stderr else ""
            self.event["warnings"] = stderr.count("Warning:")

            for substring, flag in DEGRADED_OUTPUT_WARNINGS.items():
                if substring in stderr:
                    self.flags.append(flag)

            if proc.returncode != 0:
                self.flags.append(f"return_code_{proc.returncode}")
                return

            c_path = f"{input_path}.c"
            if not os.path.isfile(c_path):
                self.flags.append("no_output_produced")
                return

            with open(c_path, "rb") as c_file:
                c_data = c_file.read()

            named_functions, total_functions = parse_function_prototypes(
                c_data.decode(errors="replace")
            )

            self.event["total"] = {
                "lines": c_data.count(b"\n"),
                "functions": total_functions,
                "named_functions": len(named_functions),
            }
            if named_functions:
                self.event["functions"] = named_functions[:limit]

            # Send decompiled pseudocode back to Strelka
            child_name = f"{file.name}.c" if file.name else "decompiled.c"
            self.emit_file(c_data, name=child_name)
