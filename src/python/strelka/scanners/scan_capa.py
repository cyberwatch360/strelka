import json
import subprocess
import tempfile

from strelka import strelka

# Keys copied from each matched rule's ATT&CK/MBC mapping entries, dropping
# "parts" since it's redundant with objective/behavior/method combined.
MAPPING_FIELDS = ["id", "objective", "behavior", "method"]


class ScanCapa(strelka.Scanner):
    """Identifies capabilities (behaviors, ATT&CK techniques, MBC objectives)
    in PE/ELF/.NET binaries using Mandiant's capa and the capa-rules ruleset.

    See https://github.com/mandiant/capa.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/dev/shm/'.
        rules: Path to a capa-rules directory. Defaults to '/opt/capa-rules/'.
        signatures: Path to a directory of FLIRT .sig/.pat signatures used to
            identify statically-linked library functions. capa raises an
            unhandled error on PE/ELF/Mach-O input if this path doesn't
            exist, so this should always point at real signatures.
            Defaults to '/opt/capa-sigs/'.
        size_limit: Maximum input file size (in bytes) that will be sent to
            capa. Static analysis time scales poorly with binary
            size/complexity. Defaults to 5000000 (5 MB).
        timeout: Maximum time (in seconds) capa is allowed to run before
            being killed. Defaults to 300.
        limit: Maximum number of matched rules to log in detail.
            Defaults to 200.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/dev/shm/")
        rules = options.get("rules", "/opt/capa-rules/")
        signatures = options.get("signatures", "/opt/capa-sigs/")
        size_limit = options.get("size_limit", 5000000)
        timeout = options.get("timeout", 300)
        limit = options.get("limit", 200)

        if len(data) > size_limit:
            self.flags.append("file_size_limit")
            return

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            command = ["capa", "-j", "-r", rules]
            if signatures:
                command.extend(["-s", signatures])
            command.append(tmp_data.name)

            try:
                proc = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                self.flags.append("capa_timeout")
                return

            stderr = proc.stderr.decode(errors="replace") if proc.stderr else ""

            if proc.returncode != 0:
                self.flags.append(f"return_code_{proc.returncode}")
                if stderr:
                    self.event["error"] = stderr[-1000:]
                return

            if not proc.stdout:
                self.flags.append("no_output_produced")
                if stderr:
                    self.event["error"] = stderr[-1000:]
                return

            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                self.flags.append(f"capa_json_error_{e}")
                return

            analysis = report.get("meta", {}).get("analysis", {})
            self.event["format"] = analysis.get("format")
            self.event["arch"] = analysis.get("arch")
            self.event["os"] = analysis.get("os")

            matches = []
            for name, rule in report.get("rules", {}).items():
                meta = rule.get("meta", {})
                matches.append(
                    {
                        "rule": name,
                        "namespace": meta.get("namespace"),
                        "attack": [
                            {field: entry.get(field) for field in MAPPING_FIELDS}
                            for entry in meta.get("attack", [])
                        ],
                        "mbc": [
                            {field: entry.get(field) for field in MAPPING_FIELDS}
                            for entry in meta.get("mbc", [])
                        ],
                    }
                )

            matches.sort(key=lambda match: match["rule"])

            self.event["total"] = {"rules_matched": len(matches)}
            if matches:
                self.event["matches"] = matches[:limit]
