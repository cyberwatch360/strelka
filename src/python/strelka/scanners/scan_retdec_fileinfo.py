import json
import subprocess
import tempfile

from strelka import strelka

# Top-level retdec-fileinfo keys that are small/bounded and safe to copy verbatim.
DIRECT_KEYS = [
    "fileFormat",
    "fileClass",
    "fileType",
    "architecture",
    "endianness",
    "entryPoint",
    "packed",
    "tools",
    "languages",
    "warnings",
    "anomalyTable",
    "missingDeps",
    "pdbInfo",
    "versionInfo",
    "telfhash",
]

# Keys that hold potentially large lists -- these are summarized with a
# total count plus a capped, trimmed-down list of entries rather than
# copied verbatim (retdec-fileinfo can report thousands of imports/sections
# for large binaries).
TABLE_KEYS = {
    "sectionTable": ("sections", ["index", "name", "sizeInFile", "entropy", "flags"]),
    "segmentTable": ("segments", ["index", "type", "sizeInFile", "flags"]),
    "importTable": ("imports", ["index", "name", "usageType", "address"]),
    "exportTable": ("exports", ["index", "name", "address"]),
    "resourceTable": ("resources", ["index", "type", "language", "size"]),
}


class ScanRetdecFileinfo(strelka.Scanner):
    """Collects file format, packer/compiler, and structural metadata using
    RetDec's static analysis tool (retdec-fileinfo).

    See https://github.com/avast/retdec.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/dev/shm/'.
        limit: Maximum number of entries to log from large tables (imports,
            exports, sections, segments, resources).
            Defaults to 100.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/dev/shm/")
        limit = options.get("limit", 100)

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            try:
                stdout, stderr = subprocess.Popen(
                    ["retdec-fileinfo", "-j", "--verbose", tmp_data.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()

                if not stdout:
                    self.flags.append("no_output_produced")
                    if stderr:
                        self.event["error"] = stderr.decode(errors="replace")[:500]
                    return

                report = json.loads(stdout)

                for key in DIRECT_KEYS:
                    if key in report:
                        self.event[key] = report[key]

                total = {}
                for report_key, (event_key, fields) in TABLE_KEYS.items():
                    table = report.get(report_key)
                    if not table:
                        continue

                    # importTable/exportTable/sectionTable are objects with a
                    # count field and a nested list; segmentTable is a bare list.
                    entries = (
                        table if isinstance(table, list) else table.get(event_key, [])
                    )

                    total[event_key] = len(entries)
                    self.event[event_key] = [
                        {field: entry[field] for field in fields if field in entry}
                        for entry in entries[:limit]
                    ]

                if total:
                    self.event["total"] = total

            except json.JSONDecodeError as e:
                self.flags.append(f"retdec_fileinfo_json_error_{e}")
            except Exception as e:
                self.flags.append(f"retdec_fileinfo_error_{e}")
