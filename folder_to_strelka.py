#!/usr/bin/env python3
"""
Recursively and heuristically discover candidate malware sample files in a
folder, scan each one with Strelka, and write one JSON result file per
sample (keyed by content sha256) to an output directory.

"Heuristic" discovery means:
    - non-sample files are skipped by extension/filename (readme, .csv, .log, ...)
      and by size (empty or larger than --max-size)
    - zip archives (including AES-encrypted ones, e.g. password "infected") are
      auto-extracted and their contents treated as candidate samples, recursively
      up to --max-depth
    - samples are de-duplicated by sha256 content hash, and already-scanned
      samples (an existing json_output/<sha256>.json) are skipped unless
      --overwrite is given, so a folder can be re-run incrementally

Requirements:
    pip install pyzipper   (optional but recommended, for AES-encrypted zips)

Usage:
    python folder_to_strelka.py --input-dir ./incoming_samples
    python folder_to_strelka.py --input-dir ./incoming_samples --workers 16 --keep-samples
"""

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

try:
    import pyzipper

    ZipOpener = pyzipper.AESZipFile
except ImportError:
    ZipOpener = zipfile.ZipFile

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("folder2strelka")

# Substring gRPC prints when a queued-too-long scan gets dropped server-side;
# worth a retry rather than a permanent failure.
CANCELLED_STREAM_MARKER = "RST_STREAM"

SKIP_EXTENSIONS = {
    ".aaa"
}
SKIP_FILENAMES = {
    "readme",
    "readme.md",
    "readme.txt",
    "license",
    "thumbs.db",
    ".ds_store",
}
ARCHIVE_PASSWORDS = [None, b"infected", b"malware", b"virus"]


class Candidate:
    """A discovered candidate sample: its bytes, a display name, and (if it
    came out of an archive) the archive it came from."""

    __slots__ = ("data", "name", "source_archive", "sha256")

    def __init__(self, data: bytes, name: str, source_archive: str = None):
        self.data = data
        self.name = name
        self.source_archive = source_archive
        self.sha256 = hashlib.sha256(data).hexdigest()


def looks_like_sample(path: Path, max_size: int) -> bool:
    if path.name.lower() in SKIP_FILENAMES:
        return False
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    return 0 < size <= max_size


def try_extract_archive(path: Path) -> dict:
    """If path is a zip archive (optionally AES-encrypted), return {name: bytes}
    for its members. Returns {} if it's not a zip or no password worked."""
    if not zipfile.is_zipfile(path):
        return {}

    for pwd in ARCHIVE_PASSWORDS:
        try:
            with ZipOpener(path) as zf:
                members = {
                    Path(info.filename).name: zf.read(info.filename, pwd=pwd)
                    for info in zf.infolist()
                    if not info.is_dir()
                }
                if members:
                    return members
        except RuntimeError:
            continue  # wrong password
        except Exception as e:
            # Real-world (and especially malware) zips are frequently
            # malformed in ways that are specific to whichever zip
            # implementation reads them (pyzipper vendors its own BadZipFile
            # class, distinct from zipfile.BadZipFile) -- any failure here
            # just means "not extractable", never worth crashing the batch.
            log.debug("could not open archive %s: %s", path, e)
            return {}
    return {}


def list_unique_extensions(root: Path) -> dict:
    """Walk root and count files by lowercase extension ("<none>" if there
    isn't one), without reading file contents."""
    counts = {}
    for _dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            ext = Path(filename).suffix.lower() or "<none>"
            counts[ext] = counts.get(ext, 0) + 1
    return counts


def discover_samples(root: Path, max_size: int, max_depth: int) -> list:
    """Walk root recursively, extracting archives, and return a de-duplicated
    (by content sha256) list of Candidate objects."""
    seen_hashes = set()
    candidates = []

    def add_candidate(data: bytes, name: str, source_archive: str = None):
        c = Candidate(data, name, source_archive)
        if c.sha256 in seen_hashes:
            return
        seen_hashes.add(c.sha256)
        candidates.append(c)

    def walk_archive_bytes(name: str, data: bytes, depth: int):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            members = try_extract_archive(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        if not members:
            add_candidate(data, name)
            return

        for member_name, member_data in members.items():
            if len(member_data) == 0 or len(member_data) > max_size:
                continue
            if depth < max_depth and _looks_like_zip_bytes(member_data):
                walk_archive_bytes(member_name, member_data, depth + 1)
            else:
                add_candidate(member_data, member_name, source_archive=name)

    def _looks_like_zip_bytes(data: bytes) -> bool:
        return data[:2] == b"PK"

    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if not looks_like_sample(path, max_size):
                continue
            try:
                data = path.read_bytes()
            except OSError as e:
                log.warning("could not read %s: %s", path, e)
                continue

            try:
                if max_depth > 0 and _looks_like_zip_bytes(data):
                    walk_archive_bytes(str(path), data, 0)
                else:
                    add_candidate(data, str(path))
            except Exception as e:
                # Discovery must never abort the whole run over one weird
                # file -- fall back to treating it as an opaque candidate.
                log.warning("failed to process %s, adding as-is: %s", path, e)
                add_candidate(data, str(path))

    return candidates


def scan_with_strelka(file_path: Path, strelka_bin: str, server: str, timeout: int):
    proc = subprocess.run(
        [
            strelka_bin,
            "-f",
            str(file_path),
            "-l",
            "-",
            "-s",
            server,
            "-t",
            str(timeout),
        ],
        capture_output=True,
        timeout=timeout + 15,
    )
    events = []
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    return events, stderr


def scan_with_retry(
    sample_path: Path, args, scan_semaphore: threading.BoundedSemaphore
):
    """Scan a file with Strelka, limiting how many scans run at once (to match
    real backend capacity) and retrying if the backend cancels a scan that
    was queued too long behind others."""
    last_stderr = ""
    for attempt in range(1, args.scan_retries + 2):
        with scan_semaphore:
            events, stderr = scan_with_strelka(
                sample_path, args.strelka_bin, args.strelka_server, args.timeout
            )
        if events or CANCELLED_STREAM_MARKER not in stderr:
            return events, stderr
        last_stderr = stderr
        if attempt <= args.scan_retries:
            time.sleep(2**attempt)
    return [], last_stderr


def process_candidate(
    candidate: Candidate, args, scan_semaphore: threading.BoundedSemaphore
) -> str:
    out_path = args.json_output_dir / f"{candidate.sha256}.json"
    if out_path.exists() and not args.overwrite:
        return "skipped"

    tmp_dir = Path(tempfile.mkdtemp(prefix="heuristic_sample_"))
    try:
        sample_path = tmp_dir / Path(candidate.name).name
        sample_path.write_bytes(candidate.data)

        try:
            events, stderr = scan_with_retry(sample_path, args, scan_semaphore)
        except subprocess.TimeoutExpired:
            log.warning(
                "[%s] strelka scan timed out (%s)", candidate.sha256, candidate.name
            )
            return "scan_timeout"
        except FileNotFoundError:
            log.error(
                "strelka-oneshot binary not found at %r -- pass --strelka-bin",
                args.strelka_bin,
            )
            return "strelka_not_found"

        result = {
            "sha256": candidate.sha256,
            "original_name": candidate.name,
            "source_archive": candidate.source_archive,
            "file_size": len(candidate.data),
            "strelka_events": events,
        }
        if stderr:
            result["strelka_stderr"] = stderr[-2000:]

        args.json_output_dir.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        if args.keep_samples:
            keep_dir = args.samples_dir
            keep_dir.mkdir(parents=True, exist_ok=True)
            keep_dir.joinpath(f"{candidate.sha256}_{sample_path.name}").write_bytes(
                candidate.data
            )

        return "ok"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Heuristically discover sample files in a folder and scan them with Strelka",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input-dir", type=Path, required=True, help="Folder to search for samples"
    )
    parser.add_argument("--json-output-dir", type=Path, default=Path("json_output"))
    parser.add_argument("--samples-dir", type=Path, default=Path("samples/extracted"))
    parser.add_argument(
        "--keep-samples",
        action="store_true",
        help="Also save discovered/extracted sample bytes to --samples-dir",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=200 * 1024 * 1024,
        help="Skip files larger than this many bytes (default 200MB)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Max nested-archive recursion depth (0 disables archive extraction)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=16,
        help="Number of worker threads. Must be >= --scan-concurrency, otherwise the "
        "thread pool itself caps concurrency below what the backend can handle "
        "(actual Strelka submission concurrency is governed by --scan-concurrency)",
    )
    parser.add_argument(
        "--scan-concurrency",
        type=int,
        default=16,
        help="Number of files submitted to Strelka at once. Set this to the number of "
        "Strelka backend workers you actually have running -- higher than that causes "
        "scans to queue up and get cancelled once they exceed --timeout (default 16, "
        "matching the current backend replica count)",
    )
    parser.add_argument(
        "--scan-retries",
        type=int,
        default=2,
        help="Retries for a scan that gets cancelled while queued behind others",
    )
    parser.add_argument(
        "--strelka-bin",
        default="strelka-oneshot.exe" if os.name == "nt" else "strelka-oneshot",
        help="Path to the strelka-oneshot CLI binary",
    )
    parser.add_argument(
        "--strelka-server", default="127.0.0.1:57314", help="Strelka frontend address"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=360,
        help="Per-file Strelka scan timeout, in seconds",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Re-scan samples that already have a JSON result",
    )
    return parser


def main():
    args = build_arg_parser().parse_args()

    if not args.input_dir.is_dir():
        log.error("--input-dir %s is not a directory", args.input_dir)
        sys.exit(1)

    args.json_output_dir.mkdir(parents=True, exist_ok=True)

    log.info("Scanning %s for unique file extensions ...", args.input_dir)
    ext_counts = list_unique_extensions(args.input_dir)
    log.info("Found %d unique extension(s):", len(ext_counts))
    for ext, count in sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        log.info("  %-15s %d", ext, count)

    log.info("Discovering candidate samples under %s ...", args.input_dir)
    candidates = discover_samples(args.input_dir, args.max_size, args.max_depth)
    log.info("Discovered %d unique candidate sample(s)", len(candidates))
    if not candidates:
        return

    stats = {}
    start = time.time()
    scan_semaphore = threading.BoundedSemaphore(args.scan_concurrency)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_candidate, c, args, scan_semaphore): c
            for c in candidates
        }
        try:
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                candidate = futures[future]
                try:
                    status = future.result()
                except Exception as e:
                    log.error("[%s] unexpected error: %s", candidate.sha256, e)
                    status = "error"
                stats[status] = stats.get(status, 0) + 1
                log.info(
                    "(%d/%d) %s (%s) -> %s",
                    i,
                    len(candidates),
                    candidate.sha256,
                    candidate.name,
                    status,
                )
        except KeyboardInterrupt:
            log.warning("Interrupted, cancelling remaining work...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    elapsed = time.time() - start
    log.info("Done in %.1fs: %s", elapsed, stats)


if __name__ == "__main__":
    main()
