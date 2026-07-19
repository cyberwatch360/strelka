from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_retdec_fileinfo import ScanRetdecFileinfo as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_retdec_fileinfo(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "fileFormat": "ELF",
        "fileClass": "64-bit",
        "fileType": "DLL",
        "architecture": "x86-64",
        "endianness": "Little endian",
        "entryPoint": {
            "address": "0x1060",
            "offset": "0x1060",
            "sectionName": ".text",
            "sectionIndex": "16",
            "bytes": mock.ANY,
        },
        "packed": "probably no",
        "tools": [
            {
                "type": "compiler",
                "name": "GCC",
                "version": "12.2.0",
                "method": ".comment section heuristic",
                "heuristics": True,
                "identicalSignificantNibbles": 0,
                "totalSignificantNibbles": 0,
                "percentage": 0.0,
            }
        ],
        "missingDeps": {"count": "0"},
        "versionInfo": {},
        "sections": mock.ANY,
        "segments": mock.ANY,
        "imports": [
            {
                "index": "0",
                "name": "__libc_start_main",
                "usageType": "FUNCTION",
                "address": "0x3fd8",
            },
            {
                "index": "1",
                "name": "_ITM_deregisterTMCloneTable",
                "usageType": "UNKNOWN",
                "address": "0x3fe0",
            },
            {
                "index": "2",
                "name": "puts",
                "usageType": "FUNCTION",
                "address": "0x3fd0",
            },
            {
                "index": "3",
                "name": "__gmon_start__",
                "usageType": "UNKNOWN",
                "address": "0x3fe8",
            },
            {
                "index": "4",
                "name": "_ITM_registerTMCloneTable",
                "usageType": "UNKNOWN",
                "address": "0x3ff0",
            },
            {
                "index": "5",
                "name": "__cxa_finalize",
                "usageType": "FUNCTION",
                "address": "0x3ff8",
            },
        ],
        "total": {"sections": 31, "segments": 13, "imports": 6},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.elf",
        options={},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
