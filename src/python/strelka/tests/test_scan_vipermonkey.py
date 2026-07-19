from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_vipermonkey import ScanVipermonkey as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_vipermonkey(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"actions": 2, "vba_builtins": 1, "shellcode_blobs": 0},
        "actions": [
            {
                "action": "Found Entry Point",
                "description": "",
                "parameters": "autoopen",
            },
            {
                "action": "Execute Command",
                "description": "Shell function",
                "parameters": "powershell.exe -enc SGVsbG8=",
            },
        ],
        "vba_builtins": ["Shell"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_vipermonkey.vba",
        options={"timeout": 60},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_vipermonkey_no_macros(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["no_macros_found"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.doc",
        options={"timeout": 60},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
