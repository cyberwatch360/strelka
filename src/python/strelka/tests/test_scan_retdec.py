from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_retdec import ScanRetdec as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_retdec(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "warnings": 0,
        "total": {"lines": mock.ANY, "functions": 9, "named_functions": 7},
        "functions": [
            "int64_t __do_global_dtors_aux(void)",
            "int64_t _fini(void)",
            "int64_t _init(void)",
            "int64_t _start(int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6)",
            "int64_t deregister_tm_clones(void)",
            "int64_t frame_dummy(void)",
            "int64_t register_tm_clones(void)",
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.elf",
        options={"timeout": 60},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
