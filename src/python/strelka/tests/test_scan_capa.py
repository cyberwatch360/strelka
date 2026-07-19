from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_capa import ScanCapa as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_capa_elf(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "format": "elf",
        "arch": "amd64",
        "os": "linux",
        "total": {"rules_matched": 0},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.elf",
        options={"rules": "/opt/capa-rules/", "timeout": 90},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_capa_dotnet(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "format": "dotnet",
        "arch": "amd64",
        "os": "any",
        "total": {"rules_matched": 4},
        "matches": [
            {
                "rule": "(internal) .NET file limitation",
                "namespace": "internal/limitation/dynamic",
                "attack": [],
                "mbc": [],
            },
            {
                "rule": "compiled to the .NET platform",
                "namespace": "runtime/dotnet",
                "attack": [],
                "mbc": [],
            },
            {
                "rule": "contains PDB path",
                "namespace": "executable/pe/pdb",
                "attack": [],
                "mbc": [],
            },
            {
                "rule": "manipulate console buffer",
                "namespace": "host-interaction/console",
                "attack": [],
                "mbc": [
                    {
                        "id": "C0033",
                        "objective": "Operating System",
                        "behavior": "Console",
                        "method": "",
                    }
                ],
            },
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
        options={"rules": "/opt/capa-rules/", "timeout": 90},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
