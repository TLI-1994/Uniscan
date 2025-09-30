from pathlib import Path

from usentinel.binaries import BinaryClassifier


def test_classifier_detects_known_extensions(tmp_path):
    dll = tmp_path / "plugin.dll"
    dll.write_bytes(b"MZ\x00\x00")

    classifier = BinaryClassifier()
    finding = classifier.classify(dll)

    assert finding is not None
    assert finding.path == dll
    assert finding.kind == "dll"


def test_classifier_ignores_non_binaries(tmp_path):
    txt = tmp_path / "notes.txt"
    txt.write_text("hello")

    classifier = BinaryClassifier()
    assert classifier.classify(txt) is None


def test_classifier_detects_magic_numbers(tmp_path):
    macho = tmp_path / "bundle"
    macho.write_bytes(bytes.fromhex("cf fa ed fe"))

    classifier = BinaryClassifier()
    finding = classifier.classify(macho)

    assert finding is not None
    assert finding.kind == "mach-o"
