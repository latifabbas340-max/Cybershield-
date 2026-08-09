import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.file_scanner import categorize_file, scan_file


def test_safe_filename():
    result = scan_file("holiday_photo.jpg")
    assert result["risk_score"] == 0
    assert "Safe" in result["threat_level"]


def test_dangerous_extension_flagged():
    result = scan_file("update.exe")
    assert result["risk_score"] >= 3
    assert result["details"]["is_known_dangerous_extension"] is True


def test_double_extension_attack_flagged():
    result = scan_file("invoice.pdf.exe")
    assert result["risk_score"] >= 5


def test_benign_multi_dot_filename_not_flagged():
    result = scan_file("quarterly_report.final.docx")
    assert result["risk_score"] == 0


def test_benign_tar_gz_not_flagged_as_double_extension():
    result = scan_file("backup.tar.gz")
    assert result["details"]["has_multiple_extensions"] is False


def test_path_traversal_stripped_to_basename():
    result = scan_file("../../etc/passwd.exe")
    assert result["filename"] == "passwd.exe"


def test_content_mismatch_detected():
    fake_pdf_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50
    result = scan_file("totally_a_pdf.pdf", file_bytes=fake_pdf_bytes)
    assert result["risk_score"] >= 4
    assert any("mismatch" in i.lower() for i in result["indicators"])


def test_matching_content_and_extension_not_penalized_for_mismatch():
    real_pdf_bytes = b"%PDF-1.4\n" + b"\x00" * 50
    result = scan_file("document.pdf", file_bytes=real_pdf_bytes)
    assert not any("mismatch" in i.lower() for i in result["indicators"])


def test_empty_filename_handled_gracefully():
    result = scan_file("")
    assert result["threat_level"] == "Invalid"


def test_categorize_file():
    result = categorize_file("song.mp3")
    assert result["category"] == "audio"
  
