"""
File Threat Scanner Module
Analyzes filenames (and, when available, file content) for suspicious
characteristics. This module never executes, imports, or interprets
uploaded content — it only reads raw bytes for signature inspection.
"""

import hashlib
import os
import re
from typing import Dict, List, Optional

MAX_SCAN_BYTES = 8 * 1024 * 1024  # only hash/inspect up to 8MB of content

DANGEROUS_EXTENSIONS = {
    ".exe": "Windows executable", ".bat": "Batch script", ".cmd": "Command file",
    ".com": "MS-DOS executable", ".pif": "Program information file", ".scr": "Screen saver",
    ".vbs": "Visual Basic script", ".vbe": "Encoded VB script", ".js": "JavaScript file",
    ".jse": "Encoded JavaScript", ".ws": "Windows Script", ".wsh": "Windows Script Host",
    ".ps1": "PowerShell script", ".ps2": "PowerShell script", ".psc1": "PowerShell script",
    ".psc2": "PowerShell script", ".msi": "Windows installer", ".msp": "Windows patch",
    ".jar": "Java archive", ".class": "Java class file", ".jnlp": "Java Web Start",
    ".app": "macOS application bundle", ".dmg": "macOS disk image", ".pkg": "macOS installer",
    ".run": "Unix executable", ".bin": "Binary executable", ".sh": "Shell script",
    ".bash": "Bash script", ".zsh": "Zsh script", ".docm": "Word macro-enabled document",
    ".xlsm": "Excel macro-enabled workbook", ".pptm": "PowerPoint macro-enabled presentation",
    ".dll": "Windows dynamic-link library", ".sys": "Windows system driver", ".hta": "HTML application",
    ".lnk": "Windows shortcut", ".reg": "Windows registry file", ".gadget": "Windows gadget",
    ".vb": "Visual Basic file", ".wsf": "Windows Script File", ".scf": "Windows Explorer command",
}

SUSPICIOUS_EXTENSIONS = {
    ".pdf": "PDF (can contain embedded scripts)",
    ".doc": "Legacy Word document (can contain macros)",
    ".xls": "Legacy Excel spreadsheet (can contain macros)",
    ".ppt": "Legacy PowerPoint (can contain macros)",
    ".rtf": "Rich text document (occasionally used to smuggle exploits)",
    ".iso": "Disk image (can hide executables from mail scanners)",
    ".img": "Disk image (can hide executables from mail scanners)",
    ".zip": "Compressed archive (contents unknown until extracted)",
    ".rar": "Compressed archive (contents unknown until extracted)",
    ".7z": "Compressed archive (contents unknown until extracted)",
    ".ace": "Compressed archive (contents unknown until extracted)",
    ".cab": "Cabinet archive (contents unknown until extracted)",
    ".gz": "Compressed archive (contents unknown until extracted)",
    ".tar": "Archive (contents unknown until extracted)",
}

DANGEROUS_DOUBLE_EXTENSIONS = [
    ".exe.txt", ".exe.doc", ".exe.pdf", ".exe.jpg", ".exe.png",
    ".zip.txt", ".zip.doc", ".bat.txt", ".bat.doc", ".cmd.txt", ".cmd.doc",
    ".jar.pdf", ".scr.txt", ".scr.doc", ".vbs.txt", ".js.txt", ".pif.doc",
    ".com.doc", ".hta.doc",
]

# Extensions where a second dot is a normal naming convention, not a
# spoofing attempt (e.g. "report.final.docx", "archive.tar.gz").
BENIGN_COMPOUND_SUFFIXES = {".tar.gz", ".tar.bz2", ".tar.xz"}

SUSPICIOUS_FILENAME_PATTERNS = {
    r"invoice.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like an invoice but is an executable/script",
    r"receipt.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a receipt but is an executable/script",
    r"document.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a document but is an executable/script",
    r"image.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like an image but is an executable/script",
    r"photo.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a photo but is an executable/script",
    r"video.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a video but is an executable/script",
    r"resume.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a resume but is an executable/script",
    r"cv.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a CV but is an executable/script",
    r"scan.*\.(exe|scr|bat|cmd|js|vbs)": "Looks like a scanned document but is an executable/script",
}

# Magic-byte signatures for common formats, used only for identification.
# Files are never parsed further or executed.
MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE executable (.exe/.dll)"),
    (b"\x7fELF", "Linux/Unix ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class (fat binary or class file)"),
    (b"PK\x03\x04", "ZIP-based archive (zip/docx/xlsx/jar/apk — inspect contents before trusting)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy Microsoft Office document (doc/xls/ppt)"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"#!/", "Script with shebang (may execute as a program on Unix)"),
]


def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identify_magic_bytes(data: bytes) -> Optional[str]:
    for signature, description in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return description
    return None


def scan_file(filename: str, file_bytes: Optional[bytes] = None) -> Dict:
    """
    Scan a file for potential security threats using filename heuristics
    and, if bytes are provided, content-based signature inspection.

    Args:
        filename: The filename to analyze.
        file_bytes: Optional raw file content (never executed or parsed
            beyond reading a magic-byte header and hashing).

    Returns:
        Dict with filename, extension, threat_level, risk_score,
        indicators, recommendation, and a details breakdown.
    """
    if not isinstance(filename, str) or not filename.strip():
        return {
            "filename": filename,
            "extension": "",
            "threat_level": "Invalid",
            "risk_score": 0,
            "indicators": ["No filename provided"],
            "recommendation": "Enter a filename to analyze.",
            "details": {},
        }

    # Strip any directory components — only the basename should be analyzed.
    filename = os.path.basename(filename.strip())

    indicators: List[str] = []
    risk_score = 0

    _, file_extension = os.path.splitext(filename)
    file_extension = file_extension.lower()
    filename_lower = filename.lower()

    # ---- CHECK: Dangerous / suspicious extension ----
    if file_extension in DANGEROUS_EXTENSIONS:
        indicators.append(f"Dangerous file type: {file_extension} ({DANGEROUS_EXTENSIONS[file_extension]})")
        risk_score += 3
    elif file_extension in SUSPICIOUS_EXTENSIONS:
        indicators.append(f"Potentially risky file type: {file_extension} ({SUSPICIOUS_EXTENSIONS[file_extension]})")
        risk_score += 1

    # ---- CHECK: Double / compound extensions ----
    is_benign_compound = any(filename_lower.endswith(suffix) for suffix in BENIGN_COMPOUND_SUFFIXES)
    dot_count = filename.count(".")
    if dot_count > 1 and not is_benign_compound:
        parts = filename.split(".")
        prior_ext = "." + parts[-2]
        final_ext = "." + parts[-1]
        # Only flag as suspicious if the *inner* extension looks like a
        # real file type being masked (not just a versioned/dated name).
        if prior_ext in DANGEROUS_EXTENSIONS or prior_ext in SUSPICIOUS_EXTENSIONS or prior_ext.lower() in {
            ".exe", ".doc", ".pdf", ".jpg", ".png", ".txt", ".zip",
        }:
            indicators.append(
                f"Filename has multiple extensions ({prior_ext} + {final_ext}) — "
                "attackers use this to disguise dangerous file types"
            )
            risk_score += 2

    # ---- CHECK: Known dangerous double-extension patterns ----
    for double_ext in DANGEROUS_DOUBLE_EXTENSIONS:
        if filename_lower.endswith(double_ext):
            indicators.append(
                f"Suspicious double extension detected: {double_ext} — "
                "the file claims to be one type but is actually another"
            )
            risk_score += 3
            break

    # ---- CHECK: Space before extension (Windows can hide the real extension) ----
    if re.search(r" \.[a-zA-Z0-9]+$", filename):
        indicators.append("Filename contains a space before the extension, a technique used to hide the real file type")
        risk_score += 1

    # ---- CHECK: RTLO / unicode direction-override trick ----
    if "\u202e" in filename or "\u202d" in filename:
        indicators.append("Filename contains a Unicode text-direction override character, often used to disguise extensions (RTLO attack)")
        risk_score += 3

    # ---- CHECK: Suspicious filename pattern ----
    for pattern, description in SUSPICIOUS_FILENAME_PATTERNS.items():
        if re.search(pattern, filename_lower):
            indicators.append(f"Suspicious filename pattern: {description}")
            risk_score += 2
            break

    # ---- CHECK: Filename length ----
    if len(filename) > 255:
        indicators.append("Filename is unusually long, which can indicate obfuscation")
        risk_score += 1
    elif len(filename) > 100:
        indicators.append("Filename is quite long")
        risk_score += 1

    # ---- CHECK: Excessive special characters ----
    special_char_count = sum(1 for c in filename if not c.isalnum() and c not in ".-_ ")
    if special_char_count > 5:
        indicators.append("Filename contains an unusually high number of special characters")
        risk_score += 1

    # ---- CHECK: No extension ----
    if not file_extension:
        indicators.append("File has no extension — some systems can still execute extensionless files")
        risk_score += 1

    # ---- CHECK: Content-based inspection (only if bytes were provided) ----
    content_info = {}
    if file_bytes is not None:
        truncated = file_bytes[:MAX_SCAN_BYTES]
        sha256 = _sha256_of_bytes(truncated if len(file_bytes) > MAX_SCAN_BYTES else file_bytes)
        detected_type = _identify_magic_bytes(truncated)
        content_info = {
            "sha256": sha256,
            "size_bytes": len(file_bytes),
            "detected_type": detected_type or "Unrecognized / no known signature matched",
            "truncated_for_hash": len(file_bytes) > MAX_SCAN_BYTES,
        }

        # Extension/content mismatch is one of the strongest real signals.
        if detected_type and "PE executable" in detected_type and file_extension not in (".exe", ".dll", ".sys", ".scr", ".com"):
            indicators.append(
                f"Content mismatch: file is actually a Windows executable but has the extension '{file_extension or '(none)'}'"
            )
            risk_score += 4
        elif detected_type and "ELF" in detected_type and file_extension not in (".sh", ".bin", ".run", ""):
            indicators.append(
                f"Content mismatch: file is actually a Linux/Unix executable but has the extension '{file_extension or '(none)'}'"
            )
            risk_score += 4
        elif detected_type and "shebang" in detected_type and file_extension not in (".sh", ".bash", ".zsh", ".py", ".pl", ".rb"):
            indicators.append("File begins with a shebang line, meaning it may run as an executable script on Unix systems")
            risk_score += 2

    risk_score = min(risk_score, 12)

    if risk_score == 0:
        threat_level = "Safe \u2705"
        recommendation = "No suspicious indicators found in the filename" + (" or content." if file_bytes is not None else ".")
    elif risk_score <= 1:
        threat_level = "Low Risk \u2705"
        recommendation = "Generally low risk, but always be cautious with unexpected files."
    elif risk_score <= 3:
        threat_level = "Medium Risk \u26a0\ufe0f"
        recommendation = "Exercise caution. Scan with antivirus before opening."
    elif risk_score <= 6:
        threat_level = "High Risk \U0001f534"
        recommendation = "Shows concerning characteristics. Do not open unless you are certain of the source."
    else:
        threat_level = "Very Dangerous \U0001f6d1"
        recommendation = "Do not open this file. It shows strong signs of being malicious or disguised."

    return {
        "filename": filename,
        "extension": file_extension if file_extension else "No extension",
        "threat_level": threat_level,
        "risk_score": risk_score,
        "indicators": indicators if indicators else ["No suspicious indicators detected"],
        "recommendation": recommendation,
        "details": {
            "is_known_dangerous_extension": file_extension in DANGEROUS_EXTENSIONS,
            "extension_type": DANGEROUS_EXTENSIONS.get(file_extension) or SUSPICIOUS_EXTENSIONS.get(file_extension, "Unknown / not flagged"),
            "filename_length": len(filename),
            "has_multiple_extensions": dot_count > 1 and not is_benign_compound,
            **content_info,
        },
    }


def get_file_security_tips() -> List[str]:
    """Return file security tips."""
    return [
        "Enable viewing of file extensions in your operating system",
        "Be suspicious of unexpected attachments, even from known contacts",
        "Use updated antivirus/anti-malware software",
        "Be wary of executable files (.exe, .bat, .scr, .js)",
        "Don't open email attachments from unknown senders",
        "Download files only from trusted, official sources",
        "Be careful with archive files (.zip, .rar) from unknown sources — scan contents before extracting",
        "Disable macros in Office documents by default",
        "Keep your operating system and software updated",
        "When in doubt, scan the file with antivirus software first",
        "Don't open files from untrusted USB drives or removable storage",
    ]


def categorize_file(filename: str) -> Dict:
    """Categorize a file by extension."""
    _, extension = os.path.splitext(filename)
    extension = extension.lower()

    categories = {
        "executable": [".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".msi", ".app", ".jar", ".dll"],
        "script": [".vbs", ".js", ".ps1", ".sh", ".bash", ".py", ".pl"],
        "document": [".doc", ".docx", ".docm", ".pdf", ".txt", ".rtf", ".odt"],
        "spreadsheet": [".xls", ".xlsx", ".xlsm", ".csv", ".ods"],
        "presentation": [".ppt", ".pptx", ".pptm", ".odp"],
        "image": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg"],
        "video": [".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv", ".webm"],
        "audio": [".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg"],
        "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".ace", ".cab"],
    }

    for category, extensions in categories.items():
        if extension in extensions:
            return {
                "filename": filename,
                "extension": extension,
                "category": category,
                "description": f"{category.capitalize()} file",
            }

    return {
        "filename": filename,
        "extension": extension,
        "category": "other",
        "description": "Unknown file type",
    }
