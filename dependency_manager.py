"""Dependency discovery and isolated installation for GOO HOST projects."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

PYTHON_STDLIB = {
    "abc", "argparse", "ast", "asyncio", "base64", "collections", "concurrent", "contextlib",
    "copy", "csv", "datetime", "decimal", "email", "enum", "functools", "glob",
    "hashlib", "http", "importlib", "inspect", "io", "itertools", "json", "logging", "math",
    "multiprocessing", "os", "pathlib", "pickle", "platform", "queue", "random", "re", "secrets",
    "shutil", "signal", "socket", "sqlite3", "statistics", "string", "subprocess", "sys",
    "tempfile", "textwrap", "threading", "time", "typing", "unittest", "urllib", "uuid", "venv",
    "warnings", "xml", "zipfile",
}
IMPORT_PACKAGE_MAP = {
    "PIL": "Pillow", "cv2": "opencv-python", "yaml": "PyYAML", "bs4": "beautifulsoup4",
    "telegram": "python-telegram-bot", "telebot": "pyTelegramBotAPI", "dotenv": "python-dotenv",
    "sklearn": "scikit-learn", "fitz": "PyMuPDF", "Crypto": "pycryptodome",
}

@dataclass
class DependencyResult:
    language: str = "none"
    manager: str = "none"
    files: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    fingerprint: str = ""
    installed: bool = False
    skipped: bool = False
    message: str = ""


def _emit(log: Callable[[str], None], stage: str, message: str) -> None:
    log(f"[ {stage.upper()} ] {message}")


def _safe_project(path: str | Path) -> Path:
    return Path(path).resolve()


def _run(command: list[str], cwd: Path, log: Callable[[str], None], timeout: int = 600) -> int:
    _emit(log, "exec", " ".join(command))
    proc = None
    try:
        proc = subprocess.Popen(command, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(line)
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if proc is not None:
            proc.kill()
        _emit(log, "timeout", f"انتهت مهلة الأمر بعد {timeout} ثانية")
        return 124
    except OSError as exc:
        _emit(log, "error", str(exc))
        return 127


def _run_with_retry(command: list[str], cwd: Path, log: Callable[[str], None], timeout: int = 600, attempts: int = 2) -> int:
    code = 1
    for attempt in range(1, attempts + 1):
        code = _run(command, cwd, log, timeout)
        if code == 0:
            return 0
        if attempt < attempts:
            _emit(log, "retry", f"إعادة المحاولة {attempt + 1}/{attempts} بعد فشل التثبيت")
            time.sleep(1)
    return code


def _python_imports(project: Path) -> set[str]:
    found: set[str] = set()
    for file in project.rglob("*.py"):
        if any(part in {".venv", "node_modules", ".git"} for part in file.parts):
            continue
        try:
            tree = ast.parse(file.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
    return found


def discover(project_path: str | Path) -> DependencyResult:
    project = _safe_project(project_path)
    result = DependencyResult()
    candidates = [
        "requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "Pipfile.lock",
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts", "gradlew",
    ]
    result.files = [name for name in candidates if (project / name).is_file()]
    if any(name in result.files for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")):
        result.language = "node"
        if (project / "pnpm-lock.yaml").exists(): result.manager = "pnpm"
        elif (project / "yarn.lock").exists(): result.manager = "yarn"
        else: result.manager = "npm"
    elif any(name in result.files for name in ("composer.json", "composer.lock")):
        result.language, result.manager = "php", "composer"
    elif any(name in result.files for name in ("pom.xml",)):
        result.language, result.manager = "java", "maven"
    elif any(name in result.files for name in ("build.gradle", "build.gradle.kts", "gradlew")):
        result.language, result.manager = "java", "gradle"
    elif result.files or any(project.rglob("*.py")):
        result.language, result.manager = "python", "pip"
    if result.language == "python" and not any(name in result.files for name in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "Pipfile.lock")):
        imports = _python_imports(project)
        result.suggestions = sorted(IMPORT_PACKAGE_MAP.get(name, name) for name in imports if name not in PYTHON_STDLIB and not name.startswith("_"))
    fingerprint = hashlib.sha256()
    for name in result.files:
        p = project / name
        fingerprint.update(name.encode())
        fingerprint.update(p.read_bytes())
    if result.suggestions:
        fingerprint.update("\n".join(result.suggestions).encode())
    result.fingerprint = fingerprint.hexdigest() if result.files or result.suggestions else "none"
    return result


def _safe_extract(zip_path: Path, destination: Path) -> None:
    import zipfile
    base = destination.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            target = (destination / member.filename).resolve()
            if os.path.commonpath([str(base), str(target)]) != str(base):
                raise ValueError("archive path traversal blocked")
        archive.extractall(destination)


def install(project_path: str | Path, log: Callable[[str], None], timeout: int = 600) -> DependencyResult:
    project = _safe_project(project_path)
    result = discover(project)
    _emit(log, "system", "تحليل المشروع...")
    _emit(log, "scan", f"تم اكتشاف {result.language} / {result.manager}; ملفات: {', '.join(result.files) or 'لا توجد'}")
    if result.language == "none":
        result.skipped = True
        result.installed = True
        result.message = "لا توجد اعتماديات معروفة للتثبيت"
        _emit(log, "success", result.message)
        return result
    state_file = project / ".dependency-state.json"
    try:
        previous = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
    except json.JSONDecodeError:
        previous = {}
    if previous.get("fingerprint") == result.fingerprint and previous.get("success"):
        result.skipped = result.installed = True
        result.message = "الاعتماديات ثابتة؛ تم استخدام الكاش"
        _emit(log, "cache", result.message)
        return result
    if result.language == "python":
        venv = project / ".venv"
        _emit(log, "python", f"Python {sys.version_info.major}.{sys.version_info.minor} detected")
        if not (venv / "bin" / "python").exists() and not (venv / "Scripts" / "python.exe").exists():
            _emit(log, "venv", "إنشاء بيئة تشغيل مستقلة...")
            if _run_with_retry([sys.executable, "-m", "venv", str(venv)], project, log, 180, attempts=2) != 0:
                result.message = "فشل إنشاء البيئة الافتراضية"
                _emit(log, "error", result.message)
                return result
        py = venv / "bin" / "python"
        if not py.exists(): py = venv / "Scripts" / "python.exe"
        req = project / "requirements.txt"
        if req.exists():
            command = [str(py), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--prefer-binary", "-r", "requirements.txt"]
        elif (project / "pyproject.toml").exists() or (project / "setup.py").exists():
            command = [str(py), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--prefer-binary", "."]
        elif (project / "Pipfile").exists() or (project / "Pipfile.lock").exists():
            pipenv = shutil.which("pipenv")
            command = [pipenv, "install", "--deploy"] if pipenv else []
            if not pipenv:
                _emit(log, "warn", "Pipenv غير مثبت؛ استخدم requirements.txt أو pyproject.toml")
        elif result.suggestions:
            _emit(log, "suggest", "تم العثور على imports خارجية؛ تثبيت القائمة المقترحة: " + ", ".join(result.suggestions))
            command = [str(py), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--prefer-binary", *result.suggestions]
        else:
            command = []
        if command and _run_with_retry(command, project, log, timeout, attempts=2) != 0:
            result.message = "فشل تثبيت اعتماديات Python؛ راجع آخر أسطر الخطأ"
            _emit(log, "error", result.message)
            state_file.write_text(json.dumps({"fingerprint": result.fingerprint, "success": False}, ensure_ascii=False), encoding="utf-8")
            return result
    elif result.language == "node":
        executable = shutil.which(result.manager)
        if not executable:
            result.message = f"مدير الحزم {result.manager} غير مثبت على الخادم"
            _emit(log, "error", result.message)
            return result
        if result.manager == "npm": command = [executable, "install", "--no-audit", "--no-fund"]
        elif result.manager == "pnpm": command = [executable, "install", "--no-frozen-lockfile"]
        else: command = [executable, "install", "--no-audit", "--no-fund"]
        if _run_with_retry(command, project, log, timeout, attempts=2) != 0:
            result.message = "فشل تثبيت اعتماديات Node؛ راجع آخر أسطر الخطأ"
            _emit(log, "error", result.message)
            state_file.write_text(json.dumps({"fingerprint": result.fingerprint, "success": False}, ensure_ascii=False), encoding="utf-8")
            return result
    elif result.language == "php":
        executable = shutil.which("composer")
        if not executable:
            result.message = "Composer غير مثبت على الخادم"
            _emit(log, "error", result.message)
            return result
        command = [executable, "install", "--no-interaction", "--prefer-dist", "--no-progress"]
        if _run_with_retry(command, project, log, timeout, attempts=2) != 0:
            result.message = "فشل تثبيت اعتماديات PHP عبر Composer"
            _emit(log, "error", result.message)
            state_file.write_text(json.dumps({"fingerprint": result.fingerprint, "success": False}, ensure_ascii=False), encoding="utf-8")
            return result
    elif result.language == "java":
        executable = shutil.which(result.manager)
        if not executable:
            result.message = f"{result.manager} غير مثبت على الخادم"
            _emit(log, "error", result.message)
            return result
        command = [executable, "-B", "dependency:go-offline"] if result.manager == "maven" else [executable, "dependencies"]
        if _run_with_retry(command, project, log, timeout, attempts=2) != 0:
            result.message = f"فشل تجهيز اعتماديات Java عبر {result.manager}"
            _emit(log, "error", result.message)
            state_file.write_text(json.dumps({"fingerprint": result.fingerprint, "success": False}, ensure_ascii=False), encoding="utf-8")
            return result
    state_file.write_text(json.dumps({"fingerprint": result.fingerprint, "success": True, "language": result.language, "manager": result.manager}, ensure_ascii=False), encoding="utf-8")
    result.installed = True
    result.message = "تم تثبيت جميع الاعتماديات والتحقق منها"
    _emit(log, "verify", "Checking dependencies...")
    _emit(log, "success", result.message)
    return result


def python_executable(project_path: str | Path) -> str:
    project = _safe_project(project_path)
    candidate = project / ".venv" / "bin" / "python"
    if candidate.exists(): return str(candidate)
    candidate = project / ".venv" / "Scripts" / "python.exe"
    return str(candidate) if candidate.exists() else sys.executable
