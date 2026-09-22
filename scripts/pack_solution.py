#!/usr/bin/env python3
"""Собирает dist/solution.zip по явному allowlist.

Включает только файлы из явного списка ниже. Всё, что не попало в
allowlist, в архив не попадает (в т.ч. docs/reference/). После сборки
проверяет целостность архива и выводит список файлов и размер.
"""

import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "dist")
OUT_ZIP = os.path.join(OUT_DIR, "solution.zip")

# Явный allowlist: корневые файлы.
ROOT_FILES = [
    "go.mod",
    "go.sum",
    "Dockerfile",
    "Dockerfile.runtime",
    "docker-compose.yml",
    "Makefile",
    "README.md",
    "consumers.yaml",
    ".env.example",
    ".dockerignore",
    ".gitignore",
]

# docs/plan.md включается только если файл существует.
OPTIONAL_DOCS = ["docs/plan.md"]


def collect_go_files(subdir):
    """Собирает все *.go файлы из cmd/ или internal/."""
    base = os.path.join(ROOT, subdir)
    result = []
    if not os.path.isdir(base):
        return result
    for dirpath, _, filenames in os.walk(base):
        for name in filenames:
            if name.endswith(".go"):
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT)
                result.append(rel.replace(os.sep, "/"))
    return sorted(result)


def main():
    files = list(ROOT_FILES)
    files += collect_go_files("cmd")
    files += collect_go_files("internal")
    for doc in OPTIONAL_DOCS:
        if os.path.isfile(os.path.join(ROOT, doc)):
            files.append(doc)

    os.makedirs(OUT_DIR, exist_ok=True)
    if os.path.exists(OUT_ZIP):
        os.remove(OUT_ZIP)

    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            src = os.path.join(ROOT, rel)
            if not os.path.isfile(src):
                print(f"WARN: missing file, skipping: {rel}")
                continue
            zf.write(src, rel)

    # Проверка целостности архива.
    with zipfile.ZipFile(OUT_ZIP) as zf:
        bad = zf.testzip()
        if bad is not None:
            raise SystemExit(f"ERROR: archive corrupted at {bad}")

    size = os.path.getsize(OUT_ZIP)
    print(f"Created {OUT_ZIP} ({size} bytes)")
    print("Files:")
    with zipfile.ZipFile(OUT_ZIP) as zf:
        for info in zf.infolist():
            print(f"  {info.filename}")


if __name__ == "__main__":
    main()