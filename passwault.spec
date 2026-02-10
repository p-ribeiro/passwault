# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for building a portable Passwault executable.

Build with:
    pyinstaller passwault.spec

Output goes to dist/passwault/ (one-folder mode for faster startup).
"""

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ["passwault/__main__.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "passwault.core.commands.authenticator",
        "passwault.core.commands.password",
        "passwault.core.database.models",
        "passwault.core.database.user_repository",
        "passwault.core.database.password_manager",
        "passwault.core.services.crypto_service",
        "passwault.core.services.backup_service",
        "passwault.core.utils.session_manager",
        "passwault.core.utils.data_dir",
        "passwault.core.utils.decorators",
        "passwault.core.utils.local_types",
        "passwault.core.utils.file_handler",
        "passwault.core.utils.logger",
        "passwault.core.config",
        "passwault.imagepass.embedder",
        "passwault.imagepass.utils.image_handler",
        # SQLAlchemy dialects
        "sqlalchemy.dialects.sqlite",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude PostgreSQL driver (not needed for portable/SQLite mode)
        "psycopg2",
        "psycopg2_binary",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="passwault",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="passwault",
)
