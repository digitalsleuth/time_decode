# -*- mode: python ; coding: utf-8 -*-

import re
from pathlib import Path

root = Path(SPECPATH)
__version__ = re.search(
    r'^__version__ = "([^"]+)"',
    (root / 'time_decode' / 'time_decode.py').read_text(encoding='utf-8'),
    re.MULTILINE,
).group(1)

a = Analysis(
    [str(root / 'entry_gui.py')],
    pathex=[str(root)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f'Time Decode v{__version__}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(root / 'version.txt'),
    icon=[str(root / 'td.ico')],
)
