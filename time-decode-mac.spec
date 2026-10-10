# -*- mode: python ; coding: utf-8 -*-

import re
from pathlib import Path

root = Path(SPECPATH)
__version__ = re.search(
    r'^__version__ = "([^"]+)"',
    (root / 'time_decode' / 'time_decode.py').read_text(encoding='utf-8'),
    re.MULTILINE,
).group(1)
bundle_id = "com.digitalsleuth.time-decode"

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
    [],
    exclude_binaries=True,
    name='Time Decode',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[str(root / 'icon.icns')],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Time Decode',
)
app = BUNDLE(
    coll,
    name=f'Time Decode v{__version__}.app',
    icon=str(root / 'icon.icns'),
    info_plist={
        'CFBundleName': 'Time Decode',
        'CFBundleDisplayName': 'Time Decode',
        'CFBundleExecutable': 'Time Decode',
        'CFBundleIdentifier': bundle_id,
        'CFBundleShortVersionString': __version__,
        'CFBundleVersion': __version__,
        'NSHighResolutionCapable': True,
    },
    bundle_identifier=bundle_id,
)
