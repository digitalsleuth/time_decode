# -*- mode: python ; coding: utf-8 -*-

__version__ = "10.1.0"
bundle_id = "com.digitalsleuth.time-decode"
block_cipher = None

a = Analysis(['time_decode/time_decode.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
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
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None,
          icon=['icon.icns'],
)
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='Time Decode')
app = BUNDLE(coll,
             name=f'Time Decode v{__version__}.app',
             icon='icon.icns',
             info_plist={
                 'CFBundleName': 'Time Decode',
                 'CFBundleDisplayName': 'Time Decode',
                 'CFBundleExecutable': 'Time Decode',
                 'CFBundleIdentifier': bundle_id,
                 'CFBundleShortVersionString': '10.1.0',
                 'CFBundleVersion': '10.1.0',
             },
             bundle_identifier=bundle_id)
