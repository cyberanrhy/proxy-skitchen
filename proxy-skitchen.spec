# -*- mode: python ; coding: utf-8 -*-

import sys

# Windows accepts only .ico (unless Pillow is available); other platforms
# take the PNG.  A committed .ico keeps CI from depending on Pillow.
ICON = 'proxy_skitchen/icon.ico' if sys.platform == 'win32' else 'proxy_skitchen/icon.png'


a = Analysis(
    ['run_proxy_skitchen.py'],
    pathex=[],
    binaries=[],
    datas=[('proxy_skitchen/icon.png', 'proxy_skitchen')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='proxy-skitchen',
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
    icon=[ICON],
)
