# -*- mode: python ; coding: utf-8 -*-
# Console build: same app, but attaches to a terminal so CLI works
# without Python installed. GUI still starts when run with no arguments.


a = Analysis(
    ['run_proxy_skitchen.py'],
    pathex=['.'],
    binaries=[],
    datas=[('proxy_skitchen/icon.png', 'proxy_skitchen')],
    hiddenimports=['PySide6.QtSvg', 'PySide6.QtNetwork'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['pyinstaller_cli_hook.py'],
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
    name='proxy-skitchen-cli',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)