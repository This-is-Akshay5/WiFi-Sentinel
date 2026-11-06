# Build WiFiSentinel as a macOS app bundle using the project's active venv.
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

project = Path.cwd().resolve()
webview_datas, webview_binaries, webview_hidden = collect_all('webview')

# The app imports its own `core` package from main.py. Explicitly collect the
# package tree so PyInstaller cannot omit modules such as core.store.
core_hidden = collect_submodules('core')

hidden = list(webview_hidden) + core_hidden + [
    'CoreWLAN', 'CoreLocation', 'objc', 'AppKit', 'Foundation',
    'PyObjCTools', 'PyObjCTools.AppHelper',
]

datas = list(webview_datas) + [
    (str(project / 'gui'), 'gui'),
    (str(project / 'data' / 'wifi_association_disassociation.csv'), 'data'),
    (str(project / 'data' / 'dataset_manifest.json'), 'data'),
]

a = Analysis(
    [str(project / 'main.py')],
    pathex=[str(project)],
    binaries=webview_binaries,
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='WiFiSentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=False,
    name='WiFiSentinel',
)
app = BUNDLE(
    coll,
    name='WiFiSentinel.app',
    icon=None,
    bundle_identifier='com.wifisentinel.desktop',
    info_plist={
        'CFBundleDisplayName': 'WiFiSentinel',
        'CFBundleName': 'WiFiSentinel',
        'LSMinimumSystemVersion': '13.0',
        'NSLocationUsageDescription': (
            'WiFiSentinel requests Location Services authorization only to access nearby '
            'Wi-Fi network identifiers (SSID and BSSID) for wireless security assessments. '
            'The app does not request or store geographic coordinates.'
        ),
        'NSLocationWhenInUseUsageDescription': (
            'WiFiSentinel uses this authorization to access nearby Wi-Fi network identifiers '
            'for wireless security assessments.'
        ),
    },
)
