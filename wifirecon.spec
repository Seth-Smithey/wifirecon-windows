# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec.

    pyinstaller wifirecon.spec                    # onedir (default)
    pyinstaller wifirecon.spec -- --onefile       # single portable exe

onedir is the default because the interface is Qt now. A one-file build has to
unpack the whole Qt runtime to a temporary directory on every launch, which is
slow and is the exact shape antivirus heuristics complain about. onedir starts
immediately and gets flagged far less; zip the folder to hand it to someone.
"""

import importlib.util
import sys
from pathlib import Path

ONEFILE = "--onefile" in sys.argv

block_cipher = None
root = Path(SPECPATH)


def installed(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


datas = [
    (str(root / "VERSION"), "."),
]
if (root / "docs").exists():
    datas.append((str(root / "docs"), "docs"))
# Only the optional web server serves these, but it is small and it keeps
# --server working in a packaged build.
if (root / "app" / "static").exists():
    datas.append((str(root / "app" / "static"), "app/static"))

hiddenimports = [
    "app.wlanapi",
    "app.installer",
    "app.runtime",
    "app.server",
    "tools.mock_source",
    # The views are imported inside a function, so name them to be certain.
    "app.ui.app",
    "app.ui.main_window",
    "app.ui.views.adapters",
    "app.ui.views.devices",
    "app.ui.views.diagnostics",
    "app.ui.views.findings",
    "app.ui.views.history",
    "app.ui.views.live",
    "app.ui.views.marks",
    "app.ui.views.network",
    "app.ui.views.report",
    "app.ui.views.settings",
    "app.ui.views.spectrum",
    "app.ui.views.ssids",
    "app.ui.views.survey",
]

if installed("uvicorn"):
    # uvicorn resolves these by name at runtime, so PyInstaller cannot see them.
    hiddenimports += [
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.loops.asyncio",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "anyio._backends._asyncio",
    ]

# Qt ships far more than this application uses. Naming what to leave out takes
# the build from roughly 300 MB to something closer to 120 MB, and none of it
# is reachable from the interface.
QT_UNUSED = [
    "Qt3DAnimation", "Qt3DCore", "Qt3DExtras", "Qt3DInput", "Qt3DLogic",
    "Qt3DRender", "QtBluetooth", "QtCharts", "QtDataVisualization",
    "QtDesigner", "QtGraphs", "QtHelp", "QtHttpServer", "QtLocation",
    "QtMultimedia", "QtMultimediaWidgets", "QtNetworkAuth", "QtNfc",
    "QtOpenGL", "QtOpenGLWidgets", "QtPdf", "QtPdfWidgets", "QtPositioning",
    "QtQml", "QtQuick", "QtQuick3D", "QtQuickControls2", "QtQuickWidgets",
    "QtRemoteObjects", "QtScxml", "QtSensors", "QtSerialBus", "QtSerialPort",
    "QtSpatialAudio", "QtSql", "QtStateMachine", "QtTest", "QtTextToSpeech",
    "QtUiTools", "QtWebChannel", "QtWebEngineCore", "QtWebEngineQuick",
    "QtWebEngineWidgets", "QtWebSockets",
]

excludes = [
    # None of this is used, and leaving it out roughly halves the binary.
    "tkinter", "matplotlib", "numpy", "pandas", "scipy", "PIL", "PyQt5",
    "PyQt6", "PySide2", "notebook", "IPython", "pytest", "setuptools", "pip",
    "test", "unittest", "distutils", "lib2to3", "pydoc_data",
] + [f"PySide6.{name}" for name in QT_UNUSED]

a = Analysis(
    ["run_app.py"],
    pathex=[str(root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)


def _drop_qt_extras(entries):
    """Remove the Qt libraries and plugins the excludes could not reach.

    PyInstaller's Qt hook collects translations and plugin directories wholesale
    rather than per module, so they survive the exclude list and account for a
    large part of the build.
    """
    drop_dirs = (
        "PySide6/translations",
        "PySide6/qml",
        "PySide6/plugins/sqldrivers",
        "PySide6/plugins/multimedia",
        "PySide6/plugins/position",
        "PySide6/plugins/sensors",
        "PySide6/plugins/webview",
        "PySide6/plugins/renderers",
        "PySide6/plugins/geometryloaders",
        "PySide6/plugins/designer",
        "PySide6/resources",
    )
    kept = []
    for entry in entries:
        name = entry[0].replace("\\", "/")
        if any(part in name for part in drop_dirs):
            continue
        if any(f"Qt6{module[2:]}" in name for module in QT_UNUSED):
            continue
        kept.append(entry)
    return kept


a.datas = _drop_qt_extras(a.datas)
a.binaries = _drop_qt_extras(a.binaries)


def _require(entries, needle, what):
    """The pruning is a substring filter, so it has to be checked.

    Losing the Windows platform plugin produces an executable that starts,
    prints nothing and shows no window. Far better to fail the build.
    """
    if not any(needle in entry[0].replace("\\", "/") for entry in entries):
        raise SystemExit(
            f"Build aborted: {what} was removed by the Qt pruning in this spec. "
            f"Nothing matching {needle!r} survived, and without it the packaged "
            "application cannot open a window."
        )


_require(a.binaries, "platforms/qwindows", "the Windows platform plugin")
_require(a.binaries, "Qt6Core", "QtCore")
_require(a.binaries, "Qt6Gui", "QtGui")
_require(a.binaries, "Qt6Widgets", "QtWidgets")

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# A console executable so --doctor, --install and the rest print somewhere.
# The window hides itself at runtime when the application opens instead.
COMMON = dict(
    name="wifirecon",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                     # UPX packing is a large antivirus trigger
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(root / "app" / "static" / "icon.ico")
        if (root / "app" / "static" / "icon.ico").exists() else None,
    version=str(root / "version_info.txt")
        if (root / "version_info.txt").exists() else None,
)

if ONEFILE:
    exe = EXE(
        pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
        runtime_tmpdir=None, **COMMON
    )
else:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, **COMMON)
    coll = COLLECT(
        exe, a.binaries, a.zipfiles, a.datas,
        strip=False, upx=False, name="wifirecon",
    )
