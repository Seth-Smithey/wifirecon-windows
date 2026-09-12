"""Colours and the Qt stylesheet.

The palette is the one the browser interface used, carried over unchanged so
the two look like the same product. Band colours follow wavelength: 2.4 GHz
amber, 5 GHz cyan, 6 GHz violet. That is the organising logic everywhere, in
chips, rows, the ribbon and the reports, so it is defined once here.

The light theme is not the dark one with the alpha tints reused. Those tints
were mixed against a near-black base and go muddy on white, so the light
variant recomputes them.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor


@dataclass(frozen=True)
class Palette:
    name: str

    void: str            # page background
    panel: str           # cards, drawer
    panel2: str          # rail, topbar, table headers, inputs
    raised: str          # buttons, hover, toasts
    line: str            # primary borders
    line_soft: str       # row separators, gridlines

    text: str
    text_hi: str
    dim: str
    dimmer: str

    b24: str             # 2.4 GHz, amber
    b5: str              # 5 GHz, cyan. Doubles as the accent colour.
    b6: str              # 6 GHz, violet
    b_other: str         # unknown band

    crit: str
    high: str
    med: str
    low: str
    info: str
    ok: str

    btn_hover: str
    btn_border_hover: str
    primary_bg: str
    primary_border: str
    primary_text: str
    primary_hover: str
    danger_border: str
    danger_text: str
    danger_hover: str
    focus_border: str
    scrollbar_hover: str
    backdrop: str

    # Coverage grading, which does not reuse the severity ladder because a
    # weak signal is not a security finding.
    grade_excellent: str
    grade_good: str
    grade_fair: str
    grade_weak: str
    grade_unusable: str

    tint_alpha_bg: float = 0.10
    tint_alpha_border: float = 0.30

    @property
    def is_dark(self) -> bool:
        return self.name == "dark"


DARK = Palette(
    name="dark",
    void="#0a0e14",
    panel="#111823",
    panel2="#0e1520",
    raised="#16202e",
    line="#1e2836",
    line_soft="#17202c",
    text="#ccd6e4",
    text_hi="#eaf1fa",
    dim="#6b7c93",
    dimmer="#465468",
    b24="#f0a35e",
    b5="#5ec8d8",
    b6="#a986e8",
    b_other="#8d97a8",
    crit="#ff4d6d",
    high="#ff8c42",
    med="#e8c547",
    low="#6ba4d8",
    info="#6b7c93",
    ok="#4ec9a0",
    btn_hover="#1d293a",
    btn_border_hover="#2a3849",
    primary_bg="#1b3a4a",
    primary_border="#24576d",
    primary_text="#bfe9f2",
    primary_hover="#204656",
    danger_border="#4a2029",
    danger_text="#ff9aad",
    danger_hover="#2a1119",
    focus_border="#2f4257",
    scrollbar_hover="#2a3849",
    backdrop="rgba(4, 7, 11, 153)",
    grade_excellent="#7ee0bd",
    grade_good="#bde095",
    grade_fair="#efd88a",
    grade_weak="#ffb182",
    grade_unusable="#ff90a5",
)


LIGHT = Palette(
    name="light",
    void="#f4f6f9",
    panel="#ffffff",
    panel2="#eef1f6",
    raised="#e6eaf1",
    line="#d4dae4",
    line_soft="#e4e8ee",
    text="#2a3442",
    text_hi="#10161f",
    dim="#5d6a7c",
    dimmer="#8794a6",
    b24="#b56a1a",
    b5="#0d7c92",
    b6="#6b3fbf",
    b_other="#5c6675",
    crit="#c2183f",
    high="#b45309",
    med="#8a6d0b",
    low="#1d4ed8",
    info="#5d6a7c",
    ok="#0f7a5a",
    btn_hover="#e0e6ee",
    btn_border_hover="#c2cad6",
    primary_bg="#d6ecf2",
    primary_border="#8dc7d6",
    primary_text="#0a4a5c",
    primary_hover="#c6e4ec",
    danger_border="#e8b9c3",
    danger_text="#a3122f",
    danger_hover="#fbe4e9",
    focus_border="#8dc7d6",
    scrollbar_hover="#b6bfcc",
    backdrop="rgba(16, 22, 31, 120)",
    grade_excellent="#0f7a5a",
    grade_good="#4a7c14",
    grade_fair="#8a6d0b",
    grade_weak="#b45309",
    grade_unusable="#c2183f",
    # Against white the same tints need less alpha in the fill and more in the
    # border, or a chip reads as a smudge with no edge.
    tint_alpha_bg=0.13,
    tint_alpha_border=0.45,
)


THEMES = {"dark": DARK, "light": LIGHT}

RAIL_WIDTH = 208
RADIUS = 6

MONO_FAMILIES = [
    "Cascadia Mono", "Cascadia Code", "JetBrains Mono", "Consolas",
    "DejaVu Sans Mono", "monospace",
]
UI_FAMILIES = [
    "Segoe UI Variable Display", "Segoe UI", "system-ui", "DejaVu Sans",
    "sans-serif",
]

BAND_KEYS = ("2.4", "5", "6")

SEVERITIES = ("critical", "high", "medium", "low", "info")


def qcolor(value: str, alpha: float = 1.0) -> QColor:
    colour = QColor(value)
    if alpha < 1.0:
        colour.setAlphaF(alpha)
    return colour


def band_colour(palette: Palette, band: str | None) -> str:
    return {
        "2.4": palette.b24,
        "5": palette.b5,
        "6": palette.b6,
    }.get(str(band or ""), palette.b_other)


def severity_colour(palette: Palette, severity: str | None) -> str:
    return {
        "critical": palette.crit,
        "high": palette.high,
        "medium": palette.med,
        "low": palette.low,
        "info": palette.info,
    }.get(str(severity or "").lower(), palette.dim)


def grade_colour(palette: Palette, grade: str | None) -> str:
    return {
        "excellent": palette.grade_excellent,
        "good": palette.grade_good,
        "fair": palette.grade_fair,
        "weak": palette.grade_weak,
        "unusable": palette.grade_unusable,
    }.get(str(grade or "").lower(), palette.dimmer)


def rgba(value: str, alpha: float) -> str:
    """A CSS rgba() string, for the parts of Qt styling that take one."""
    colour = QColor(value)
    return f"rgba({colour.red()}, {colour.green()}, {colour.blue()}, {alpha:.3f})"


def tint(palette: Palette, value: str) -> tuple[str, str]:
    """Background and border for a chip in the given colour."""
    return rgba(value, palette.tint_alpha_bg), rgba(value, palette.tint_alpha_border)


def _families(names: list[str]) -> str:
    return ", ".join(f'"{n}"' if " " in n else n for n in names)


def stylesheet(p: Palette) -> str:
    mono = _families(MONO_FAMILIES)
    ui = _families(UI_FAMILIES)
    return f"""
* {{
    font-family: {ui};
    font-size: 14px;
    outline: none;
}}

QWidget {{
    color: {p.text};
    background: transparent;
}}

QMainWindow, #root {{
    background: {p.void};
}}

QToolTip {{
    background: {p.panel};
    color: {p.text_hi};
    border: 1px solid {p.line};
    padding: 6px 8px;
    font-family: {mono};
    font-size: 11px;
}}

/* -- rail ------------------------------------------------------------- */

#rail {{
    background: {p.panel2};
    border-right: 1px solid {p.line};
    min-width: {RAIL_WIDTH}px;
    max-width: {RAIL_WIDTH}px;
}}

#brandTitle {{
    font-size: 15px;
    font-weight: 650;
    color: {p.text_hi};
}}

#brandSub {{
    font-family: {mono};
    font-size: 10px;
    letter-spacing: 1px;
    color: {p.dimmer};
}}

#brandBox, #sitePickBox {{
    border-bottom: 1px solid {p.line};
}}

QPushButton[nav="true"] {{
    background: transparent;
    border: none;
    border-radius: {RADIUS}px;
    color: {p.dim};
    padding: 8px 10px;
    text-align: left;
    font-size: 13px;
}}

QPushButton[nav="true"]:hover {{
    background: {p.raised};
    color: {p.text};
}}

QPushButton[nav="true"][on="true"] {{
    background: {p.raised};
    color: {p.text_hi};
}}

#railFoot QLabel {{
    font-family: {mono};
    font-size: 10px;
    color: {p.dimmer};
}}

/* -- topbar ----------------------------------------------------------- */

#topbar {{
    background: {p.panel2};
    border-bottom: 1px solid {p.line};
    min-height: 58px;
    max-height: 58px;
}}

#adapterChip {{
    background: {p.raised};
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
    padding: 4px 12px 4px 8px;
    text-align: left;
}}

#adapterChip:hover {{
    border: 1px solid {p.focus_border};
}}

#adapterName {{
    font-size: 12px;
    font-weight: 600;
    color: {p.text_hi};
}}

#adapterSub {{
    font-family: {mono};
    font-size: 10px;
    color: {p.dimmer};
}}

#phaseText {{
    font-family: {mono};
    font-size: 10px;
    letter-spacing: 0.7px;
    color: {p.dim};
}}

QLabel[readoutValue="true"] {{
    font-family: {mono};
    font-size: 17px;
    font-weight: 600;
    color: {p.text_hi};
}}

QLabel[readoutValue="true"][alarm="true"] {{
    color: {p.crit};
}}

QLabel[readoutCaption="true"] {{
    font-size: 9px;
    letter-spacing: 0.9px;
    color: {p.dimmer};
}}

/* -- cards and text --------------------------------------------------- */

QFrame[card="true"] {{
    background: {p.panel};
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
}}

QLabel[cardTitle="true"] {{
    font-size: 14px;
    font-weight: 620;
    color: {p.text_hi};
}}

QLabel[hint="true"] {{
    font-size: 12px;
    color: {p.dim};
}}

QLabel[eyebrow="true"] {{
    font-family: {mono};
    font-size: 10px;
    letter-spacing: 1.2px;
    color: {p.dimmer};
}}

QLabel[mono="true"], QPlainTextEdit[mono="true"] {{
    font-family: {mono};
    font-size: 12px;
}}

QLabel[dim="true"] {{ color: {p.dim}; }}
QLabel[dimmer="true"] {{ color: {p.dimmer}; }}

/* -- buttons ---------------------------------------------------------- */

QPushButton {{
    background: {p.raised};
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
    color: {p.text};
    padding: 6px 12px;
}}

QPushButton:hover {{
    background: {p.btn_hover};
    border-color: {p.btn_border_hover};
}}

QPushButton:disabled {{
    color: {p.dimmer};
    background: {p.panel2};
}}

QPushButton[small="true"] {{
    font-size: 12px;
    padding: 3px 8px;
}}

QPushButton[kind="primary"] {{
    background: {p.primary_bg};
    border-color: {p.primary_border};
    color: {p.primary_text};
}}

QPushButton[kind="primary"]:hover {{
    background: {p.primary_hover};
}}

QPushButton[kind="danger"] {{
    border-color: {p.danger_border};
    color: {p.danger_text};
}}

QPushButton[kind="danger"]:hover {{
    background: {p.danger_hover};
}}

/* -- inputs ----------------------------------------------------------- */

QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background: {p.panel2};
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
    color: {p.text};
    padding: 5px 8px;
    selection-background-color: {p.b5};
    selection-color: {p.void};
}}

QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border-color: {p.focus_border};
}}

QLineEdit::placeholder {{
    color: {p.dimmer};
}}

QComboBox::drop-down {{
    border: none;
    width: 18px;
}}

QComboBox QAbstractItemView {{
    background: {p.panel};
    border: 1px solid {p.line};
    selection-background-color: {p.raised};
    color: {p.text};
}}

QCheckBox, QRadioButton {{
    spacing: 8px;
    color: {p.text};
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {p.line};
    border-radius: 3px;
    background: {p.panel2};
}}

QRadioButton::indicator {{
    border-radius: 8px;
}}

QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background: {p.b5};
    border-color: {p.b5};
}}

/* -- tables ----------------------------------------------------------- */

QTableView, QTreeView {{
    background: {p.panel};
    alternate-background-color: {p.panel};
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
    gridline-color: {p.line_soft};
    selection-background-color: {p.raised};
    selection-color: {p.text_hi};
}}

QTableView::item, QTreeView::item {{
    padding: 4px 6px;
    border: none;
}}

QTableView::item:hover, QTreeView::item:hover {{
    background: {p.raised};
}}

QHeaderView::section {{
    background: {p.panel2};
    border: none;
    border-bottom: 1px solid {p.line};
    border-right: 1px solid {p.line_soft};
    color: {p.dimmer};
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.8px;
    padding: 6px 8px;
    text-transform: uppercase;
}}

QHeaderView::section:hover {{
    color: {p.text};
}}

QTableCornerButton::section {{
    background: {p.panel2};
    border: none;
}}

/* -- scrollbars ------------------------------------------------------- */

QScrollBar:vertical {{
    background: {p.panel2};
    width: 10px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {p.line};
    border-radius: 5px;
    min-height: 28px;
}}

QScrollBar::handle:vertical:hover {{
    background: {p.scrollbar_hover};
}}

QScrollBar:horizontal {{
    background: {p.panel2};
    height: 10px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background: {p.line};
    border-radius: 5px;
    min-width: 28px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {p.scrollbar_hover};
}}

QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0;
    width: 0;
}}

QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

QScrollArea {{
    border: none;
}}

/* -- misc ------------------------------------------------------------- */

QSplitter::handle {{
    background: {p.line};
}}

QMenu {{
    background: {p.panel};
    border: 1px solid {p.line};
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 22px 6px 12px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background: {p.raised};
    color: {p.text_hi};
}}

QMenuBar {{
    background: {p.panel2};
    color: {p.text};
}}

QMenuBar::item:selected {{
    background: {p.raised};
}}

QGroupBox {{
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
    margin-top: 14px;
    padding-top: 10px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {p.dimmer};
    font-size: 10px;
    letter-spacing: 0.8px;
}}

QProgressBar {{
    background: {p.line};
    border: none;
    border-radius: 2px;
    max-height: 3px;
    text-align: center;
}}

QProgressBar::chunk {{
    background: {p.b5};
    border-radius: 2px;
}}

QTabWidget::pane {{
    border: 1px solid {p.line};
    border-radius: {RADIUS}px;
    top: -1px;
}}

QTabBar::tab {{
    background: transparent;
    color: {p.dim};
    padding: 7px 14px;
    border: none;
    border-bottom: 2px solid transparent;
}}

QTabBar::tab:selected {{
    color: {p.text_hi};
    border-bottom: 2px solid {p.b5};
}}

QTabBar::tab:hover {{
    color: {p.text};
}}
"""
