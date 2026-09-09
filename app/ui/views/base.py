"""Shared plumbing for the views."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QScrollArea,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..bridge import Pool, ScanBridge
from ..delegates import BaseDelegate, TextDelegate
from ..models import DictTableModel, SortProxy
from ..theme import Palette

log = logging.getLogger(__name__)


@dataclass
class Context:
    """What every view needs from the application around it."""

    pool: Pool
    bridge: ScanBridge
    palette: Palette
    toast: Callable[..., None]
    open_drawer: Callable[[str], None]
    show_view: Callable[[str], None]
    refresh_status: Callable[[], None]
    confirm: Callable[..., bool]
    ask_text: Callable[..., str | None]
    add_mark: Callable[[str, str, str], None]


class View(QWidget):
    """One screen. Loads lazily and only refreshes while it is showing."""

    title = ""
    # Views that show what the radio just heard reload when a scan finishes.
    reload_on_scan = False

    def __init__(self, context: Context, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ctx = context
        self.palette_colours = context.palette
        self._loaded = False
        self._delegates: list[BaseDelegate] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        outer.addWidget(self._scroll)

        self._body = QWidget()
        self.layout_ = QVBoxLayout(self._body)
        self.layout_.setContentsMargins(20, 20, 20, 20)
        self.layout_.setSpacing(16)
        self._scroll.setWidget(self._body)

        self.build()

    # -- lifecycle ----------------------------------------------------------

    def build(self) -> None:
        """Create the widgets. Called once, at construction."""

    def load(self) -> None:
        """Fetch data. Called every time the view is shown."""

    def on_shown(self) -> None:
        self._loaded = True
        self.load()

    def on_scan_finished(self) -> None:
        if self.reload_on_scan and self.isVisible():
            self.load()

    def apply_palette(self, palette: Palette) -> None:
        self.palette_colours = palette
        self.ctx.palette = palette
        for delegate in self._delegates:
            delegate.set_palette_colours(palette)
        self.repalette(palette)
        self.update()

    def repalette(self, palette: Palette) -> None:
        """Views override this to recolour anything painted by hand."""

    # -- helpers ------------------------------------------------------------

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.layout_.addWidget(widget, stretch)
        return widget

    def add_stretch(self) -> None:
        self.layout_.addStretch(1)

    def run(self, fn, on_done=None, *args, **kwargs) -> None:
        """Run a blocking call off the interface thread and report failures."""
        self.ctx.pool.run(fn, on_done, self._report_error, *args, **kwargs)

    def _report_error(self, exc: Exception) -> None:
        from ...services import ServiceError

        if isinstance(exc, ServiceError):
            self.ctx.toast(exc.message, kind="err")
            return
        # An unexpected failure with no traceback in the log is unfixable, so
        # the log gets the detail and the person gets the readable half.
        log.exception("%s failed", type(self).__name__, exc_info=exc)
        self.ctx.toast(
            f"{exc.__class__.__name__}: {exc}"[:200],
            title="Something went wrong", kind="err",
        )

    def make_table(self, model: DictTableModel, *, proxy: bool = True,
                   on_activate: Callable[[dict], None] | None = None,
                   sort_column: int = -1,
                   sort_order: Qt.SortOrder = Qt.SortOrder.DescendingOrder,
                   ) -> tuple[QTableView, SortProxy | DictTableModel]:
        table = QTableView()
        source: Any = model
        if proxy:
            source = SortProxy(table)
            source.setSourceModel(model)
        table.setModel(source)
        table.setSortingEnabled(proxy)
        table.setAlternatingRowColors(False)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setMouseTracking(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(30)
        table.horizontalHeader().setHighlightSections(False)
        table.horizontalHeader().setStretchLastSection(False)

        header = table.horizontalHeader()
        for position, column in enumerate(model.columns()):
            if column.stretch:
                header.setSectionResizeMode(position, QHeaderView.ResizeMode.Stretch)
            elif column.width:
                header.setSectionResizeMode(position, QHeaderView.ResizeMode.Fixed)
                table.setColumnWidth(position, column.width)
            else:
                header.setSectionResizeMode(
                    position, QHeaderView.ResizeMode.ResizeToContents
                )
            if column.mono:
                delegate = TextDelegate(self.palette_colours, mono=True)
                self._delegates.append(delegate)
                table.setItemDelegateForColumn(position, delegate)

        default = TextDelegate(self.palette_colours)
        self._delegates.append(default)
        table.setItemDelegate(default)

        if sort_column >= 0 and proxy:
            table.sortByColumn(sort_column, sort_order)

        if on_activate is not None:
            def clicked(index) -> None:
                model_or_proxy = table.model()
                row = (model_or_proxy.row_at(index.row())
                       if hasattr(model_or_proxy, "row_at") else None)
                if row is not None:
                    on_activate(row)

            table.clicked.connect(clicked)

        return table, source

    def set_column_delegate(self, table: QTableView, column: int,
                            delegate: BaseDelegate) -> None:
        self._delegates.append(delegate)
        table.setItemDelegateForColumn(column, delegate)
