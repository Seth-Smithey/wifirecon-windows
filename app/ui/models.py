"""Table models.

Most tables in the application are a list of dictionaries with a fixed set of
columns, so one model handles them all from a column specification. The Live
table needs custom painting rather than a custom model, which is what the
delegates are for.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)

# Roles the delegates read to paint a cell without re-deriving anything.
ROW_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
FLAG_ROLE = Qt.ItemDataRole.UserRole + 3      # "flagged" | "watched" | ""
STALE_ROLE = Qt.ItemDataRole.UserRole + 4

BAND_ORDER = {"2.4": 0, "5": 1, "6": 2}


@dataclass
class Column:
    key: str
    header: str
    format: Callable[[Any, dict], str] | None = None
    align: Qt.AlignmentFlag = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
    sort: Callable[[dict], Any] | None = None
    width: int = 0
    stretch: bool = False
    mono: bool = False

    def text(self, row: dict) -> str:
        value = row.get(self.key)
        if self.format is not None:
            return self.format(value, row)
        return "—" if value is None else str(value)

    def sort_value(self, row: dict) -> Any:
        if self.sort is not None:
            return self.sort(row)
        value = row.get(self.key)
        # A scalar, never a tuple: Qt's own comparator cannot order a Python
        # tuple, so returning one silently disables sorting for the column.
        # SortProxy.lessThan puts nulls last instead.
        return value


class DictTableModel(QAbstractTableModel):
    """A list of dicts shown through a column specification."""

    def __init__(self, columns: list[Column], parent=None) -> None:
        super().__init__(parent)
        self._columns = columns
        self._rows: list[dict] = []
        self._flags: dict[str, str] = {}
        self._stale_key: str | None = None
        self._stale_after: float = 0.0

    # -- data ---------------------------------------------------------------

    def set_rows(self, rows: list[dict]) -> None:
        self.beginResetModel()
        self._rows = list(rows or [])
        self.endResetModel()

    def rows(self) -> list[dict]:
        return self._rows

    def row_at(self, index: int) -> dict | None:
        if 0 <= index < len(self._rows):
            return self._rows[index]
        return None

    def set_flags(self, flags: dict[str, str]) -> None:
        """Map of BSSID to "flagged" or "watched"."""
        self._flags = flags or {}
        if self._rows:
            top = self.index(0, 0)
            bottom = self.index(len(self._rows) - 1, len(self._columns) - 1)
            self.dataChanged.emit(top, bottom, [FLAG_ROLE])

    def set_stale_rule(self, key: str, seconds: float) -> None:
        self._stale_key = key
        self._stale_after = seconds

    # -- Qt interface -------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._columns[section].header
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(self._columns[section].align)
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = self._columns[index.column()]

        if role == Qt.ItemDataRole.DisplayRole:
            return column.text(row)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(column.align)
        if role == ROW_ROLE:
            return row
        if role == SORT_ROLE:
            return column.sort_value(row)
        if role == FLAG_ROLE:
            return self._flags.get(row.get("bssid", ""), "")
        if role == STALE_ROLE:
            if not self._stale_key or not self._stale_after:
                return False
            import time

            seen = row.get(self._stale_key)
            return bool(seen and time.time() - float(seen) > self._stale_after)
        return None

    def column_spec(self, section: int) -> Column:
        return self._columns[section]

    def columns(self) -> list[Column]:
        return self._columns


class SortProxy(QSortFilterProxyModel):
    """Sorts on the model's sort role and filters on a caller-supplied test.

    The comparison is done here rather than left to Qt. Qt can only order the
    handful of types it knows, so anything richer — a tuple, a mixed column —
    compares as equal and the table silently stops sorting.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setSortRole(SORT_ROLE)
        self.setDynamicSortFilter(True)
        self._test: Callable[[dict], bool] | None = None

    def lessThan(self, left, right) -> bool:  # noqa: N802
        a = left.data(SORT_ROLE)
        b = right.data(SORT_ROLE)
        # An unknown value is not a small one, so nulls go to the bottom in
        # both directions rather than crowding the top when reversed.
        if a is None or b is None:
            if a is None and b is None:
                return False
            ascending = self.sortOrder() == Qt.SortOrder.AscendingOrder
            return (b is None) if ascending else (a is None)
        try:
            return bool(a < b)
        except TypeError:
            # A column mixing numbers and text still has to order somehow.
            return str(a) < str(b)

    def set_test(self, test: Callable[[dict], bool] | None) -> None:
        self._test = test
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent) -> bool:  # noqa: N802
        if self._test is None:
            return True
        model = self.sourceModel()
        row = model.row_at(source_row) if hasattr(model, "row_at") else None
        if row is None:
            return True
        try:
            return bool(self._test(row))
        except Exception:
            return True

    def row_at(self, proxy_row: int) -> dict | None:
        source = self.mapToSource(self.index(proxy_row, 0))
        model = self.sourceModel()
        if not source.isValid() or not hasattr(model, "row_at"):
            return None
        return model.row_at(source.row())


def channel_sort(row: dict) -> Any:
    """Band first, then channel, so 2.4 GHz channel 11 sorts below 5 GHz 36."""
    band = BAND_ORDER.get(str(row.get("band") or ""), 9)
    channel = row.get("channel")
    return (band, channel if channel is not None else 9999)


def band_sort(row: dict) -> Any:
    return BAND_ORDER.get(str(row.get("band") or ""), 9)
