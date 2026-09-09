"""The thirteen screens."""

from __future__ import annotations

from .base import Context, View


def build_views(context: Context) -> dict[str, View]:
    """Construct every view. Imported here so a broken view names itself."""
    from .adapters import AdaptersView
    from .devices import DevicesView
    from .diagnostics import DiagnosticsView
    from .findings import FindingsView
    from .history import HistoryView
    from .live import LiveView
    from .marks import MarksView
    from .network import NetworkView
    from .report import ReportView
    from .settings import SettingsView
    from .spectrum import SpectrumView
    from .ssids import SsidsView
    from .survey import SurveyView

    classes = {
        "live": LiveView,
        "spectrum": SpectrumView,
        "findings": FindingsView,
        "ssids": SsidsView,
        "marks": MarksView,
        "history": HistoryView,
        "devices": DevicesView,
        "network": NetworkView,
        "survey": SurveyView,
        "report": ReportView,
        "adapters": AdaptersView,
        "diagnostics": DiagnosticsView,
        "settings": SettingsView,
    }
    return {key: cls(context) for key, cls in classes.items()}


__all__ = ["Context", "View", "build_views"]
