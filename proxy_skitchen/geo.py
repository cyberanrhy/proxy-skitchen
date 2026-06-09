from PySide6.QtCore import QObject, Signal, Slot
from .parsers import geo_lookup

class GeoWorker(QObject):
    geo_result_signal = Signal(int, str, str)
    log_signal = Signal(str)
    finished = Signal()

    @Slot(list, list)
    def geo_batch(self, entries: list, indices: list):
        for i, entry in enumerate(entries):
            row = indices[i]
            host = entry.host
            country_name = geo_lookup(host)
            code = country_name[:2].upper() if country_name else ""
            self.geo_result_signal.emit(row, code, country_name or "Unknown")
        self.finished.emit()
