from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QWidget


class MainWindow(QMainWindow):
    """Minimal GUI shell. Scans should run in background workers in Phase 4."""
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WinSecLite")
        self.resize(900, 600)
        title = QLabel("WinSecLite Security Dashboard")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        start_button = QPushButton("Start Quick Scan")
        start_button.setToolTip("Next: connect to a background scan worker")
        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(start_button)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)


def run_gui() -> int:
    app = QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
