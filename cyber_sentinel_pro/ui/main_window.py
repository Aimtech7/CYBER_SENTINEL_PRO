import os
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QListWidget, QListWidgetItem,
    QStackedWidget, QLabel
)
from PyQt6.QtGui import QIcon

from .wifi_tab import WifiTab
from .sniffer_tab import SnifferTab
from .webscan_tab import WebScanTab
from .nmap_tab import NmapTab
from .siem_tab import SIEMTab
from .malware_tab import MalwareTab
from .threatintel_tab import ThreatIntelTab
from .settings_tab import SettingsTab


class SidebarItem(QListWidgetItem):
    def __init__(self, text: str, icon_path: str):
        super().__init__(text)
        if os.path.exists(icon_path):
            self.setIcon(QIcon(icon_path))
        self.setSizeHint(QSize(180, 40))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Cyber Sentinel Pro')
        self.setMinimumSize(1200, 800)
        self._init_ui()

    def _init_ui(self):
        container = QWidget()
        root = QHBoxLayout(container)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Sidebar
        sidebar = QListWidget()
        sidebar.setFixedWidth(220)
        sidebar.setObjectName('Sidebar')
        sidebar.setAlternatingRowColors(False)

        assets = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets', 'icons')
        items = [
            ('WiFi Analyzer', 'wifi.svg'),
            ('Packet Sniffer', 'sniffer.svg'),
            ('Web Scanner', 'web.svg'),
            ('Network Mapper', 'nmap.svg'),
            ('SIEM Analyzer', 'siem.svg'),
            ('Hashcat Controller', 'hashcat.svg'),
            ('Malware Sandbox', 'malware.svg'),
            ('Threat Intelligence', 'threat.svg'),
            ('Settings', 'settings.svg'),
        ]
        for text, icon in items:
            sidebar.addItem(SidebarItem(text, os.path.join(assets, icon)))

        # Stack
        stack = QStackedWidget()
        stack.setObjectName('MainStack')

        # Tabs
        self.tabs = {
            'WiFi Analyzer': WifiTab(),
            'Packet Sniffer': SnifferTab(),
            'Web Scanner': WebScanTab(),
            'Network Mapper': NmapTab(),
            'SIEM Analyzer': SIEMTab(),
            'Hashcat Controller': self._placeholder('Hashcat Controller tab will load below...', HashcatTab=None),
            'Malware Sandbox': MalwareTab(),
            'Threat Intelligence': ThreatIntelTab(),
            'Settings': SettingsTab(),
        }

        # The Hashcat tab is heavy and interacts with external binary; import lazily
        try:
            from .hashcat_tab import HashcatTab
            self.tabs['Hashcat Controller'] = HashcatTab()
        except Exception as exc:
            self.tabs['Hashcat Controller'] = self._placeholder(
                f'Hashcat tab failed to load: {exc}\nInstall Hashcat and ensure PATH is set.'
            )

        for _, tab in self.tabs.items():
            stack.addWidget(tab)

        root.addWidget(sidebar)
        root.addWidget(stack, 1)
        self.setCentralWidget(container)

        def on_change(idx):
            stack.setCurrentIndex(idx)

        sidebar.currentRowChanged.connect(on_change)
        sidebar.setCurrentRow(0)

    def _placeholder(self, text: str, HashcatTab=None):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel(text)
        lbl.setObjectName('PlaceholderLabel')
        v.addWidget(lbl)
        return w

