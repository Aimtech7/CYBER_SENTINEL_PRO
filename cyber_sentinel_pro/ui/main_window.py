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
from .honeypot_tab import HoneypotTab
from .threatintel_tab import ThreatIntelTab
from .settings_tab import SettingsTab
from .faq_tab import FAQTab
from .network_tools_tab import NetworkToolsTab
from .endpoint_tab import EndpointTab
from .report_tab import ReportTab
from .scheduler_tab import SchedulerTab


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
            ('AI Threat Assistant', 'threat.svg'),
            ('Automation Engine', 'siem.svg'),
            ('Hashcat Controller', 'hashcat.svg'),
            ('Malware Sandbox', 'malware.svg'),
            ('Honeypot', 'shield.svg'),
            ('Threat Intelligence', 'threat.svg'),
            ('Endpoint Forensics', 'endpoint.svg'),
            ('Network Tools', 'tools.svg'),
            ('Report Builder', 'report.svg'),
            ('System Health', 'siem.svg'),
            ('Scheduler', 'clock.svg'),
            ('FAQ', 'help.svg'),
            ('Settings', 'settings.svg'),
        ]
        for text, icon in items:
            sidebar.addItem(SidebarItem(text, os.path.join(assets, icon)))

        # Stack
        stack = QStackedWidget()
        stack.setObjectName('MainStack')

        # Tabs mapped by label
        tab_map = {
            'WiFi Analyzer': WifiTab(),
            'Packet Sniffer': SnifferTab(),
            'Web Scanner': WebScanTab(),
            'Network Mapper': NmapTab(),
            'SIEM Analyzer': SIEMTab(),
            'AI Threat Assistant': self._lazy_ai_tab(),
            'Automation Engine': self._lazy_auto_tab(),
            'Hashcat Controller': self._placeholder('Hashcat Controller tab will load below...', HashcatTab=None),
            'Malware Sandbox': MalwareTab(),
            'Honeypot': HoneypotTab(),
            'Threat Intelligence': ThreatIntelTab(),
            'Endpoint Forensics': EndpointTab(),
            'Network Tools': NetworkToolsTab(),
            'Report Builder': ReportTab(),
            'System Health': self._lazy_health_tab(),
            'Scheduler': SchedulerTab(),
            'FAQ': FAQTab(),
            'Settings': SettingsTab(),
        }

        # Lazy import Hashcat tab if available
        try:
            from .hashcat_tab import HashcatTab
            tab_map['Hashcat Controller'] = HashcatTab()
        except Exception as exc:
            tab_map['Hashcat Controller'] = self._placeholder(
                f'Hashcat tab failed to load: {exc}\nInstall Hashcat and ensure PATH is set.'
            )

        # Add widgets to stack following sidebar order
        self._tab_order = []
        for text, _ in items:
            w = tab_map.get(text)
            if w is not None:
                stack.addWidget(w)
                self._tab_order.append(text)

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

    def _lazy_ai_tab(self):
        try:
            from .ai_assistant_tab import AIAssistantTab
            return AIAssistantTab()
        except Exception as exc:
            return self._placeholder(f'AI Assistant failed to load: {exc}')

    def _lazy_auto_tab(self):
        try:
            from .automation_tab import AutomationTab
            return AutomationTab()
        except Exception as exc:
            return self._placeholder(f'Automation failed to load: {exc}')

    def _lazy_health_tab(self):
        try:
            from .health_tab import HealthTab
            return HealthTab()
        except Exception as exc:
            return self._placeholder(f'Health tab failed to load: {exc}')

