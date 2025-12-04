import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon

# Ensure working directory to project root when executed directly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, 'assets')
STYLES_DIR = os.path.join(ASSETS_DIR, 'styles')

# Lazy import of MainWindow to avoid circulars during packaging
from ui.main_window import MainWindow
from core.utils.secure_storage import load_setting
from core.utils.workflow import schedule_self_test


def load_stylesheet():
    style_path = os.path.join(STYLES_DIR, 'dark.qss')
    if os.path.exists(style_path):
        with open(style_path, 'r', encoding='utf-8') as f:
            return f.read()
    return ''


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Cyber Sentinel Pro')
    app.setOrganizationName('CyberSentinel')
    if load_setting('dark_mode', True):
        qss = load_stylesheet()
        if qss:
            app.setStyleSheet(qss)

    # Set a default window icon
    icon_path = os.path.join(ASSETS_DIR, 'icons', 'shield.svg')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.show()
    try:
        schedule_self_test()
    except Exception:
        pass
    sys.exit(app.exec())


if __name__ == '__main__':
    main()

