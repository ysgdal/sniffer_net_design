from PyQt5.QtCore import pyqtSignal, QObject
from data import PacketInfo


class Signals(QObject):
    update_table = pyqtSignal(PacketInfo)
    update_reassemble_table = pyqtSignal(PacketInfo)