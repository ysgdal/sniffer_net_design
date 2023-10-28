from PyQt5.QtWidgets import *
from PyQt5.QtGui import QColor, QFont
from scapy.all import get_working_ifaces
from data import PacketInfo
from find import PacketFinder
import catch
import json
from main_window import Window_UI
import sys


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Window_UI()
        self.ui.designer(self)
        self.s = catch.PacketSniffer(self.ui)
        self.show_table()
        self.get_nif(self.ui.if_box)
        self.initialize()
        self.design_toolbar()
        self.choose_if_box()
        self.design_signal()
        self.searcher()

    def get_nif(self, if_box: QComboBox):
        if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
        if_box.addItems(if_list)
        return if_list

    def initialize(self):
        self.ui.action_start.setEnabled(False)
        self.ui.action_stop.setEnabled(False)
        self.ui.action_restart.setEnabled(False)
        self.ui.action_clean_all.setEnabled(False)
        self.ui.action_save_as.setEnabled(False)




# 设置信息展示表格
    def show_table(self):
        self.ui.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ui.table.setColumnWidth(0, 50)
        self.ui.table.setColumnWidth(2, 150)
        self.ui.table.setColumnWidth(3, 150)
        self.ui.table.setColumnWidth(4, 100)
        self.ui.table.setColumnWidth(5, 50)
        self.ui.table.horizontalHeader().setStretchLastSection(True)
        self.ui.table.setStyleSheet('QTableWidget::item:selected{background-color: #ACACAC}')
        self.ui.table.itemClicked.connect(self.show_detail)
        self.ui.table.itemClicked.connect(self.hex)



# 设置工具栏操作
    def design_toolbar(self):
        self.ui.action_exit.triggered.connect(exit)
        self.ui.action_start.triggered.connect(self.start)
        self.ui.action_stop.triggered.connect(self.stop)
        self.ui.action_clean_all.triggered.connect(self.clean)
        self.ui.action_restart.triggered.connect(self.restart)
        self.ui.action_save_as.triggered.connect(self.save)
        self.ui.action_open_file.triggered.connect(self.read)
        self.ui.action_show_details.triggered.connect(lambda: self.ui.tab.setCurrentIndex(0))



    def choose_if_box(self):
        self.ui.if_box.currentIndexChanged.connect(self.checknet)


    def searcher(self):
        search_button = self.ui.search_button
        search_button.clicked.connect(self.look_up)
        search_button.setShortcut('Return')


# 设置信号
    def design_signal(self):
        self.s.signal_triggers.update_table.connect(self.contiue)


# 退出界面
    def exit(self):
        reply = QMessageBox.question(self, '温馨提示',
                                     "确定退出吗?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.ui.close()


# 检测网卡
    def checknet(self, index):
        if index != 0 and not self.s.capture_active:
            self.ui.action_start.setEnabled(True)
            self.ui.action_restart.setEnabled(True)
        else:
            self.ui.action_start.setEnabled(False)
            self.ui.action_restart.setEnabled(False)


# 添加行
    def contiue(self, packet_info: PacketInfo):
        table: QTableWidget = self.ui.table
        rows = table.rowCount()
        table.insertRow(rows)
        headers = ['number', 'time', 'src', 'dst', 'protocol', 'length', 'info']

        # 根据协议类型设置颜色
        color_dict = {
            'UDP': QColor('#E0F7FA'),
            'TCP': QColor('#E8F5E9'),
            'DNS': QColor('#FFF9C4'),
            'ICMPv6': QColor('#F3E5F5'),
            'ARP': QColor('#FFECB3')
        }
        color = color_dict.get(packet_info.protocol, QColor('#FFFFFF'))  # 默认为白色

        for i, header in enumerate(headers):
            item = QTableWidgetItem(str(packet_info.__dict__[header]))
            item.setBackground(color)
            table.setItem(rows, i, item)

        table.scrollToBottom()


 # 清除信息
    def clear(self):
        self.clear_table()
        self.s.reset_data()


# 清除数据包显示表
    def clear_table(self):
        self.ui.table.clearContents()
        self.ui.table.setRowCount(0)
        self.ui.detail_tree.clear()
        self.ui.hex_text.clear()


# 开始嗅探
    def start(self):
        try:
            self.s.activate()
            self.ui.action_stop.setEnabled(True)
            self.ui.action_start.setEnabled(False)
            self.ui.action_restart.setEnabled(False)
            self.ui.action_clean_all.setEnabled(False)
            self.ui.action_save_as.setEnabled(False)
            self.ui.action_exit.setEnabled(False)
            self.ui.action_open_file.setEnabled(False)
        except Exception as e:
            # 打印异常信息到控制台
            print(f"An error occurred: {e}")


# 重新开始
    def restart(self):
        self.clear()
        self.start()


    # 停止嗅探
    def stop(self):
        self.s.deactivate()
        self.ui.action_stop.setEnabled(False)
        self.ui.action_restart.setEnabled(True)
        self.ui.action_start.setEnabled(True)
        self.ui.action_clean_all.setEnabled(True)
        self.ui.action_save_as.setEnabled(True)
        self.ui.action_open_file.setEnabled(True)
        self.ui.action_exit.setEnabled(True)


    # 清除内容
    def clean(self):
        reply = QMessageBox.question(self, '温馨提示',
                                     "该操作将会清除所有内容！",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.clear()
            self.ui.action_save_as.setEnabled(False)


    # 展示详细信息

    class CustomTreeWidgetItem(QTreeWidgetItem):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

    def show_detail(self, item: QTableWidgetItem):
        tree: QTreeWidget = self.ui.detail_tree
        tab: QTabWidget = self.ui.tab

        # 设置树的样式表
        tree.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #ccc;
                background-color: #f9f9f9;
            }
            QTreeWidget::item {
                border-bottom: 1px solid #ccc;
            }
        """)

        # 清除旧的项
        tree.clear()

        # 获取行号和相关信息
        row = item.row()
        number = int(self.ui.table.item(row, 0).text()) - 1
        info = self.s.packet_list[number].detail_info

        # 设置字体和图标
        font = QFont()
        font.setBold(True)

        for layer, layer_info in info.items():
            root = self.CustomTreeWidgetItem(tree)
            root.setText(0, layer)
            root.setFont(0, font)  # 设置粗体字

            if layer_info:
                for key, value in layer_info.items():
                    if value is None:
                        value = ''
                    node = self.CustomTreeWidgetItem(root)
                    node.setText(0, key)
                    node.setText(1, value)
                    root.addChild(node)

        tree.expandAll()
        tab.setCurrentIndex(0)

    # 展示hex信息
    def hex(self, item: QTableWidgetItem):
        row = item.row()
        number = int(self.ui.table.item(row, 0).text()) - 1
        text: QTextBrowser = self.ui.hex_text
        text.clear()
        hex_info = self.s.packet_list[number].hex_info
        text.setText(hex_info)


    def look_up(self):
        try:
            search_text: QLineEdit = self.ui.search_text
            text = search_text.text()
            self.clear_table()
            if text == '':
                for p in self.s.packet_list:
                    self.contiue(p)
            else:
                searcher = PacketFinder(self.s.packet_list, text)
                result = searcher.find_packets()
                for p in result:
                    self.contiue(p)
        except Exception as e:
            print(f"An error occurred: {e}")
            import traceback
            traceback.print_exc()



    def save(self):
        try:
            save_list = []
            assemble_rows = self.ui.table.selectedIndexes()
            rows = set(tmp_row.row() for tmp_row in assemble_rows)
            if len(rows) > 0:
                for row in rows:
                    number = int(self.ui.table.item(row, 0).text()) - 1
                    save_list.append(self.s.packet_list[number].to_dict())
                for i, save_dict in enumerate(sorted(save_list, key=lambda x: x['time'])):
                    save_dict['number'] = i + 1
                filepath, _ = QFileDialog.getSaveFileName(
                    self,  # 父窗口对象
                    "保存文件",  # 标题
                    "./save/",  # 起始目录
                    "json类型 (*.json);;All Files (*)"
                )
                if filepath:
                    with open(filepath, 'w') as f:
                        f.write(json.dumps(save_list))
                        f.close()
                    QMessageBox.information(self, '提示', '保存成功', QMessageBox.Yes)
            else:
                QMessageBox.warning(self, "警告", "至少选择一个包。", QMessageBox.Yes)
        except Exception as e:
            print(e)


    def read(self):
        file, _ = QFileDialog.getOpenFileName(self, "选择已保存的文件", '', '(*.json)')
        if file:
            try:
                self.clear()
                packet_list1 = []
                with open(file, 'r') as f:
                    save_list = json.loads(f.read())
                    for packet_dict in save_list:
                        p = PacketInfo()
                        p.from_dict(packet_dict)
                        packet_list1.append(p)
                    self.s.packet_list = packet_list1
                    f.close()
                for p in self.s.packet_list:
                    self.contiue(p)
                QMessageBox.information(self, '提示', '读取成功', QMessageBox.Yes)
            except Exception as e:
                QMessageBox.warning(self, "警告", "读取出现异常", QMessageBox.Yes)
                print(e)



if __name__ == '__main__':
    app = QApplication(sys.argv)  # 创建QApplication对象
    window = MainWindow()  # 创建MainWindow对象
    window.showMaximized()  # 显示最大化的窗口
    window.ui.table.setColumnWidth(4, 150)
    window.ui.table.setColumnWidth(5, 150)
    window.ui.table.setColumnWidth(6, 170)
    sys.exit(app.exec_())  # 运行事件循环
