import sys
import os
import ctypes
import psutil
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton, QComboBox, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt

class DLLInjectorApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("DLL Injector")
        self.setGeometry(100, 100, 400, 250)

        layout = QVBoxLayout()


        self.process_label = QLabel("Select a Process:")
        self.process_dropdown = QComboBox()
        self.populate_process_dropdown()


        self.choose_dll_button = QPushButton("Choose DLL")
        self.choose_dll_button.clicked.connect(self.choose_dll)


        self.inject_button = QPushButton("Inject DLL")
        self.inject_button.clicked.connect(self.inject_dll)


        self.result_label = QLabel("Injection Status: ")
        self.result_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result_label.setStyleSheet("font-weight: bold;")


        self.dll_label = QLabel("Chosen DLL:")
        self.dll_label_value = QLabel()
        self.dll_label_value.setStyleSheet("font-style: italic;")


        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.process_label)
        layout.addWidget(self.process_dropdown)
        layout.addWidget(self.choose_dll_button)
        layout.addWidget(self.inject_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.dll_label)
        layout.addWidget(self.dll_label_value)
        layout.addWidget(self.status_label)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

    def choose_dll(self):
        file_dialog = QFileDialog()
        file_name, _ = file_dialog.getOpenFileName(self, "Select DLL File", "", "DLL Files (*.dll);;All Files (*)")

        if file_name:
            self.selected_dll = file_name
            self.dll_label_value.setText(file_name)

    def populate_process_dropdown(self):
        process_list = [proc.info['name'] for proc in psutil.process_iter(attrs=['pid', 'name'])]
        self.process_dropdown.addItems(process_list)

    def inject_dll(self):
        process_name = self.process_dropdown.currentText()

        if hasattr(self, 'selected_dll') and self.selected_dll:
            if self.inject_dll_code(self.selected_dll, process_name):
                self.result_label.setText(f"Injection Status: Injected '{self.selected_dll}' into '{process_name}' successfully.")
                self.result_label.setStyleSheet("color: green;")
                self.status_label.setText("Injection successful.")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.result_label.setText(f"Injection Status: Failed to inject '{self.selected_dll}' into '{process_name}'.")
                self.result_label.setStyleSheet("color: red;")
                self.status_label.setText("Injection failed.")
                self.status_label.setStyleSheet("color: red;")
        else:
            self.result_label.setText("Injection Status: Please choose a DLL file and a target process.")
            self.result_label.setStyleSheet("color: black;")
            self.status_label.clear()

    def inject_dll_code(self, dll_path, process_name):
        pid = None
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if proc.info['name'] == process_name:
                pid = proc.info['pid']
                break

        if pid:
            process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)

            if process_handle:
                dll_path = os.path.abspath(dll_path)
                kernel32 = ctypes.windll.kernel32
                kernel32_path = kernel32.GetModuleHandleW(None)
                kernel32.LoadLibraryW.restype = ctypes.c_void_p
                remote_dll = kernel32.LoadLibraryW(ctypes.c_wchar_p(dll_path))

                if remote_dll:
                    ctypes.windll.kernel32.CloseHandle(process_handle)
                    return True

        return False

def main():
    app = QApplication(sys.argv)
    window = DLLInjectorApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
