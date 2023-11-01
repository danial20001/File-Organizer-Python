import sys
import os
import shutil
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QTextEdit, QLabel
from PyQt5.QtCore import pyqtSlot
from datetime import datetime  # <-- Add this

class FileOrganizerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()

        self.srcDirLabel = QLabel("Source Directory:")
        self.srcDirPathLabel = QLabel("C:/Users/Danial/Desktop")  # Default directory
        self.chooseDirButton = QPushButton("Choose Directory", self)
        self.organizeButton = QPushButton("Organize Files", self)
        self.logDisplay = QTextEdit(self)
        self.logDisplay.setReadOnly(True)

        layout.addWidget(self.srcDirLabel)
        layout.addWidget(self.srcDirPathLabel)
        layout.addWidget(self.chooseDirButton)
        layout.addWidget(self.organizeButton)
        layout.addWidget(self.logDisplay)

        self.chooseDirButton.clicked.connect(self.choose_directory)
        self.organizeButton.clicked.connect(self.organize_files)

        self.setLayout(layout)
        self.setWindowTitle('Desktop File Organizer')
        self.show()

    @pyqtSlot()
    def choose_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_path:
            self.srcDirPathLabel.setText(dir_path)

    @pyqtSlot()
    def organize_files(self):
        src_dir = self.srcDirPathLabel.text()
        self.logDisplay.append(f"Organizing files from {src_dir}")
        self.organize_desktop(src_dir)
        self.logDisplay.append("Organization completed.")

    def log_move(self, src, dst):  # <-- Add this function
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"[{timestamp}] Moved '{src}' to '{dst}'"
        self.logDisplay.append(message)

    def move_with_rename(self, src, dst):
        if not os.path.exists(dst):
            shutil.move(src, dst)
            self.log_move(src, dst)  # <-- Add this
        else:
            base, extension = os.path.splitext(dst)
            counter = 1
            while os.path.exists(dst):
                dst = f"{base} ({counter}){extension}"
                counter += 1
            shutil.move(src, dst)
            self.log_move(src, dst)  # <-- And this

    def organize_desktop(self, desktop_path):
        # Define paths
        pictures_path = "C:/Users/Danial/Pictures/Saved Pictures"
        documents_path = "C:/Users/Danial/Documents"
        screenshots_path = os.path.join("C:/Users/Danial/Pictures/Screenshots")
        python_projects_path = "C:/Users/Danial/IdeaProjects/Random .py"
        downloads_path = "C:/Users/Danial/Downloads"

        # Ensure destination folders exist
        for path in [pictures_path, documents_path, screenshots_path, python_projects_path, downloads_path]:
            os.makedirs(path, exist_ok=True)

        # Get all files on the desktop
        files_on_desktop = [os.path.join(desktop_path, f) for f in os.listdir(desktop_path) if os.path.isfile(os.path.join(desktop_path, f))]

        # Move images
        for img in [f for f in files_on_desktop if f.endswith(('.jpg', '.png', '.gif', '.jpeg', 'avif'))]:
            if "screenshot" in os.path.basename(img).lower() or "screen shot" in os.path.basename(img).lower():
                self.move_with_rename(img, os.path.join(screenshots_path, os.path.basename(img)))
            else:
                self.move_with_rename(img, os.path.join(pictures_path, os.path.basename(img)))

        # Move PDFs
        for pdf in [f for f in files_on_desktop if f.endswith('.pdf')]:
            self.move_with_rename(pdf, os.path.join(documents_path, os.path.basename(pdf)))

        # Move .py files
        for py_file in [f for f in files_on_desktop if f.endswith('.py')]:
            self.move_with_rename(py_file, os.path.join(python_projects_path, os.path.basename(py_file)))

        # Move .zip files
        for zip_file in [f for f in files_on_desktop if f.endswith('.zip')]:
            self.move_with_rename(zip_file, os.path.join(downloads_path, os.path.basename(zip_file)))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FileOrganizerApp()
    sys.exit(app.exec_())
