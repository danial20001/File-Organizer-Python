from netmiko import ConnectHandler
from getpass import getpass
import os

# List of device hostnames
devices = [
    "device1",
    "device2",
    "device3",
    # Add more devices as needed
]

# Commands to execute on devices
commands = [
    "show license usage",
    "show version",
    "show running-config",
    # Add more commands as needed
]

def connect_to_device(hostname, username, password, commands, output_file):
    """Connects to a device using Netmiko and runs multiple commands."""
    try:
        # Define device parameters
        device = {
            "device_type": "cisco_ios",  # Change this to match your device type
            "host": hostname,
            "username": username,
            "password": password,
        }

        # Connect to the device
        connection = ConnectHandler(**device)

        # Append the output for each command
        with open(output_file, "a") as file:
            file.write(f"--- Output for {hostname} ---\n")
            for command in commands:
                file.write(f"\n>>> Command: {command}\n")
                output = connection.send_command(command)
                file.write(output + "\n")
            file.write("\n" + "=" * 50 + "\n\n")

        print(f"Output for {hostname} saved in {output_file}")
        connection.disconnect()

    except Exception as e:
        # Log the error for the device
        error_file = "error_log.txt"
        with open(error_file, "a") as log:
            log.write(f"Failed to connect to {hostname}: {e}\n")
        print(f"Failed to connect to {hostname}: {e}")

def main():
    # Ask for username and password once
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")  # Secure password input

    # Define the single output file name
    output_file = "all_device_outputs.txt"

    # Clear the file at the start (if it already exists)
    with open(output_file, "w") as file:
        file.write("Device Command Outputs\n")
        file.write("=" * 50 + "\n\n")

    # Iterate over devices and run the commands
    for device in devices:
        print(f"Connecting to {device}...")
        connect_to_device(device, username, password, commands, output_file)

    print("All tasks completed. Check all_device_outputs.txt for results.")
    print("Check error_log.txt for failures, if any.")

if __name__ == "__main__":
    main()







Dim managerRaw As String
Dim managerClean As String

managerRaw = .manager ' Get the raw manager DN
If managerRaw <> "" Then
    ' Remove "CN=" and anything after a comma
    managerClean = Replace(managerRaw, "CN=", "")
    managerClean = Replace(managerClean, "\", "") ' Remove the slash
    managerClean = Left(managerClean, InStr(managerClean, ",") - 1) ' Extract until first comma
Else
    managerClean = "N/A" ' Handle cases where manager is not set
End If

' Write the cleaned name to the Manager column
shtADQuery.[ra_Results_Manager].Offset(IngRowOffset, 0).Value = managerClean


import subprocess

# Define the subnet details
subnets = ["10.244.230", "10.244.231"]  # Covers the full /23 range
start_ip = 0
end_ip = 255

# Output file to save results
output_file = "nslookup_results_10.244.230.0_23.txt"

print(f"Starting nslookup scan for /23 subnet: {subnets[0]}.0 to {subnets[1]}.255")
with open(output_file, "w") as file:
    for subnet in subnets:
        for i in range(start_ip, end_ip + 1):
            ip = f"{subnet}.{i}"
            try:
                # Run nslookup for the current IP
                result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)

                # Write the raw output to the file
                file.write(f"Results for {ip}:\n")
                file.write(result.stdout + "\n")
                file.write("-" * 50 + "\n")  # Separator for readability
                print(f"Checked {ip}, results saved.")
            except subprocess.TimeoutExpired:
                print(f"{ip} timed out.")
                file.write(f"Results for {ip}:\nTimeout\n")
                file.write("-" * 50 + "\n")
            except Exception as e:
                print(f"Error for {ip}: {e}")
                file.write(f"Results for {ip}:\nError: {e}\n")
                file.write("-" * 50 + "\n")

print(f"Scan completed. Results saved to {output_file}")



import subprocess

# Define your subnet range
subnet = "10.344.344"
start_ip = 1
end_ip = 254

# Open a file to save raw results
output_file = "nslookup_raw_results.txt"

print(f"Starting nslookup scan for {subnet}.{start_ip}-{end_ip}")
with open(output_file, "w") as file:
    for i in range(start_ip, end_ip + 1):
        ip = f"{subnet}.{i}"
        try:
            # Run nslookup for the current IP
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)

            # Write the raw output to the file
            file.write(f"Results for {ip}:\n")
            file.write(result.stdout + "\n")
            file.write("-" * 50 + "\n")  # Separator for readability
            print(f"Checked {ip}, results saved.")
        except subprocess.TimeoutExpired:
            print(f"{ip} timed out.")
            file.write(f"Results for {ip}:\nTimeout\n")
            file.write("-" * 50 + "\n")
        except Exception as e:
            print(f"Error for {ip}: {e}")
            file.write(f"Results for {ip}:\nError: {e}\n")
            file.write("-" * 50 + "\n")

print(f"Scan completed. Raw results saved to {output_file}")



import sys
import os
import shutil
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QFileDialog
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtCore import pyqtSlot, QUrl
from datetime import datetime, timedelta
from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import pyqtSignal


import numpy as np
from tensorflow import keras
from keras.preprocessing import image
from keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input, decode_predictions







class ClickableLabel(QLabel):
    clicked = pyqtSignal()  # Define the signal

    def mousePressEvent(self, event):
        self.clicked.emit()  # Emit the signal


class FileOrganizerApp(QWidget):
    def __init__(self, auto_run=False):
        super().__init__()
        self.image_model = MobileNetV2(weights='imagenet')
        self.initUI()
        
        if auto_run:
            self.organize_files()
        
    def initUI(self):
        layout = QVBoxLayout()

        self.srcDirLabel = QLabel("Source Directory:")
        self.srcDirPathLabel = ClickableLabel("C:/Users/dania/Desktop")  # Default directory
        self.chooseDirButton = QPushButton("Choose Directory", self)
        self.organizeButton = QPushButton("Organize Files", self)
        self.viewHistoryButton = QPushButton("View History", self)
        self.logDisplay = QTextEdit(self)
        self.logDisplay.setReadOnly(True)

        layout.addWidget(self.srcDirLabel)
        layout.addWidget(self.srcDirPathLabel)
        layout.addWidget(self.chooseDirButton)
        layout.addWidget(self.organizeButton)
        layout.addWidget(self.viewHistoryButton)
        layout.addWidget(self.logDisplay)

        self.chooseDirButton.clicked.connect(self.choose_directory)
        self.organizeButton.clicked.connect(self.organize_files)
        self.viewHistoryButton.clicked.connect(self.show_history)
        self.srcDirPathLabel.clicked.connect(self.open_folder_in_explorer)

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

    @pyqtSlot()
    def open_folder_in_explorer(self):
        folder_path = self.srcDirPathLabel.text()
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder_path))

    def log_move(self, src, dst):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"[{timestamp}] Moved '{src}' to '{dst}'\n"
        self.logDisplay.append(message)

        with open('file_move_history.log', 'a') as log_file:
            log_file.write(message)

    def move_with_rename(self, src, dst):
        if not os.path.exists(dst):
            shutil.move(src, dst)
            self.log_move(src, dst)
        else:
            base, extension = os.path.splitext(dst)
            counter = 1
            new_dst = f"{base} ({counter}){extension}"
            while os.path.exists(new_dst):
                counter += 1
                new_dst = f"{base} ({counter}){extension}"
            shutil.move(src, new_dst)
            self.log_move(src, new_dst)

    def classify_image(self, img_path):
        img = image.load_img(img_path, target_size=(224, 224))
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)

        predictions = self.image_model.predict(img_array)
        decoded_predictions = decode_predictions(predictions, top=1)[0][0]
        return decoded_predictions[1]  # Return the most likely category label

    def organize_desktop(self, desktop_path):
        # Define paths...
        documents_path = r"C:\Users\dania\OneDrive\Documenti\PDF"
        python_projects_path = r"C:\Users\dania\OneDrive\Documenti\Projects"
        downloads_path = r"C:\Users\dania\Downloads"
        screenshots_path = r"C:\Users\dania\OneDrive\Immagini\Screenshots"
        other_images_path = r"C:\Users\dania\OneDrive\Immagini\Other"
        word_documents_path = r"C:\Users\dania\OneDrive\Documenti\World Documents"


        files_on_desktop = [os.path.join(desktop_path, f) for f in os.listdir(desktop_path) if os.path.isfile(os.path.join(desktop_path, f))]

        for img_file in [f for f in files_on_desktop if f.endswith(('.jpg', '.png', '.gif', '.jpeg', '.avif'))]:
            full_img_path = os.path.join(desktop_path, img_file)
            category = self.classify_image(full_img_path)

            if "screenshot" in category.lower():
                destination = os.path.join(screenshots_path, os.path.basename(img_file))
            else:
                new_name = f"{category}_{os.path.basename(img_file)}"
                destination = os.path.join(other_images_path, new_name)

            self.move_with_rename(full_img_path, destination)

        # Continue organizing other file types as before
        # ...
        # Organize PDFs
        for pdf in [f for f in files_on_desktop if f.endswith('.pdf')]:
            self.move_with_rename(pdf, os.path.join(documents_path, os.path.basename(pdf)))

        # Organize .py files
        for py_file in [f for f in files_on_desktop if f.endswith('.py')]:
            self.move_with_rename(py_file, os.path.join(python_projects_path, os.path.basename(py_file)))

        # Organize .zip files
        for zip_file in [f for f in files_on_desktop if f.endswith('.zip')]:
            self.move_with_rename(zip_file, os.path.join( downloads_path, os.path.basename(zip_file)))

        for doc_file in [f for f in files_on_desktop if f.endswith('.docx')]:
            self.move_with_rename(doc_file, os.path.join(word_documents_path, os.path.basename(doc_file)))

    def read_log_history(self):
        two_weeks_ago = datetime.now() - timedelta(days=14)
        history = ""

        with open('file_move_history.log', 'r') as log_file:
            for line in log_file:
                if line.strip():
                    timestamp_str = line.split(']')[0].strip('[')
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    if timestamp > two_weeks_ago:
                        history += line

        return history

    def show_history(self):
        history = self.read_log_history()
        self.logDisplay.clear()
        self.logDisplay.append(history)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    auto_run_flag = '--auto-run' in sys.argv
    ex = FileOrganizerApp(auto_run=auto_run_flag)
    if not auto_run_flag:
        sys.exit(app.exec_())  # Only start the event loop if not auto-running
import subprocess

# Define your subnet range
subnet = "10.344.344"
start_ip = 1
end_ip = 254

# Open a file to save results
output_file = "nslookup_results.txt"

print(f"Starting nslookup scan for {subnet}.{start_ip}-{end_ip}")
with open(output_file, "w") as file:
    for i in range(start_ip, end_ip + 1):
        ip = f"{subnet}.{i}"
        try:
            # Run nslookup for the current IP
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)
            
            # Process the result
            if "name =" in result.stdout.lower():
                hostname = result.stdout.split("name =")[1].strip().split("\n")[0]
                print(f"{ip} resolves to {hostname}")
                file.write(f"{ip} resolves to {hostname}\n")
            else:
                print(f"{ip} does not resolve to a hostname")
                file.write(f"{ip} does not resolve to a hostname\n")
        except subprocess.TimeoutExpired:
            print(f"{ip} timed out")
            file.write(f"{ip}: Timeout\n")
        except Exception as e:
            print(f"Error for {ip}: {e}")
            file.write(f"{ip}: Error: {e}\n")

print(f"Scan completed. Results saved to {output_file}")
