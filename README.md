# Reverse Shell Handler

Reverse Shell Handler is a graphical offensive security tool built in Python that allows users to generate reverse shell payloads, start a TCP listener, and interact with connected targets through an integrated command shell.

This project was developed as part of a **university coursework assignment** for educational and ethical hacking purposes.

---

## ⚠️ Disclaimer

This tool is created strictly for:

- Authorized security testing  
- Cybersecurity coursework  
- Learning and research  
- Capture The Flag (CTF) challenges  

**Do NOT use this tool on any system without explicit permission.**  
Unauthorized usage is illegal and unethical. The author is not responsible for any misuse.

---

## 📌 Features

### Payload Generator
- Generate multiple reverse shell payload types  
- Supported payloads:
  - Bash TCP / UDP  
  - Python  
  - PHP  
  - Netcat (multiple methods)  
  - Perl  
  - Ruby  
  - Socat  
- Copy generated payload to clipboard  
- Simple and intuitive interface  

### Integrated Listener & Shell
- Built-in TCP listener (no external netcat required)  
- Interactive reverse shell console  
- Real-time command execution  
- Command history navigation  
- Activity logging  
- ANSI escape code filtering for clean output  

### Smart Synchronization
- IP address and port entered in the generator tab are automatically synced to the listener tab  
- Prevents retyping and configuration mistakes  

### User Interface
- Dark themed Tkinter GUI  
- Split panel view:
  - Shell output panel  
  - Activity log panel  
- Quick action command buttons  

---

## 📁 Project Structure

├── requirements.txt
└── Reverse Shell Handler.py

---

## 🛠 Requirements

- Python 3.x  
- Tkinter (included with Python by default)  
- pyperclip

Install dependencies:

```bash
pip install -r requirements.txt

