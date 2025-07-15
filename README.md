# dp2p Terminal Chat

![Python](https://img.shields.io/badge/python-3.x-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Stars](https://img.shields.io/github/stars/dzulldev/dp2p?style=social)
![Last Commit](https://img.shields.io/github/last-commit/dzulldev/dp2p?color=orange)

A lightweight peer-to-peer terminal-based chat app built with Python.  
Communicates over **local network** (LAN) without any central server.  
Simple. Fast. Private. 🔐⚡

---

## ✨ Features

- 🔍 **Automatic peer discovery** using UDP broadcast
- 💬 **Real-time chat** with timestamp and username
- 👤 **Private messages** using `/whisper`
- 🧠 **Deduplication** of messages with UUID
- 🧑‍🤝‍🧑 **See all connected peers** using `/peers`
- 📝 **Change your name** on the fly with `/name`
- 🖥️ **Clean CLI interface**, just like a real terminal
- 🔌 Runs completely offline in local network

---

## ⚙️ Requirements

- Python 3.x
- Runs on:
  - ✅ Linux
  - ✅ Android (Termux)
  - ✅ macOS
  - ⚠️ Windows (limited UDP broadcast support)

---

## 🚀 How to Run

1. Clone or download the script:
   ```bash
   git clone https://github.com/dzulldev/dp2p.git
   ```
2. Open Folder
   ```bash
   cd dp2p
   ```

3. Run The Script
   ```bash
   python dp2p.py
   ```

4. Enter your name (or leave blank for random):

    your name (leave blank for random): gavin

6. You're in! Chat away! 🗨️

---

🧠 Available Commands

/name newname — change your display name

/peers — show list of connected peers

/whisper IP message — send private message to a peer

/exit — quit the chat

---

💡 Example

your ip: 192.168.0.42

<@anon1023> hello!
[14:22:01] <@anon1023>: hello!

[14:22:03] connected: 192.168.0.13
[14:22:04] <@anon5698>: hi bro

<@anon1023>

---

🔐 How It Works

Uses TCP sockets for messaging and UDP sockets for discovery.

When script runs, it broadcasts your IP via UDP.

When another device receives your broadcast, it connects to you using TCP.

All messages include a unique ID to prevent duplicate broadcasting.

---

🛠 Use Case

Local anonymous chatting in a school lab, office, or café ☕

Testing socket communication over LAN

Learning peer-to-peer basics

---

📄 License

MIT — free for personal and educational use.

---

🙋‍♂️ Author

Built by ChatGPT
Feel free to fork, modify, or contribute!

