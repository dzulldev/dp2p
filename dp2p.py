# dp2p_refactored.py

import socket
import threading
import os
import random
import time
import uuid
import re
import json
from datetime import datetime
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import DSA
from Crypto.Random.random import randint
from Crypto.Hash import SHA256

# ====== CONFIG ======

PORT = 6666
UDP_PORT = 7777
BUFFER = 1024
MAX_MESSAGE_LENGTH = 512
VALID_CHAR_PATTERN = re.compile(r'^[\x20-\x7E\n\r\t]+$')

peers = {}
shared_keys = {}
lock = threading.Lock()
message_history = set()
log_file = "chat_log.txt"

# ====== UTILITIES ======

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def random_name():
    return "anon" + str(random.randint(1000, 9999))

def generate_msg_id():
    return str(uuid.uuid4())

def timestamp():
    return time.strftime("[%H:%M:%S]")

def print_connected(ip):
    print(f"\n{timestamp()} connected: {ip}\n<@{name}> ", end="", flush=True)

def log_message(msg):
    with open(log_file, 'a') as f:
        f.write(msg + "\n")

def is_valid_message(msg):
    return len(msg) <= MAX_MESSAGE_LENGTH and VALID_CHAR_PATTERN.match(msg)

def generate_dh_key():
    private = randint(1, 1000000)
    public = pow(5, private, 997)
    return private, public

def compute_dh_shared(peer_pub, private):
    return SHA256.new(str(pow(int(peer_pub), private, 997)).encode()).digest()[:16]

def encrypt_msg(msg, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(msg.encode(), AES.block_size))
    return b64encode(iv + ct).decode()

def decrypt_msg(enc_msg, key):
    try:
        data = b64decode(enc_msg)
        iv, ct = data[:16], data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception as e:
        return f"[Decryption Failed: {e}]"

# ====== COMMUNICATION ======

def send_json(conn, obj):
    try:
        conn.sendall(json.dumps(obj).encode())
    except Exception as e:
        print(f"[!] Failed to send: {e}")

def send_all(msg_id, msg):
    with lock:
        for ip, conn in list(peers.items()):
            key = shared_keys.get(ip)
            if key:
                send_json(conn, {
                    "id": msg_id,
                    "type": "msg",
                    "data": encrypt_msg(msg, key)
                })

def send_whisper(target_ip, msg):
    with lock:
        conn = peers.get(target_ip)
        key = shared_keys.get(target_ip)
        if conn and key:
            try:
                msg_id = generate_msg_id()
                send_json(conn, {
                    "id": msg_id,
                    "type": "whisper",
                    "data": encrypt_msg(msg, key)
                })
                return True
            except Exception as e:
                print(f"[!] Failed whisper to {target_ip}: {e}")
    return False

def recv_from_peer(conn, addr):
    ip = addr[0]
    while True:
        try:
            data = conn.recv(BUFFER)
            if not data:
                break

            msg = json.loads(data.decode())
            msg_id = msg.get("id")
            if msg_id in message_history:
                continue
            message_history.add(msg_id)

            key = shared_keys.get(ip)
            if key:
                text = decrypt_msg(msg.get("data"), key)
                if msg.get("type") == "whisper":
                    print(f"\n{timestamp()} <@{ip}> (whisper): {text}")
                else:
                    print(f"\n{timestamp()} <@{ip}>: {text}")
                    log_message(f"{timestamp()} <@{ip}>: {text}")

            print(f"<@{name}> ", end="", flush=True)
        except Exception as e:
            print(f"[!] Error receiving from {ip}: {e}")
            break

    with lock:
        if ip in peers:
            del peers[ip]
            del shared_keys[ip]
    conn.close()
    print(f"\n{timestamp()} {ip} disconnected.")
    print(f"<@{name}> ", end="", flush=True)

def perform_dh_handshake(conn, addr):
    ip = addr[0]
    try:
        priv, pub = generate_dh_key()
        conn.sendall(str(pub).encode())
        peer_pub = conn.recv(BUFFER).decode()
        key = compute_dh_shared(peer_pub, priv)
        shared_keys[ip] = key
        peers[ip] = conn
        threading.Thread(target=recv_from_peer, args=(conn, addr), daemon=True).start()
        print_connected(ip)
    except Exception as e:
        print(f"[!] DH handshake failed with {ip}: {e}")
        conn.close()

# ====== SERVER ======

def server_thread():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', PORT))
    s.listen()
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=perform_dh_handshake, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[!] Accept error: {e}")

def connect_to_peer(ip):
    if ip == my_ip or ip in peers:
        return
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(3)
        conn.connect((ip, PORT))
        peer_pub = conn.recv(BUFFER).decode()
        priv, pub = generate_dh_key()
        conn.sendall(str(pub).encode())
        key = compute_dh_shared(peer_pub, priv)
        shared_keys[ip] = key
        peers[ip] = conn
        threading.Thread(target=recv_from_peer, args=(conn, (ip, PORT)), daemon=True).start()
        print_connected(ip)
    except Exception as e:
        print(f"[!] Failed to connect to {ip}: {e}")

def reconnect_peer(ip):
    time.sleep(2)
    connect_to_peer(ip)

# ====== BROADCAST ======

def udp_broadcast():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        try:
            udp.sendto(my_ip.encode(), ('', UDP_PORT))
        except:
            pass
        time.sleep(5)

def udp_listener():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(('', UDP_PORT))
    while True:
        try:
            data, addr = udp.recvfrom(BUFFER)
            peer_ip = data.decode().strip()
            if peer_ip != my_ip:
                connect_to_peer(peer_ip)
        except:
            continue

# ====== IP HELPER ======

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# ====== MAIN LOOP ======

if __name__ == "__main__":
    clear()
    name = input("your name (leave blank for random): ").strip().lower() or random_name()
    my_ip = get_my_ip()

    threading.Thread(target=server_thread, daemon=True).start()
    threading.Thread(target=udp_broadcast, daemon=True).start()
    threading.Thread(target=udp_listener, daemon=True).start()

    time.sleep(0.5)
    print(f"\nyour ip: {my_ip}\n")
    print(f"<@{name}> ", end="", flush=True)

    while True:
        try:
            msg = input().strip()
            if not msg:
                print(f"<@{name}> ", end="", flush=True)
                continue

            if msg == "/help":
                print("""
/peers         Show connected peers
/name <new>    Change your nickname
/whisper <ip> <message>     Send private message
/exit          Exit chat
/help          Show help
""")
            elif msg.startswith("/name "):
                name = msg.split(" ", 1)[1].strip().lower()
                print(f"name changed to {name}")
            elif msg.startswith("/whisper "):
                parts = msg.split(" ", 2)
                if len(parts) == 3:
                    ip, message = parts[1], parts[2]
                    if is_valid_message(message):
                        ok = send_whisper(ip, f"{timestamp()} <@{name}>: {message}")
                        if not ok:
                            print(f"[!] Failed to whisper to {ip}")
                    else:
                        print("[!] Invalid whisper message.")
            elif msg == "/peers":
                print("connected peers:")
                with lock:
                    for ip in peers:
                        print(f" - {ip}")
            elif msg == "/exit":
                print("bye.")
                os._exit(0)
            elif is_valid_message(msg):
                full_msg = f"{timestamp()} <@{name}>: {msg}"
                msg_id = generate_msg_id()
                send_all(msg_id, full_msg)
                print(full_msg)
                log_message(full_msg)
            else:
                print("[!] Invalid message.")
            print(f"<@{name}> ", end="", flush=True)
        except KeyboardInterrupt:
            print("\nbye.")
            os._exit(0)
        except Exception as e:
            print(f"[!] Error: {e}")
            print(f"<@{name}> ", end="", flush=True)
