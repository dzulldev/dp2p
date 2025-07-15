import socket
import threading
import os
import random
import time
import uuid
from datetime import datetime

# ====== CONFIG ======
PORT = 6666
UDP_PORT = 7777
BUFFER = 1024

peers = {}
lock = threading.Lock()
message_history = set()

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

# ====== PEER COMMUNICATION ======

def send_all(msg_id, msg):
    with lock:
        for ip, conn in list(peers.items()):
            try:
                conn.sendall(f"{msg_id}|{msg}".encode())
            except:
                continue

def send_whisper(target_ip, msg):
    with lock:
        conn = peers.get(target_ip)
        if conn:
            try:
                msg_id = generate_msg_id()
                conn.sendall(f"{msg_id}|{msg}".encode())
                return True
            except:
                return False
    return False

def recv_from_peer(conn, addr):
    while True:
        try:
            data = conn.recv(BUFFER)
            if not data:
                break

            raw = data.decode().strip()
            if "|" not in raw:
                continue

            msg_id, msg = raw.split("|", 1)
            if msg_id in message_history:
                continue

            message_history.add(msg_id)
            print(f"\n{timestamp()} {msg}\n<@{name}> ", end="", flush=True)
            send_all(msg_id, msg)
        except:
            break

    with lock:
        for ip, peer_conn in list(peers.items()):
            if peer_conn == conn:
                del peers[ip]
    conn.close()

# ====== SERVER SETUP ======

def server_thread():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', PORT))
    s.listen()

    while True:
        try:
            conn, addr = s.accept()
            ip = addr[0]
            with lock:
                if ip not in peers:
                    peers[ip] = conn
                    threading.Thread(target=recv_from_peer, args=(conn, addr), daemon=True).start()
                    print_connected(ip)
        except:
            continue

def connect_to_peer(ip):
    if ip == my_ip or ip in peers:
        return
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, PORT))
        with lock:
            peers[ip] = conn
        threading.Thread(target=recv_from_peer, args=(conn, (ip, PORT)), daemon=True).start()
        print_connected(ip)
    except:
        print(f"\n{timestamp()} fail connect to {ip}\n<@{name}> ", end="", flush=True)

# ====== BROADCAST DISCOVERY ======

def udp_broadcast():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        try:
            udp.sendto(my_ip.encode(), ('<broadcast>', UDP_PORT))
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

# ====== NETWORK HELPERS ======

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

# ====== MAIN CHAT LOOP ======

if __name__ == "__main__":
    clear()
    name = input("your name (leave blank for random): ").strip().lower()
    if not name:
        name = random_name()

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

            if msg.startswith("/name "):
                name = msg.split(" ", 1)[1].strip().lower()
                print(f"name changed to {name}")

            elif msg.startswith("/whisper "):
                parts = msg.split(" ", 2)
                if len(parts) == 3:
                    ip, message = parts[1], parts[2]
                    ok = send_whisper(ip, f"{timestamp()} <@{name}> (whisper): {message}")
                    if not ok:
                        print(f"fail whisper to {ip}")

            elif msg == "/peers":
                print("connected peers:")
                with lock:
                    for ip in peers:
                        print(f" - {ip}")

            elif msg == "/exit":
                print("bye.")
                break

            else:
                full_msg = f"{timestamp()} <@{name}>: {msg}"
                msg_id = generate_msg_id()
                send_all(msg_id, full_msg)
                print(full_msg)

            print(f"<@{name}> ", end="", flush=True)

        except KeyboardInterrupt:
            print("\nbye.")
            break
