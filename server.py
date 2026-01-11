#!/usr/bin/env python3

import socket
import threading
import ssl
import json

clients_lock = threading.Lock()

def send_json(sock, obj):
    try:
        data = (json.dumps(obj) + "\n").encode()
        sock.sendall(data)
    except Exception:
        pass

def broadcast(clients, sender_sock, obj):
    to_remove = []
    with clients_lock:
        for client in list(clients):
            try:
                if client is not sender_sock:
                    send_json(client, obj)
            except Exception:
                to_remove.append(client)
        for c in to_remove:
            if c in clients:
                clients.remove(c)
                try:
                    c.close()
                except:
                    pass

def client_thread(cln_socket, clients, usernames):
    buffer = ""
    user = None
    try:
        while True:
            data = cln_socket.recv(4096)
            if not data:
                break
            buffer += data.decode(errors="ignore")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue
                try:
                    msg_obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                mtype = msg_obj.get("type")
                if mtype == "introduce":
                    user = msg_obj.get("user", "<unknown>")
                    with clients_lock:
                        usernames[cln_socket] = user
                    system = {"type":"system", "msg": f"[ ! ] User {user} has connected to the chat"}
                    broadcast(clients, cln_socket, system)
                elif mtype == "chat":
                    chat = {"type":"chat", "user": msg_obj.get("user", "<unknown>"), "msg": msg_obj.get("msg","")}
                    broadcast(clients, cln_socket, chat)
                elif mtype == "command":
                    cmd = msg_obj.get("cmd", "")
                    if cmd == "!users":
                        with clients_lock:
                            user_list = list(usernames.values())
                        reply = {"type":"users", "users": user_list}
                        send_json(cln_socket, reply)
                    elif cmd == "!exit":
                        raise ConnectionResetError()
    except Exception:
        pass
    finally:
        try:
            cln_socket.close()
        except:
            pass
        with clients_lock:
            if cln_socket in clients:
                clients.remove(cln_socket)
            left_name = usernames.pop(cln_socket, "<unknown>")
        system = {"type":"system", "msg": f"[ ! ] User {left_name} has left the chat"}
        broadcast(clients, None, system)

def server_program():
    s_addr = ('localhost', 12345)
    host, port = s_addr
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.key")

    svr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svr_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svr_socket.bind(s_addr)
    svr_socket.listen()

    svr_socket = context.wrap_socket(svr_socket, server_side=True)

    print(f"\n[+] Server listening...")

    clients = []
    usernames = {}
    try:
        while True:
            cln_socket, c_addr = svr_socket.accept()
            with clients_lock:
                clients.append(cln_socket)
            print(f"\n[+] Client connected: {c_addr}")
            thread = threading.Thread(target=client_thread, args=(cln_socket, clients, usernames), daemon=True).start()
    finally:
        try:
            svr_socket.close()
        except:
            pass

if __name__ == '__main__':
    server_program()
