#!/usr/bin/env python3

import socket
import threading
import ssl
import json
import customtkinter as ctk

# ---------- GUI insert helpers ----------
def insert_text(text_widget, msg, tag=None):
    text_widget.configure(state="normal")
    if tag == "system":
        text_widget.insert("end", "\n")
        text_widget.insert("end", msg, tag)
        text_widget.insert("end", "\n\n")
    else:
        text_widget.insert("end", msg)
    text_widget.configure(state="disabled")
    text_widget.see("end")

def insert_user_msg(text_widget, username, msg, self_user=False):
    text_widget.configure(state="normal")
    tag_user = "username_self" if self_user else "username_other"
    text_widget.insert("end", f"{username} -> ", tag_user)
    text_widget.insert("end", msg + "\n", "message")
    text_widget.configure(state="disabled")
    text_widget.see("end")

def safe_insert(window, func, *args):
    window.after(0, func, *args)

# ---------- Network recv loop (NDJSON parsing) ----------
def recv_msg(cln_socket, window, text_widget, my_username):
    buffer = ""
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
                if mtype == "system":
                    txt = msg_obj.get("msg", "")
                    safe_insert(window, insert_text, text_widget, txt, "system")
                elif mtype == "users":
                    users = msg_obj.get("users", [])
                    txt = (("[ + ] Live users list: [ ") + (", ".join(users)) + (" ]"))
                    safe_insert(window, insert_text, text_widget, txt, "system")
                elif mtype == "chat":
                    user = msg_obj.get("user", "<unknown>")
                    msg = msg_obj.get("msg", "")
                    is_self = (user == my_username)
                    safe_insert(window, insert_user_msg, text_widget, user, msg, is_self)
                else:
                    safe_insert(window, insert_text, text_widget, str(msg_obj), None)
    except Exception:
        pass
    finally:
        try:
            cln_socket.close()
        except:
            pass
        safe_insert(window, insert_text, text_widget, "[ ! ] Disconnected from server", "system")

# ---------- Send helpers ----------
def send_json(sock, obj):
    try:
        sock.sendall((json.dumps(obj) + "\n").encode())
    except Exception:
        pass

def send_msg(cln_socket, username, text_widget, entry_widget):
    msg = entry_widget.get().rstrip()
    if not msg.strip():
        return
    payload = {"type": "chat", "user": username, "msg": msg}
    send_json(cln_socket, payload)
    entry_widget.delete(0, "end")

    text_widget.configure(state="normal")
    text_widget.insert("end", f"{username} -> ", "username_self")
    text_widget.insert("end", f"{msg}\n", "message")
    text_widget.configure(state="disabled")
    text_widget.see("end")

def list_users_request(cln_socket):
    send_json(cln_socket, {"type":"command", "cmd": "!users"})

def exit_request(cln_socket, window):
    try:
        send_json(cln_socket, {"type":"command", "cmd": "!exit"})
        cln_socket.close()
    except:
        pass
    window.quit()
    window.destroy()

# ---------- GUI setup ----------
def set_widgets(window, cln_socket, username):
    set_font = ("Arial", 16)
    # --- Textbox Frame + Textbox + Scrollbar ---
    text_frame_widget = ctk.CTkFrame(window)
    text_frame_widget.pack(fill="both", expand=True, padx=10, pady=10)

    text_widget = ctk.CTkTextbox(text_frame_widget, state="disabled", font=set_font)
    text_widget.tag_config("username_other", foreground="#00ff00")
    text_widget.tag_config("username_self", foreground="#1E90FF")
    text_widget.tag_config("system", foreground="#ff0000")
    text_widget.tag_config("message", foreground="#ffffff")
    text_widget.pack(side="left", fill="both", expand=True)

    scrollbar = ctk.CTkScrollbar(text_frame_widget, command=text_widget.yview)
    scrollbar.pack(side="right", fill="y")
    text_widget.configure(yscrollcommand=scrollbar.set)

    # --- Bottom Frame + Users Entry Textbox + <Return> Send Behaviour ---
    bottom_frame = ctk.CTkFrame(window)
    bottom_frame.pack(fill="x", padx=10, pady=(0, 10))

    entry_widget = ctk.CTkEntry(bottom_frame, font=set_font)
    entry_widget.pack(side="left", fill="x", expand=True, padx=(0, 10))

    entry_widget.bind("<Return>", lambda _: send_msg(cln_socket, username, text_widget, entry_widget))

    # --- Buttons Frame + Send Button ---
    buttons_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent", bg_color="transparent")
    buttons_frame.pack(side="right")

    send_button = ctk.CTkButton(
            buttons_frame,
            text="Send",
            command=lambda: send_msg(cln_socket, username, text_widget, entry_widget)
            )
    send_button.pack(side="left", padx=5)

    # --- Extra Botton Feature Buttons ---
    users_button = ctk.CTkButton(
            buttons_frame,
            text="Live Users",
            command=lambda: list_users_request(cln_socket)
            )
    users_button.pack(side="left", padx=5)

    exit_button = ctk.CTkButton(
            buttons_frame,
            text="Quit",
            fg_color="darkred",
            hover_color="red",
            command=lambda: exit_request(cln_socket, window)
            )
    exit_button.pack(side="left", padx=5)

    # --- Thread handler to receive messages ---
    thread = threading.Thread(
            target=recv_msg,
            args=(cln_socket, window, text_widget, username),
            daemon=True
            ).start()

def ask_username_gui(window):
    username_result = {"value": None}

    window.title("Login")
    window.geometry("350x160")
    window.resizable(False, False)

    frame = ctk.CTkFrame(window)
    frame.pack(expand=True, fill="both", padx=20, pady=20)

    label = ctk.CTkLabel(frame, text="Insert username:", font=("Arial", 16))
    label.pack(pady=(0, 10))

    entry = ctk.CTkEntry(frame, font=("Arial", 16))
    entry.pack(fill="x", pady=(0, 15))
    entry.focus()

    def submit():
        name = entry.get().strip()
        if not name:
            return
        username_result["value"] = name
        window.withdraw()   # 👈 CLAVE
        window.quit()

    button = ctk.CTkButton(frame, text="Connect", command=submit)
    button.pack()

    entry.bind("<Return>", lambda _: submit())

    def on_close():
        window.withdraw()
        window.quit()

    window.protocol("WM_DELETE_WINDOW", on_close)
    window.mainloop()

    for w in window.winfo_children():
        w.destroy()

    return username_result["value"]

def client_program():
    s_addr = ('localhost', 12345)
    host, port = s_addr
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cln_socket = context.wrap_socket(raw_socket, server_hostname="localhost")
    cln_socket.connect(s_addr)

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    window = ctk.CTk()

    username = ask_username_gui(window)
    if not username:
        return
    send_json(cln_socket, {"type": "introduce", "user": username})

    window.deiconify()
    window.title("Chat")
    window.geometry("900x600")

    set_widgets(window, cln_socket, username)

    window.mainloop()
    try:
        cln_socket.close()
    except:
        pass

if __name__ == '__main__':
    client_program()
