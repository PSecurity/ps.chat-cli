#!/usr/bin/env python3
"""
PS.Chat CLI — Cliente terminal para salas offline
Instala dependências automaticamente, se necessário.
"""

import sys, os, time, threading, subprocess
from datetime import datetime

def ensure_dependencies():
    missing = []
    try:
        import socketio
    except ImportError:
        missing.append("python-socketio[client]")
    try:
        from zeroconf import ServiceBrowser, Zeroconf, ServiceStateChange
    except ImportError:
        missing.append("zeroconf")
    if missing:
        print("🔧 Dependências faltando:", ", ".join(missing))
        ok = input("Deseja instalá-las agora? [S/n]: ").strip().lower()
        if ok in ('', 's', 'y', 'sim', 'yes'):
            for pkg in missing:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            print("✅ Instalação concluída. Reiniciando script...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            print("❌ Instalação recusada. Instale manualmente e tente novamente.")
            sys.exit(1)

ensure_dependencies()

import socketio
from zeroconf import ServiceBrowser, Zeroconf, ServiceStateChange

# Cores ANSI
R = "\033[0m"
B = "\033[1m"
P = "\033[38;5;135m"
N = "\033[38;5;177m"
D = "\033[38;5;96m"
G = "\033[38;5;48m"
E = "\033[38;5;203m"

def banner():
    print(P + B + r"""
  ╔══════════════════════════════╗
  ║  PS.CHAT CLI  ▸ PeekSecurity║
  ╚══════════════════════════════╝
""" + R)

def log(msg, level='info'):
    pre = {
        'info': D + "[●]" + R,
        'ok': G + "[✔]" + R,
        'warn': D + "[!]" + R,
        'err': E + "[✘]" + R,
    }.get(level, D + "[ ]" + R)
    print(pre + " " + msg)

class PSChatListener:
    def __init__(self):
        self.hosts = []
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            ip = info.parsed_addresses()[0] if info.parsed_addresses() else info.server
            self.hosts.append((ip, info.port))
    def update_service(self, *args): pass
    def remove_service(self, *args): pass

def discover(timeout=4):
    listener = PSChatListener()
    try:
        zc = Zeroconf()
        ServiceBrowser(zc, "_pschat._tcp.local.", listener)
        time.sleep(timeout)
        zc.close()
    except Exception as e:
        log(f"Falha na descoberta mDNS: {e}", "warn")
    return listener.hosts

def connect_with_retry(url, retries=2, timeout=15):
    sio = socketio.Client()
    for attempt in range(1, retries + 1):
        try:
            log(f"Tentativa {attempt}/{retries}...", "info")
            # Aumenta o timeout padrão do socketio
            sio.connect(url, wait_timeout=timeout)
            return sio
        except Exception as e:
            log(f"Falha na tentativa {attempt}: {e}", "err")
            if attempt < retries:
                time.sleep(2)
    return None

def main():
    banner()
    hosts = discover()
    if hosts:
        ip, port = hosts[0]
        log(f"Servidor encontrado: {ip}:{port}", "ok")
    else:
        log("Nenhum servidor via mDNS.", "warn")
        ip = input(N + "IP do servidor: " + R).strip()
        port = input(N + "Porta [5000]: " + R).strip() or "5000"
        port = int(port)

    url = f"http://{ip}:{port}"
    sio = connect_with_retry(url)
    if sio is None:
        log("Não foi possível conectar após várias tentativas.", "err")
        print(D + "Verifique:"
              "\n  - O servidor PS.Chat Admin está rodando?"
              "\n  - O IP e a porta estão corretos?"
              "\n  - Firewall/isolamento do Wi‑Fi não está bloqueando a porta 5000."
              "\n  - Tente acessar http://" + ip + ":" + str(port) + "/admin pelo navegador." + R)
        sys.exit(1)

    alive = True
    token = ""
    username = ""

    @sio.event
    def connect():
        nonlocal token, username
        log("Conectado!", "ok")
        token = input(N + "Token da sala: " + R).strip()
        username = input(N + "Seu nome: " + R).strip() or "Anônimo"
        sio.emit('entrar', {'token': token, 'username': username})

    @sio.on('mensagem')
    def on_msg(data):
        user = data.get('user', '')
        text = data.get('text', '')
        ts = data.get('timestamp', '')
        if user.startswith('⚡'):
            print(D + f"  {text}" + R)
        elif user == username:
            print(G + f"\n▸ {user}: {text}  {D}{ts}{R}")
        else:
            print(N + f"\n▸ {user}: {text}  {D}{ts}{R}")
        sys.stdout.write(P + ">>> " + R)
        sys.stdout.flush()

    @sio.on('erro')
    def on_err(data):
        log(data.get('mensagem', 'Erro'), "err")

    @sio.event
    def disconnect():
        nonlocal alive
        log("Conexão encerrada.", "err")
        alive = False

    def input_loop():
        nonlocal alive
        while alive:
            try:
                msg = input(P + ">>> " + R).strip()
            except:
                alive = False
                break
            if msg.lower() == '/sair':
                alive = False
                sio.disconnect()
                break
            elif msg:
                sio.emit('mensagem', {
                    'token': token,
                    'text': msg,
                    'timestamp': datetime.now().isoformat()
                })

    t = threading.Thread(target=input_loop, daemon=True)
    t.start()
    while alive:
        time.sleep(0.5)
    sio.disconnect()
    log("Chat encerrado.", "info")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + D + "Encerrado." + R)
