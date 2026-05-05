#!/usr/bin/env python3
"""
PS.Chat CLI — Cliente terminal seguro com E2EE + Assinatura
Comandos: /sala, /help, /clear, /sair
"""

import sys, os, time, threading, subprocess, json, base64, hashlib
from datetime import datetime

# ========== Instalação automática de dependências ==========
def ensure_dependencies():
    deps = {
        "socketio": "python-socketio[client]",
        "zeroconf": "zeroconf",
        "cryptography": "cryptography"
    }
    missing = []
    for mod, pkg in deps.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("🔧 Dependências faltando:", ", ".join(missing))
        ok = input("Instalar agora? [S/n]: ").strip().lower()
        if ok in ('', 's', 'sim', 'yes'):
            for pkg in missing:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                except subprocess.CalledProcessError:
                    print(f"Falha ao instalar {pkg}. Tente manualmente.")
                    sys.exit(1)
            print("✅ Instalação concluída. Reiniciando...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            print("❌ Instale manualmente e tente novamente.")
            sys.exit(1)

ensure_dependencies()

import socketio
from zeroconf import ServiceBrowser, Zeroconf, ServiceStateChange
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# Cores ANSI
R = "\033[0m"
B = "\033[1m"
P = "\033[38;5;135m"
N = "\033[38;5;177m"
D = "\033[38;5;96m"
G = "\033[38;5;48m"
E = "\033[38;5;203m"

CONFIG_DIR = os.path.expanduser("~/.pschat")
KEY_FILE = os.path.join(CONFIG_DIR, "keys.json")

def banner():
    print(P + B + r"""
  ╔══════════════════════════════╗
  ║  PS.CHAT CLI  ▸ PeekSecurity║
  ╚══════════════════════════════╝
""" + R)

def log(msg, level='info'):
    pre = {'info': D+"[●]"+R, 'ok': G+"[✔]"+R, 'warn': D+"[!]"+R, 'err': E+"[✘]"+R}
    print(pre.get(level, D+"[ ]"+R) + " " + msg)

# ========== Gerenciamento de chaves ==========
def load_or_create_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            data = json.load(f)
            priv = serialization.load_pem_private_key(base64.b64decode(data['private']), password=None)
            pub  = serialization.load_pem_public_key(base64.b64decode(data['public']))
            sign_priv = serialization.load_pem_private_key(base64.b64decode(data['sign_private']), password=None)
            sign_pub  = serialization.load_pem_public_key(base64.b64decode(data['sign_public']))
            return priv, pub, sign_priv, sign_pub
    os.makedirs(CONFIG_DIR, exist_ok=True)
    # Par de criptografia (X25519)
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    # Par de assinatura (Ed25519)
    sign_priv = Ed25519PrivateKey.generate()
    sign_pub  = sign_priv.public_key()
    data = {
        'private': base64.b64encode(
            priv.private_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PrivateFormat.PKCS8,
                               encryption_algorithm=serialization.NoEncryption())
        ).decode(),
        'public': base64.b64encode(
            pub.public_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode(),
        'sign_private': base64.b64encode(
            sign_priv.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption())
        ).decode(),
        'sign_public': base64.b64encode(
            sign_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode()
    }
    with open(KEY_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    try: os.chmod(KEY_FILE, 0o600)
    except: pass
    return priv, pub, sign_priv, sign_pub

# ========== Criptografia ==========
def encrypt_message(plaintext: str, recipient_pub_pem: str, sender_priv: X25519PrivateKey, sign_priv: Ed25519PrivateKey) -> dict:
    recipient_pub = serialization.load_pem_public_key(base64.b64decode(recipient_pub_pem))
    shared_key = sender_priv.exchange(recipient_pub)
    derived_key = hashlib.sha256(shared_key).digest()
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    signature = sign_priv.sign(ciphertext)
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'signature': base64.b64encode(signature).decode(),
        'recipient_pub': recipient_pub_pem
    }

def decrypt_message(encrypted: dict, sender_pub_pem: str, sender_sign_pub_pem: str, recipient_priv: X25519PrivateKey) -> str:
    sender_sign_pub = serialization.load_pem_public_key(base64.b64decode(sender_sign_pub_pem))
    ciphertext = base64.b64decode(encrypted['ciphertext'])
    signature = base64.b64decode(encrypted['signature'])
    try:
        sender_sign_pub.verify(signature, ciphertext)
    except InvalidSignature:
        raise ValueError("Assinatura inválida! Mensagem pode ser forjada.")

    sender_pub = serialization.load_pem_public_key(base64.b64decode(sender_pub_pem))
    shared_key = recipient_priv.exchange(sender_pub)
    derived_key = hashlib.sha256(shared_key).digest()
    aesgcm = AESGCM(derived_key)
    nonce = base64.b64decode(encrypted['nonce'])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# ========== Descoberta mDNS ==========
class PSChatListener:
    def __init__(self): self.hosts = []
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
        log(f"Falha mDNS: {e}", "warn")
    return listener.hosts

# ========== Função principal ==========
def main():
    banner()
    priv, pub, sign_priv, sign_pub = load_or_create_keys()
    pub_pem = base64.b64encode(
        pub.public_bytes(encoding=serialization.Encoding.PEM,
                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    sign_pub_pem = base64.b64encode(
        sign_pub.public_bytes(encoding=serialization.Encoding.PEM,
                              format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    log("Chaves carregadas.", "ok")

    hosts = discover()
    if hosts:
        ip, port = hosts[0]
        log(f"Servidor: {ip}:{port}", "ok")
    else:
        log("Servidor não encontrado via mDNS.", "warn")
        ip = input(N + "IP do servidor: " + R).strip()
        port = int(input(N + "Porta [5000]: " + R).strip() or "5000")

    url = f"http://{ip}:{port}"
    sio = socketio.Client()
    alive = True
    peers = {}          # username -> {pubkey, sign_pubkey}
    token = ""
    username = ""

    # ========== Handlers de eventos ==========
    @sio.event
    def connect():
        nonlocal token, username
        log("Conectado!", "ok")
        token = input(N + "Token da sala: " + R).strip()
        username = input(N + "Seu nome: " + R).strip() or "Anônimo"
        # Envia chaves públicas ao entrar
        sio.emit('entrar', {
            'token': token,
            'username': username,
            'pubkey': pub_pem,
            'sign_pubkey': sign_pub_pem
        })

    @sio.on('chave_publica')
    def on_chave_publica(data):
        if data.get('user') == username:
            return
        peers[data['user']] = {
            'pubkey': data['pubkey'],
            'sign_pubkey': data['sign_pubkey']
        }
        log(f"Chave de {data['user']} armazenada.", "ok")

    @sio.on('mensagem')
    def on_msg(data):
        if data.get('user') == username:
            return
        # Mensagens criptografadas
        if 'ciphertext' in data and 'signature' in data:
            peer_info = peers.get(data['user'])
            if not peer_info:
                log(f"Chave de {data['user']} não disponível. Mensagem ignorada.", "err")
                return
            try:
                plain = decrypt_message(data, peer_info['pubkey'], peer_info['sign_pubkey'], priv)
                print(N + f"\n▸ {data['user']} (🔒 seguro): {plain}" + R)
            except ValueError as e:
                log(f"Falha de segurança: {e}", "err")
                return
        # Mensagens de sistema ou texto plano
        elif data.get('type') == 'system':
            print(D + f"\n  {data['text']}" + R)
        else:
            print(D + f"\n▸ {data['user']}: {data.get('text','')}" + R)
        sys.stdout.write(P + ">>> " + R)
        sys.stdout.flush()

    @sio.on('sala_info')
    def on_sala_info(data):
        members = data.get('members', [])
        print(N + "\n👥 Participantes:" + R)
        for m in members:
            key_status = "🔑" if m.get('has_pubkey') else "❌"
            print(f"  {key_status} {m['username']}")
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

    # Conectar
    try:
        sio.connect(url, wait_timeout=15)
    except Exception as e:
        log(f"Falha ao conectar: {e}", "err")
        sys.exit(1)

    # ========== Thread de input ==========
    def input_loop():
        nonlocal alive
        while alive:
            try:
                msg = input(P + ">>> " + R).strip()
            except (EOFError, KeyboardInterrupt):
                alive = False
                break

            if not msg:
                continue
            # Comandos especiais
            if msg.lower() == '/sair':
                alive = False
                sio.disconnect()
                break
            elif msg.lower() == '/sala':
                if token:
                    sio.emit('sala_info', {'token': token})
                else:
                    log("Você ainda não entrou em uma sala.", "warn")
            elif msg.lower() == '/clear':
                os.system('clear' if os.name != 'nt' else 'cls')
                banner()
            elif msg.lower() == '/help':
                print(N + """
╔══════════════════════════════════════╗
║ Comandos:                           ║
║  /sala   - Listar participantes     ║
║  /clear  - Limpar a tela            ║
║  /help   - Mostrar esta ajuda       ║
║  /sair   - Sair da sala             ║
║                                     ║
║ Digite a mensagem e Enter para      ║
║ enviar criptografada (se houver     ║
║ chave) ou em texto plano.           ║
╚══════════════════════════════════════╝
""" + R)
                sys.stdout.write(P + ">>> " + R)
                sys.stdout.flush()
            elif msg and token:
                # Envia mensagem (criptografada se possível)
                if peers:
                    for peer, info in peers.items():
                        enc = encrypt_message(msg, info['pubkey'], priv, sign_priv)
                        sio.emit('mensagem', {
                            'token': token,
                            'user': username,
                            **enc
                        })
                else:
                    # Fallback texto plano
                    sio.emit('mensagem', {
                        'token': token,
                        'text': msg,
                        'timestamp': datetime.now().isoformat()
                    })

    threading.Thread(target=input_loop, daemon=True).start()
    while alive:
        time.sleep(0.5)
    sio.disconnect()
    log("Chat encerrado.", "info")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + D + "Encerrado." + R)
