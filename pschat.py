#!/usr/bin/env python3
"""
PS.Chat CLI v2.0 – E2EE + efêmeras + log + arquivos + anônimo + resolução de chaves
"""

import sys, os, time, threading, subprocess, json, base64, hashlib, random, string
from datetime import datetime
from pathlib import Path

# ========== Dependências automáticas ==========
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature, InvalidTag

# Cores
R = "\033[0m"
B = "\033[1m"
P = "\033[38;5;135m"
N = "\033[38;5;177m"
D = "\033[38;5;96m"
G = "\033[38;5;48m"
E = "\033[38;5;203m"

CONFIG_DIR = os.path.expanduser("~/.pschat")
KEY_FILE = os.path.join(CONFIG_DIR, "keys.json")
HISTORY_DIR = os.path.join(CONFIG_DIR, "history")
DOWNLOAD_DIR = os.path.expanduser("~/Downloads/pschat")

def banner():
    print(P + B + r"""
  ╔══════════════════════════════╗
  ║  PS.CHAT CLI  ▸ PeekSecurity║
  ╚══════════════════════════════╝
""" + R)

def log(msg, level='info'):
    pre = {'info': D+"[●]"+R, 'ok': G+"[✔]"+R, 'warn': D+"[!]"+R, 'err': E+"[✘]"+R}
    print(pre.get(level, D+"[ ]"+R) + " " + msg)

# ========== Chaves ==========
def generate_ephemeral_keys():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    sign_priv = Ed25519PrivateKey.generate()
    sign_pub = sign_priv.public_key()
    return priv, pub, sign_priv, sign_pub

def load_or_create_keys(anonymous=False):
    if anonymous:
        return generate_ephemeral_keys()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            data = json.load(f)
            priv = serialization.load_pem_private_key(base64.b64decode(data['private']), password=None)
            pub  = serialization.load_pem_public_key(base64.b64decode(data['public']))
            sign_priv = serialization.load_pem_private_key(base64.b64decode(data['sign_private']), password=None)
            sign_pub  = serialization.load_pem_public_key(base64.b64decode(data['sign_public']))
            return priv, pub, sign_priv, sign_pub
    os.makedirs(CONFIG_DIR, exist_ok=True)
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    sign_priv = Ed25519PrivateKey.generate()
    sign_pub  = sign_priv.public_key()
    data = {
        'private': base64.b64encode(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode(),
        'public': base64.b64encode(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode(),
        'sign_private': base64.b64encode(sign_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode(),
        'sign_public': base64.b64encode(sign_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode()
    }
    with open(KEY_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    os.chmod(KEY_FILE, 0o600)
    return priv, pub, sign_priv, sign_pub

# ========== Criptografia ==========
def encrypt_message(plaintext, recipient_pub_pem, sender_priv, sign_priv):
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

def decrypt_message(encrypted, sender_pub_pem, sender_sign_pub_pem, recipient_priv):
    sender_sign_pub = serialization.load_pem_public_key(base64.b64decode(sender_sign_pub_pem))
    ciphertext = base64.b64decode(encrypted['ciphertext'])
    signature = base64.b64decode(encrypted['signature'])
    try:
        sender_sign_pub.verify(signature, ciphertext)
    except InvalidSignature:
        raise ValueError("Assinatura inválida!")
    sender_pub = serialization.load_pem_public_key(base64.b64decode(sender_pub_pem))
    shared_key = recipient_priv.exchange(sender_pub)
    derived_key = hashlib.sha256(shared_key).digest()
    aesgcm = AESGCM(derived_key)
    nonce = base64.b64decode(encrypted['nonce'])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# ========== Histórico local criptografado ==========
def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_file(data, password):
    key, salt = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode()

def decrypt_file(encrypted_str, password):
    raw = base64.b64decode(encrypted_str)
    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]
    key, _ = derive_key(password, salt)
    aesgcm = AESGCM(key)
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

# ========== Principal ==========
def main():
    banner()

    # Modo anônimo?
    anon = input(N + "Entrar como anônimo? [s/N]: " + R).strip().lower()
    anonymous = anon == 's'

    priv, pub, sign_priv, sign_pub = load_or_create_keys(anonymous)
    pub_pem = base64.b64encode(pub.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    sign_pub_pem = base64.b64encode(sign_pub.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    if anonymous:
        username = 'Anon_' + ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        log(f"Identidade anônima: {username}", "ok")
    else:
        log("Chaves carregadas.", "ok")
        username = None

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
    peers = {}
    token = ""
    if not anonymous:
        username = ""

    logging_active = False
    log_password = None
    log_filename = None
    log_messages = []

    @sio.event
    def connect():
        nonlocal token, username
        log("Conectado!", "ok")
        token = input(N + "Token da sala: " + R).strip()
        if not anonymous:
            username = input(N + "Seu nome: " + R).strip() or "Anônimo"
        sio.emit('entrar', {
            'token': token,
            'username': username,
            'pubkey': pub_pem,
            'sign_pubkey': sign_pub_pem,
            'senha': ''
        })

    @sio.on('erro')
    def on_err(data):
        msg = data.get('mensagem', 'Erro')
        if 'Senha' in msg:
            s = input(N + "Senha da sala: " + R).strip()
            sio.emit('entrar', {
                'token': token,
                'username': username,
                'pubkey': pub_pem,
                'sign_pubkey': sign_pub_pem,
                'senha': s
            })
        else:
            log(msg, "err")

    @sio.on('chave_publica')
    def on_chave(data):
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
        if data.get('type') == 'file':
            filename = data.get('filename', 'arquivo')
            filedata = base64.b64decode(data['filedata'])
            os.makedirs(DOWNLOAD_DIR, exist_ok=True)
            path = os.path.join(DOWNLOAD_DIR, filename)
            with open(path, 'wb') as f:
                f.write(filedata)
            print(G + f"\n📎 Arquivo recebido: {path}" + R)
            sys.stdout.write(P + ">>> " + R)
            sys.stdout.flush()
            return

        if 'ciphertext' in data and 'signature' in data:
            peer = peers.get(data['user'])
            if not peer:
                sio.emit('solicitar_chave', {'token': token, 'username': data['user']})
                log(f"Chave de {data['user']} indisponível. Solicitei atualização.", "warn")
                return
            try:
                txt = decrypt_message(data, peer['pubkey'], peer['sign_pubkey'], priv)
                prefix = "🔒 seguro"
                if data.get('ephemeral'):
                    prefix = "⚡ efêmero"
                print(N + f"\n▸ {data['user']} ({prefix}): {txt}" + R)
                if logging_active:
                    log_messages.append(f"{data['user']}: {txt}")
            except (InvalidSignature, InvalidTag, ValueError, Exception) as e:
                # Provavelmente a chave está desatualizada, solicitar nova
                sio.emit('solicitar_chave', {'token': token, 'username': data['user']})
                log(f"Falha ao descriptografar mensagem de {data['user']} – solicitando chave atualizada.", "err")
                return
        elif data.get('type') == 'system':
            print(D + f"\n  {data['text']}" + R)
        else:
            txt = data.get('text', '')
            print(D + f"\n▸ {data['user']}: {txt}" + R)
            if logging_active:
                log_messages.append(f"{data['user']}: {txt}")
        sys.stdout.write(P + ">>> " + R)
        sys.stdout.flush()

    @sio.on('sala_info')
    def on_sala(data):
        members = data.get('members', [])
        print(N + "\n👥 Participantes:" + R)
        for m in members:
            key_status = "🔑" if m.get('has_pubkey') else "❌"
            print(f"  {key_status} {m['username']}")
        sys.stdout.write(P + ">>> " + R)
        sys.stdout.flush()

    @sio.event
    def disconnect():
        nonlocal alive
        log("Conexão encerrada.", "err")
        alive = False

    try:
        sio.connect(url, wait_timeout=15)
    except Exception as e:
        log(f"Falha ao conectar: {e}", "err")
        sys.exit(1)

    def input_loop():
        nonlocal alive, logging_active, log_password, log_filename, log_messages
        while alive:
            try:
                raw = input(P + ">>> " + R).strip()
            except (EOFError, KeyboardInterrupt):
                alive = False
                break
            if not raw:
                continue
            if raw.lower() == '/sair':
                alive = False
                sio.disconnect()
                break
            elif raw.lower() == '/sala':
                if token:
                    sio.emit('sala_info', {'token': token})
                else:
                    log("Você ainda não entrou em uma sala.", "warn")
            elif raw.lower() == '/clear':
                os.system('clear' if os.name != 'nt' else 'cls')
                banner()
            elif raw.lower() == '/help':
                print(N + """
╔══════════════════════════════════════════╗
║ Comandos:                               ║
║  /sala       - Listar participantes     ║
║  /sumir msg  - Mensagem efêmera         ║
║  /send arq   - Enviar arquivo           ║
║  /log on <senha> - Ativar histórico     ║
║  /log off    - Desativar histórico      ║
║  /log show   - Mostrar últimas linhas   ║
║  /clear      - Limpar a tela            ║
║  /help       - Esta ajuda               ║
║  /sair       - Sair da sala             ║
╚══════════════════════════════════════════╝
""" + R)
                sys.stdout.write(P + ">>> " + R)
                sys.stdout.flush()
            elif raw.lower().startswith('/sumir '):
                msg = raw[7:].strip()
                if msg and token:
                    if peers:
                        for peer, info in peers.items():
                            enc = encrypt_message(msg, info['pubkey'], priv, sign_priv)
                            enc['ephemeral'] = True
                            sio.emit('mensagem', {
                                'token': token,
                                'user': username,
                                **enc
                            })
                    else:
                        sio.emit('mensagem', {
                            'token': token,
                            'text': msg,
                            'timestamp': datetime.now().isoformat(),
                            'ephemeral': True
                        })
            elif raw.lower().startswith('/send '):
                filepath = raw[6:].strip()
                if not os.path.exists(filepath):
                    log("Arquivo não encontrado.", "err")
                    continue
                if os.path.getsize(filepath) > 5 * 1024 * 1024:
                    log("Arquivo muito grande (máx 5 MB).", "err")
                    continue
                with open(filepath, 'rb') as f:
                    b64data = base64.b64encode(f.read()).decode()
                filename = os.path.basename(filepath)
                sio.emit('mensagem', {
                    'token': token,
                    'type': 'file',
                    'filename': filename,
                    'filedata': b64data,
                    'user': username
                })
                log("Arquivo enviado.", "ok")
            elif raw.lower().startswith('/log '):
                parts = raw.split()
                if len(parts) < 2:
                    continue
                subcmd = parts[1].lower()
                if subcmd == 'on':
                    if len(parts) < 3:
                        log("Uso: /log on <senha>", "err")
                    else:
                        log_password = parts[2]
                        logging_active = True
                        log_messages = []
                        log_filename = os.path.join(HISTORY_DIR, f"{token}.log.enc")
                        os.makedirs(HISTORY_DIR, exist_ok=True)
                        log("Histórico criptografado ativado.", "ok")
                elif subcmd == 'off':
                    if logging_active and log_messages:
                        content = "\n".join(log_messages[-200:])
                        enc_content = encrypt_file(content, log_password)
                        with open(log_filename, 'w') as f:
                            f.write(enc_content)
                        log("Histórico salvo e desativado.", "ok")
                    logging_active = False
                    log_password = None
                elif subcmd == 'show':
                    if not log_filename or not os.path.exists(log_filename):
                        log("Nenhum log encontrado.", "warn")
                    else:
                        pwd = input("Senha do log: ").strip()
                        with open(log_filename) as f:
                            enc = f.read()
                        try:
                            dec = decrypt_file(enc, pwd)
                            print(dec)
                        except Exception:
                            log("Senha incorreta ou arquivo corrompido.", "err")
                else:
                    log("Comando /log inválido. Use on/off/show.", "warn")
            else:
                if token:
                    if peers:
                        for peer, info in peers.items():
                            enc = encrypt_message(raw, info['pubkey'], priv, sign_priv)
                            sio.emit('mensagem', {
                                'token': token,
                                'user': username,
                                **enc
                            })
                    else:
                        sio.emit('mensagem', {
                            'token': token,
                            'text': raw,
                            'timestamp': datetime.now().isoformat()
                        })

    threading.Thread(target=input_loop, daemon=True).start()
    while alive:
        time.sleep(0.5)
    if logging_active and log_messages:
        content = "\n".join(log_messages[-200:])
        enc_content = encrypt_file(content, log_password)
        with open(log_filename, 'w') as f:
            f.write(enc_content)
        log("Histórico salvo.", "ok")
    sio.disconnect()
    log("Chat encerrado.", "info")
    os._exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + D + "Encerrado." + R)
        os._exit(0)
