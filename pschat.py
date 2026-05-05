#!/usr/bin/env python3
"""
PS.Chat CLI v2.0 – E2EE de sala, fluxo de entrada corrigido, sem duplo entrar
"""

import sys, os, time, threading, subprocess, json, base64, hashlib, random, string
from datetime import datetime

# ---------- Dependências automáticas ----------
def ensure_dependencies():
    deps = {"socketio": "python-socketio[client]", "zeroconf": "zeroconf", "cryptography": "cryptography"}
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
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            print("✅ Instalação concluída. Reiniciando...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            sys.exit(1)

ensure_dependencies()

import socketio
from zeroconf import ServiceBrowser, Zeroconf
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

# ---------- Cores ----------
R = "\033[0m"
B = "\033[1m"
P = "\033[38;5;135m"
N = "\033[38;5;177m"
D = "\033[38;5;96m"
G = "\033[38;5;48m"
E = "\033[38;5;203m"
Y = "\033[38;5;228m"
M = "\033[38;5;141m"

CONFIG_DIR = os.path.expanduser("~/.pschat")
KEY_FILE = os.path.join(CONFIG_DIR, "keys.json")
HISTORY_DIR = os.path.join(CONFIG_DIR, "history")
DOWNLOAD_DIR = os.path.expanduser("~/Downloads/pschat")

def banner():
    print(P + r"""  ╔══════════════════════════════╗
  ║  PS.CHAT CLI  ▸ PeekSecurity║
  ╚══════════════════════════════╝
""" + R)

def log(msg, level='info'):
    pre = {'info': D+"[●]"+R, 'ok': G+"[✔]"+R, 'warn': D+"[!]"+R, 'err': E+"[✘]"+R}
    print(pre.get(level, D+"[ ]"+R) + " " + msg)

def fingerprint(pub_pem: str) -> str:
    raw = base64.b64decode(pub_pem)
    sha = hashlib.sha256(raw).digest()[:10]
    return base64.b32encode(sha).decode().rstrip("=").lower()[:16]

def generate_ephemeral_keys():
    priv = X25519PrivateKey.generate()
    sign_priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key(), sign_priv, sign_priv.public_key()

def load_or_create_keys(anonymous=False):
    if anonymous:
        return generate_ephemeral_keys()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            data = json.load(f)
            priv = serialization.load_pem_private_key(base64.b64decode(data['private']), password=None)
            pub = serialization.load_pem_public_key(base64.b64decode(data['public']))
            sign_priv = serialization.load_pem_private_key(base64.b64decode(data['sign_private']), password=None)
            sign_pub = serialization.load_pem_public_key(base64.b64decode(data['sign_public']))
            return priv, pub, sign_priv, sign_pub
    os.makedirs(CONFIG_DIR, exist_ok=True)
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    sign_priv = Ed25519PrivateKey.generate()
    sign_pub = sign_priv.public_key()
    data = {
        'private': base64.b64encode(priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())).decode(),
        'public': base64.b64encode(pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
        'sign_private': base64.b64encode(sign_priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())).decode(),
        'sign_public': base64.b64encode(sign_pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    }
    with open(KEY_FILE, 'w') as f: json.dump(data, f, indent=2)
    os.chmod(KEY_FILE, 0o600)
    return priv, pub, sign_priv, sign_pub

def encrypt_for_peer(plaintext: str, recipient_pub_pem: str, sender_priv, sign_priv) -> dict:
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

def decrypt_from_peer(encrypted: dict, sender_pub_pem: str, sender_sign_pub_pem: str, recipient_priv) -> str:
    sender_sign_pub = serialization.load_pem_public_key(base64.b64decode(sender_sign_pub_pem))
    ciphertext = base64.b64decode(encrypted['ciphertext'])
    signature = base64.b64decode(encrypted['signature'])
    sender_sign_pub.verify(signature, ciphertext)
    sender_pub = serialization.load_pem_public_key(base64.b64decode(sender_pub_pem))
    shared_key = recipient_priv.exchange(sender_pub)
    derived_key = hashlib.sha256(shared_key).digest()
    aesgcm = AESGCM(derived_key)
    nonce = base64.b64decode(encrypted['nonce'])
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def encrypt_room_message(plaintext: str, room_key: bytes, sign_priv) -> dict:
    aesgcm = AESGCM(room_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    signature = sign_priv.sign(ciphertext)
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'signature': base64.b64encode(signature).decode(),
        'room_encrypted': True
    }

def decrypt_room_message(encrypted: dict, room_key: bytes, sender_sign_pub_pem: str) -> str:
    sender_sign_pub = serialization.load_pem_public_key(base64.b64decode(sender_sign_pub_pem))
    ciphertext = base64.b64decode(encrypted['ciphertext'])
    signature = base64.b64decode(encrypted['signature'])
    sender_sign_pub.verify(signature, ciphertext)
    aesgcm = AESGCM(room_key)
    nonce = base64.b64decode(encrypted['nonce'])
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

class PSListener:
    def __init__(self): self.hosts = []
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            self.hosts.append((info.parsed_addresses()[0] if info.parsed_addresses() else info.server, info.port))
    def update_service(self, *args): pass
    def remove_service(self, *args): pass

def discover(timeout=4):
    listener = PSListener()
    try:
        zc = Zeroconf()
        ServiceBrowser(zc, "_pschat._tcp.local.", listener)
        time.sleep(timeout)
        zc.close()
    except: pass
    return listener.hosts

class ChatClient:
    def __init__(self):
        self.sio = socketio.Client()
        self.peers = {}
        self.room_key = None
        self.username = ""
        self.token = ""
        self.is_admin = False
        self.is_moderator = False
        self.saved_admin_pass = ""
        self.alive = True
        self.logging_active = False
        self.log_password = None
        self.log_filename = None
        self.log_messages = []
        self._register_handlers()

    def _register_handlers(self):
        sio = self.sio

        @sio.event
        def connect():
            pass

        @sio.on('admin_auth')
        def on_admin_auth(data):
            if data.get('status') == 'ok':
                self.is_admin = True
                print(Y + "👑 Admin autenticado." + R)

        @sio.on('promoted')
        def on_promoted(data):
            self.is_moderator = True
            log("Você foi promovido a moderador.", "ok")

        @sio.on('demoted')
        def on_demoted(data):
            self.is_moderator = False
            log("Você foi rebaixado de moderador.", "warn")

        @sio.on('erro')
        def on_err(data):
            msg = data.get('mensagem', 'Erro')
            # Agora a senha da sala é pedida antes; se ainda assim der erro, apenas informamos.
            log(msg, "err")
            if data.get('tipo') == 'senha_sala':
                # Damos uma nova chance
                nova_senha = input(N + "Senha da sala incorreta. Tente novamente: " + R).strip()
                if nova_senha:
                    self.sio.emit('entrar', {
                        'token': self.token, 'username': self.username,
                        'pubkey': self.pub_pem, 'sign_pubkey': self.sign_pub_pem,
                        'senha': nova_senha, 'senha_admin': self.saved_admin_pass
                    })

        @sio.on('chave_publica')
        def on_chave(data):
            if data['user'] == self.username:
                return
            self.peers[data['user']] = {'pubkey': data['pubkey'], 'sign_pubkey': data['sign_pubkey']}
            log(f"Chave de {data['user']} armazenada.", "ok")
            # Envia a chave de sala para o novo colega
            if self.room_key and data['user']:
                self._send_room_key_to(data['user'])

        @sio.on('room_key')
        def on_room_key(data):
            if data.get('user') == self.username:
                return
            if data['user'] not in self.peers:
                log("Recebi room_key de um usuário sem chave pública.", "err")
                return
            try:
                plain = decrypt_from_peer(
                    {'nonce': data['nonce'], 'ciphertext': data['ciphertext'], 'signature': data['signature']},
                    self.peers[data['user']]['pubkey'],
                    self.peers[data['user']]['sign_pubkey'],
                    self.priv
                )
                if not self.room_key or data.get('admin'):   # aceita renovação
                    self.room_key = base64.b64decode(plain)
                    log("Chave de sala recebida.", "ok")
            except Exception as e:
                log(f"Falha ao receber room key: {e}", "err")

        @sio.on('mensagem')
        def on_msg(data):
            if data.get('user') == self.username:
                return

            if data.get('type') == 'file':
                filename = data.get('filename', 'arquivo')
                filedata = base64.b64decode(data['filedata'])
                os.makedirs(DOWNLOAD_DIR, exist_ok=True)
                path = os.path.join(DOWNLOAD_DIR, filename)
                with open(path, 'wb') as f: f.write(filedata)
                print(G + f"\n📎 Arquivo recebido: {path}" + R)
                sys.stdout.write(P + ">>> " + R); sys.stdout.flush()
                return

            if data.get('room_encrypted'):
                if not self.room_key:
                    return   # silencia até ter a chave
                if data['user'] not in self.peers:
                    return
                try:
                    txt = decrypt_room_message(
                        {'nonce': data['nonce'], 'ciphertext': data['ciphertext'], 'signature': data['signature']},
                        self.room_key, self.peers[data['user']]['sign_pubkey']
                    )
                    admin_icon = Y+"👑 " if data.get('admin') else ""
                    mod_icon = M+"🛡️ " if data.get('moderator') else ""
                    prefix = "🔒 seguro"
                    if data.get('ephemeral'): prefix = "⚡ efêmero"
                    user_color = Y if data.get('admin') else (M if data.get('moderator') else N)
                    print(user_color + f"\n▸ {admin_icon}{mod_icon}{data['user']}{R} ({prefix}): {txt}" + R)
                    if self.logging_active: self.log_messages.append(f"{data['user']}: {txt}")
                except Exception as e:
                    log(f"Erro ao descriptografar: {e}", "err")
                sys.stdout.write(P + ">>> " + R); sys.stdout.flush()
                return

            if data.get('type') == 'system':
                print(D + f"\n  {data['text']}" + R)
            else:
                print(D + f"\n▸ {data.get('user','')}: {data.get('text','')}" + R)
            sys.stdout.write(P + ">>> " + R); sys.stdout.flush()

        @sio.on('sala_info')
        def on_sala(data):
            print(N + "\n👥 Participantes:" + R)
            for m in data.get('members', []):
                admin_icon = Y+"👑 " if m.get('admin') else ""
                mod_icon = M+"🛡️ " if m.get('moderator') else ""
                key_icon = "🔑" if m.get('has_pubkey') else "❌"
                print(f"  {admin_icon}{mod_icon}{key_icon} {m['username']}{R}")
            sys.stdout.write(P + ">>> " + R); sys.stdout.flush()

        @sio.on('kick')
        def on_kick(data):
            log(data.get('mensagem', 'Você foi removido da sala.'), "err")
            self.alive = False
            self.sio.disconnect()

        @sio.event
        def disconnect():
            self.alive = False
            log("Conexão encerrada.", "err")

    def _send_room_key_to(self, dest):
        if not self.room_key: return
        peer = self.peers.get(dest)
        if not peer: return
        enc = encrypt_for_peer(base64.b64encode(self.room_key).decode(), peer['pubkey'], self.priv, self.sign_priv)
        self.sio.emit('room_key', {
            'token': self.token, 'destinatario': dest, 'user': self.username,
            'nonce': enc['nonce'], 'ciphertext': enc['ciphertext'], 'signature': enc['signature'],
            'admin': self.is_admin
        })

    def generate_and_distribute_room_key(self):
        self.room_key = os.urandom(32)
        log("Nova chave de sala gerada.", "ok")
        for peer in self.peers:
            self._send_room_key_to(peer)

    def run(self):
        print(P + B + r"""  ╔══════════════════════════════╗
  ║  PS.CHAT CLI  ▸ PeekSecurity║
  ╚══════════════════════════════╝
""" + R)

        # ----- Credenciais -----
        anon = input(N + "Entrar como anônimo? [s/N]: " + R).strip().lower()
        anonymous = anon == 's'

        self.priv, self.pub, self.sign_priv, self.sign_pub = load_or_create_keys(anonymous)
        self.pub_pem = base64.b64encode(self.pub.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        self.sign_pub_pem = base64.b64encode(self.sign_pub.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

        if not anonymous:
            log("Chaves carregadas.", "ok")
            print(Y + f"🔑 Fingerprint: {fingerprint(self.pub_pem)}" + R)

        hosts = discover()
        if hosts:
            ip, port = hosts[0]
            log(f"Servidor: {ip}:{port}", "ok")
        else:
            ip = input(N + "IP do servidor: " + R).strip()
            port = int(input(N + "Porta [5000]: " + R).strip() or "5000")

        try:
            self.sio.connect(f"http://{ip}:{port}", wait_timeout=15)
        except Exception as e:
            log(f"Falha ao conectar: {e}", "err")
            sys.exit(1)

        # ----- Sequência de entrada (única) -----
        self.token = input(N + "Token da sala: " + R).strip()
        if anonymous:
            self.username = 'Anon_' + ''.join(random.choices(string.ascii_letters + string.digits, k=6))
            self.saved_admin_pass = ''
        else:
            self.saved_admin_pass = input(Y + "Senha de admin (Enter se não for admin): " + R).strip()
            self.username = input(N + "Seu nome: " + R).strip() or "Anônimo"

        # Solicita a senha da sala já na sequência
        senha_sala = input(N + "Senha da sala (Enter se não houver): " + R).strip()

        # Emite o único entrar
        self.sio.emit('entrar', {
            'token': self.token, 'username': self.username,
            'pubkey': self.pub_pem, 'sign_pubkey': self.sign_pub_pem,
            'senha': senha_sala, 'senha_admin': self.saved_admin_pass
        })

        # Se o admin entrou e não há chave de sala, gera após um curto período
        if self.is_admin:
            # Pequena espera para acumular peers
            time.sleep(1)
            if not self.room_key:
                self.generate_and_distribute_room_key()

        # ----- Thread de input -----
        def input_loop():
            while self.alive:
                try:
                    raw = input(P + ">>> " + R).strip()
                except (EOFError, KeyboardInterrupt):
                    self.alive = False
                    break
                if not raw: continue
                if raw.lower() == '/sair':
                    self.alive = False
                    self.sio.disconnect()
                    break
                elif raw.lower() == '/sala':
                    self.sio.emit('sala_info', {'token': self.token})
                elif raw.lower() == '/clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    print(P + B + r"""  ╔══════════════════════════════╗
  ║  PS.CHAT CLI  ▸ PeekSecurity║
  ╚══════════════════════════════╝
""" + R)
                elif raw.lower() == '/help':
                    print(N + """
╔══════════════════════════════════════════╗
║ Comandos:                               ║
║  /sala        - Listar participantes    ║
║  /sumir msg   - Mensagem efêmera        ║
║  /send arq    - Enviar arquivo          ║
║  /log on <senha> - Ativar histórico     ║
║  /log off     - Desativar histórico     ║
║  /log show    - Mostrar log descript.   ║
║  /fingerprint - Ver seu fingerprint     ║
║  /kick <user> - Expulsar (admin/mod)    ║
║  /clear       - Limpar a tela           ║
║  /help        - Esta ajuda              ║
║  /sair        - Sair da sala            ║
╚══════════════════════════════════════════╝
""" + R)
                elif raw.lower().startswith('/sumir '):
                    msg = raw[7:].strip()
                    if msg and self.room_key:
                        enc = encrypt_room_message(msg, self.room_key, self.sign_priv)
                        enc['ephemeral'] = True
                        self.sio.emit('mensagem', {'token': self.token, 'user': self.username, **enc})
                        print(M + f"\n▸ Você (⚡ efêmero): {msg}" + R)
                        sys.stdout.write(P + ">>> " + R); sys.stdout.flush()
                elif raw.lower().startswith('/send '):
                    filepath = raw[6:].strip()
                    if not os.path.exists(filepath): log("Arquivo não encontrado.", "err")
                    elif os.path.getsize(filepath) > 5*1024*1024: log("Arquivo muito grande.", "err")
                    else:
                        with open(filepath, 'rb') as f: b64 = base64.b64encode(f.read()).decode()
                        self.sio.emit('mensagem', {'token': self.token, 'type': 'file', 'filename': os.path.basename(filepath), 'filedata': b64, 'user': self.username})
                        log("Arquivo enviado.", "ok")
                elif raw.lower().startswith('/kick '):
                    target = raw[6:].strip()
                    if target and (self.is_admin or self.is_moderator):
                        self.sio.emit('kick_user', {'token': self.token, 'username': target})
                    else:
                        log("Sem permissão para kick.", "err")
                elif raw.lower().startswith('/log '):
                    parts = raw.split()
                    if len(parts) < 2: continue
                    subcmd = parts[1].lower()
                    if subcmd == 'on' and len(parts) >= 3:
                        self.log_password = parts[2]
                        self.logging_active = True
                        self.log_messages = []
                        os.makedirs(HISTORY_DIR, exist_ok=True)
                        self.log_filename = os.path.join(HISTORY_DIR, f"{self.token}.log.enc")
                        log("Histórico ativado.", "ok")
                    elif subcmd == 'off':
                        if self.logging_active:
                            content = "\n".join(self.log_messages[-200:])
                            key = hashlib.sha256(self.log_password.encode()).digest()
                            aeslog = AESGCM(key)
                            nonce = os.urandom(12)
                            ctext = aeslog.encrypt(nonce, content.encode(), None)
                            with open(self.log_filename, 'w') as f: f.write(json.dumps({
                                'nonce': base64.b64encode(nonce).decode(),
                                'ciphertext': base64.b64encode(ctext).decode()
                            }))
                            log("Histórico salvo.", "ok")
                        self.logging_active = False
                        self.log_password = None
                    elif subcmd == 'show':
                        if not self.log_filename or not os.path.exists(self.log_filename):
                            log("Nenhum log.", "warn")
                        else:
                            pwd = input("Senha do log: ").strip()
                            with open(self.log_filename) as f: d = json.load(f)
                            key = hashlib.sha256(pwd.encode()).digest()
                            aeslog = AESGCM(key)
                            try:
                                plain = aeslog.decrypt(base64.b64decode(d['nonce']), base64.b64decode(d['ciphertext']), None)
                                print(plain.decode())
                            except Exception:
                                log("Senha ou arquivo inválido.", "err")
                elif raw.lower() == '/fingerprint':
                    print(Y + f"🔑 Seu fingerprint: {fingerprint(self.pub_pem)}" + R)
                else:
                    if self.room_key:
                        enc = encrypt_room_message(raw, self.room_key, self.sign_priv)
                        self.sio.emit('mensagem', {'token': self.token, 'user': self.username, **enc})
                        admin_icon = Y+"👑 " if self.is_admin else ""
                        mod_icon = M+"🛡️ " if self.is_moderator else ""
                        user_color = Y if self.is_admin else (M if self.is_moderator else N)
                        print(user_color + f"\n▸ {admin_icon}{mod_icon}{self.username}{R} (🔒 seguro): {raw}" + R)
                        sys.stdout.write(P + ">>> " + R); sys.stdout.flush()
                    else:
                        log("Chave de sala ainda não disponível.", "warn")

        threading.Thread(target=input_loop, daemon=True).start()
        while self.alive:
            time.sleep(0.5)
        self.sio.disconnect()
        log("Chat encerrado.", "info")

if __name__ == '__main__':
    client = ChatClient()
    try:
        client.run()
    except KeyboardInterrupt:
        print("\n" + D + "Encerrado." + R)
        os._exit(0)
