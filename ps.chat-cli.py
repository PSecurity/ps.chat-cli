#!/usr/bin/env python3
# ps.chat-cli.py - Cliente PS.Chat com descoberta automática (mDNS) e fallback manual

import sys
import socket
import webbrowser
import subprocess
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener

class PSChatListener(ServiceListener):
    def __init__(self):
        self.services = []

    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port
            self.services.append((ip, port))

def descobrir_servidor(timeout=2):
    zeroconf = Zeroconf()
    listener = PSChatListener()
    browser = ServiceBrowser(zeroconf, "_pschat._tcp.local.", listener)
    print("🔍 Procurando servidor PS.Chat na rede...")
    import time
    time.sleep(timeout)
    zeroconf.close()
    if listener.services:
        ip, port = listener.services[0]
        return f"http://{ip}:{port}"
    return None

def is_termux():
    return "/data/data/com.termux" in sys.prefix or "com.termux" in sys.executable

def abrir_url(url):
    if is_termux():
        try:
            subprocess.run(["termux-open-url", url], check=True)
            return True
        except:
            pass
    try:
        webbrowser.open(url)
        return True
    except:
        return False

def main():
    print("\n" + "=" * 40)
    print("👾 PS.CHAT – CLIENTE COM DESCOBERTA")
    print("=" * 40)

    url_base = descobrir_servidor()
    if url_base:
        print(f"✅ Servidor encontrado: {url_base}")
    else:
        print("⚠️ Descoberta automática falhou. Digite os dados manualmente.")
        ip = input("📡 IP do servidor: ").strip()
        if not ip:
            print("❌ IP não informado.")
            return
        url_base = f"http://{ip}:5000"

    token = input("🔑 Token da sala: ").strip()
    if not token:
        print("❌ Token não informado.")
        return

    url_sala = f"{url_base}/sala/{token}"
    print(f"\n🌐 Abrindo: {url_sala}")
    if abrir_url(url_sala):
        print("✅ Navegador aberto. Escolha um nome e converse.")
    else:
        print(f"❌ Não foi possível abrir o navegador. Acesse manualmente: {url_sala}")

    input("\n🔚 Pressione ENTER para sair...")

if __name__ == "__main__":
    main()