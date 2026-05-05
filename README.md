# 💻 PS.Chat CLI

[![Version](https://img.shields.io/badge/version-2.2.6-blue.svg)](https://github.com/PSecurity/ps.chat-cli/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-yellow.svg)](https://python.org)
[![Termux](https://img.shields.io/badge/Termux-Compatible-red.svg)](https://termux.com)

**Cliente terminal seguro para o PS.Chat** – comunicação offline, criptografada ponta a ponta (E2EE), com comandos de moderação e anonimato.

> ⚡ **Novo na v2.2.6:** E2EE com chave de sala, DM criptografada, verificação de identidade, comandos de moderação, histórico local criptografado e saída limpa sem travar o terminal.

---

## ✨ Funcionalidades

- 🔒 **E2EE robusta** – X25519 + AES‑GCM + Ed25519, mesma segurança do cliente anterior
- 👑 **Autenticação de admin** – use a mesma senha do painel para obter privilégios
- 🛡️ **Moderação** – `/promote`, `/demote`, `/kick`, `/mute`, `/unmute`, `/ban`
- 📩 **Mensagens diretas (DM)** – criptografadas individualmente, invisíveis para outros
- ⚡ **Mensagens efêmeras** – `/sumir` – não são salvas no histórico
- 📎 **Envio de arquivos** – `/send` – até 5 MB
- 📜 **Histórico local criptografado** – `/log on/off/show` + `/export`
- 🔍 **Verificação de identidade** – `/verify` com desafio criptográfico
- 🎯 **Subcanais** – `/filter` – filtre mensagens por tópico
- 🤫 **Modo anônimo** – gere chaves temporárias e nome aleatório
- 📟 **Autocompletar** – pressione Tab para completar comandos
- 🌐 **Descoberta automática** – mDNS encontra o servidor na rede local

---

## 🚀 Instalação

### Pré‑requisitos

| Ambiente | Requisitos |
|----------|------------|
| **Termux (Android)** | `pkg update && pkg install python python-cryptography` |
| **Linux/macOS** | Python 3.9+ |
| **Windows** | WSL ou Python direto |

### 1. Clone o repositório

```bash
git clone https://github.com/PSecurity/ps.chat-cli
cd ps.chat-cli
```

### 2. Instale as dependências

```bash
pip install -r requirements.txt
```

**Dependências:**
```
· python-socketio[client]>=5.11,<6.0
· zeroconf>=0.131,<1.0
· cryptography>=41,<42
```

Opcional, mas recomendado: `websocket-client>=1.6` para trocar polling por WebSocket real.

> 💡 **No Termux, instale `cryptography` primeiro com `pkg install python-cryptography`** para evitar erros de compilação.

### 3. Execute o cliente

```bash
python3 pschat.py
```

Na primeira execução, as dependências ausentes serão instaladas automaticamente.

---

## 📖 Como usar

### Fluxo básico

1. **Inicie o servidor** (veja o repositório `ps.chat‑admin`).
2. **Execute o cliente** no terminal.
3. Responda `n` para "Entrar como anônimo?" ou `s` para modo anônimo.
4. Informe o **IP do servidor** e a porta (padrão: `5000`).
5. Informe o **token da sala** (fornecido pelo administrador).
6. Se você for o administrador, informe a **senha do painel admin** quando solicitado (Enter se não for admin).
7. Digite seu **nome** (ou Enter para "Anônimo").
8. Se a sala tiver senha, informe‑a.
9. Comece a conversar! Suas mensagens já estão protegidas.

### Exemplo de sessão

```
╔══════════════════════════════╗
║  PS.CHAT CLI  ▸ PeekSecurity║
╚══════════════════════════════╝

Entrar como anônimo? [s/N]: n
🔑 Fingerprint: 54hkabtx5465fcgx
IP do servidor: 192.168.1.11
Porta [5000]: 5000
Token da sala: a1b2c3d4
Senha de admin (Enter se não for admin): PeekAdmin2025
Seu nome: Peek
Senha da sala (Enter se não houver): 123

>>> Olá, pessoal!
[17:00] 👑 Peek (🔒 seguro): Olá, pessoal!
```

---

## 📟 Todos os comandos

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `/sala` | Lista participantes com ícones 👑 🛡️ 🔇 🔑 | `/sala` |
| `/help` | Mostra todos os comandos disponíveis | `/help` |
| `/fingerprint` | Exibe seu fingerprint criptográfico | `/fingerprint` |
| `/sumir mensagem` | Mensagem efêmera (não salva no histórico) | `/sumir Reunião às 15h` |
| `/dm Usuário mensagem` | Mensagem direta criptografada | `/dm Lux como você está?` |
| `/send arquivo.txt` | Envia um arquivo (máx 5 MB) | `/send /sdcard/foto.png` |
| `/log on senha` | Ativa histórico local criptografado | `/log on minhasenha123` |
| `/log off` | Desativa e salva o histórico | `/log off` |
| `/log show` | Exibe o histórico descriptografado | `/log show` |
| `/export` | Exporta o histórico para um arquivo `.txt` | `/export` |
| `/filter vendas` | Filtra mensagens que começam com `#vendas` | `/filter vendas` |
| `/filter off` | Remove o filtro atual | `/filter off` |
| `/verify Usuário` | Verifica a identidade criptográfica de um participante | `/verify Lux` |
| `/promote Usuário` | *(admin/mod)* Promove a moderador | `/promote Lux` |
| `/demote Usuário` | *(admin/mod)* Remove privilégios de moderador | `/demote Lux` |
| `/kick Usuário` | *(admin/mod)* Expulsa um participante | `/kick Invasor` |
| `/mute Usuário` | *(admin/mod)* Silencia um participante | `/mute Spammer` |
| `/unmute Usuário` | *(admin/mod)* Remove o silêncio | `/unmute Spammer` |
| `/ban Usuário` | *(admin/mod)* Bane permanentemente (chave pública + device) | `/ban Troll` |
| `/clear` | Limpa a tela do terminal | `/clear` |
| `/sair` | Sai da sala e encerra o cliente | `/sair` |

---

## 🧩 Estrutura do projeto

```
ps.chat-cli/
├── pschat.py              # Cliente principal
├── requirements.txt       # Dependências Python
└── README.md
```

**Arquivos gerados (em `~/.pschat/`):**
```
~/.pschat/
├── keys.json              # Chaves criptográficas (privada + pública + assinatura)
├── device_id              # Identificador único do dispositivo
└── history/               # Históricos criptografados por sala
    └── <token>.log.enc
```

---

## 🐛 Troubleshooting

| Problema | Solução |
|----------|---------|
| `ModuleNotFoundError: cryptography` | Instale `python-cryptography` via `pkg` (Termux) ou `pip` |
| `Falha ao conectar` | Verifique o IP e a porta do servidor. O servidor está rodando? |
| `Aguardando chave de sala...` | Aguarde alguns segundos – o primeiro membro gera a chave automaticamente. |
| `Chave de sala não disponível` | O admin ou o primeiro membro ainda não gerou a chave. Peça para alguém enviar uma mensagem. |
| Terminal trava após desconexão | Pressione `Ctrl+C` ou feche a aba. Na v2.2.6 isso está resolvido. |
| Comandos não são reconhecidos | Use `/help` para ver a lista exata. O autocompletar com Tab ajuda. |
| **Termux: erro ao instalar `cryptography`** | Use `pkg install python-cryptography` antes do `pip install` |

---

## 🔒 Segurança

- **Criptografia ponta a ponta** – o servidor não consegue ler suas mensagens.
- **Chaves assimétricas** – X25519 para acordo de chaves, Ed25519 para assinaturas.
- **Chave de sala** – AES‑GCM renovada automaticamente (forward secrecy).
- **Fingerprint** – verifique presencialmente para evitar ataques MITM.
- **Device ID** – o banimento persiste mesmo trocando de nome ou recriando chaves.
- **Modo anônimo** – gere chaves temporárias, sem deixar rastros no dispositivo.

---

## 🧪 Testado em

| Plataforma | Terminal | Status |
|------------|----------|--------|
| Termux (Android 12+) | Bash | ✅ |
| Ubuntu 22.04 | GNOME Terminal | ✅ |
| Windows 11 (WSL) | Windows Terminal | ✅ |
| macOS | Terminal.app, iTerm2 | ✅ |

---

## 🤝 Contribuindo

1. Faça um fork do projeto
2. Crie uma branch (`git checkout -b feature/nova-feature`)
3. Commit suas alterações (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

---

## 📄 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.

---

## 🙋 Suporte

- Abra uma issue no [GitHub Issues](https://github.com/PSecurity/ps.chat-cli/issues)
- Consulte o repositório servidor: [ps.chat-admin](https://github.com/PSecurity/ps.chat-admin)

---

**Desenvolvido por `PeekSecurity` – Comunicação offline, segura e no terminal.**
