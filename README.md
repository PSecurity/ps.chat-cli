# 👾 PS.Chat Client

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/seu-usuario/ps.chat-client/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Termux](https://img.shields.io/badge/Termux-Compatible-red.svg)](https://termux.com)
[![Bash](https://img.shields.io/badge/bash-5.1+-black.svg)](https://www.gnu.org/software/bash/)

**Cliente leve para acessar salas do PS.Chat** – sem necessidade de instalar servidor ou dependências complexas.

[![PS.Chat Client Demo](https://placehold.co/800x200/0a0014/b026ff?text=PS.Chat+Client)](https://tempimg.cc/800x200?bg=0a0014&color=ff00ff&text=PS.Chat-Cli)

---

## 🎯 O que é este repositório?

Este repositório contém **scripts clientes** para se conectar a um servidor [PS.Chat Admin](https://github.com/seu-usuario/ps.chat-admin) já em execução.

**Você só precisa:**
1. Saber o **IP do servidor** (quem está rodando o admin)
2. Ter o **token da sala** (fornecido pelo administrador)

> 🔗 **Repositório do servidor:** [ps.chat-admin](https://github.com/seu-usuario/ps.chat-admin)

---

## 📦 Opções de cliente

| Script | Linguagem | Requerimentos | Uso recomendado |
|--------|-----------|---------------|------------------|
| `ps.chat-cli.py` | Python | Python 3 + `zeroconf` | **Recomendado** – com descoberta automática |
| `ps.chat-lite.sh` | Bash | Apenas bash | Dispositivos muito limitados |
| `ps.chat-installer.sh` | Bash + Python | Nenhum (instala tudo) | Usuários leigos no Termux |

---

## 🚀 Instalação e uso

### Opção 1: Instalador automático (MAIS FÁCIL) – APENAS TERMUX

```bash
curl -sSL https://raw.githubusercontent.com/PSecurity/ps.chat-client/main/ps.chat-installer.sh | bash
```

O script irá:

· Instalar termux-api (para abrir navegador)
· Perguntar IP do servidor e token
· Abrir o navegador automaticamente na sala

**Opção 2:** Cliente Python (Linux/macOS/Windows/Termux)

```bash
# Clone o repositório
git clone https://github.com/PSecurity/ps.chat-client.git
cd ps.chat-client

# Instale a dependência (apenas para descoberta automática)
pip install zeroconf

# Execute
python ps.chat-cli.py
```

**Opção 3:** Cliente bash (qualquer sistema com bash)

```bash
# Baixe o script
curl -O https://raw.githubusercontent.com/seu-usuario/ps.chat-client/main/ps.chat-lite.sh
chmod +x ps.chat-lite.sh

# Execute
./ps.chat-lite.sh
```

---

## 📖 Como usar (qualquer opção)

1. Execute o cliente escolhido
2. Digite o IP do servidor (ex: 192.168.0.100 – veja no terminal do admin)
3. Digite o token da sala (ex: a1b2c3d4 – fornecido pelo admin)
4. O navegador será aberto automaticamente na sala de chat
5. Escolha um nome e comece a conversar!

**Exemplo de sessão**

```
========================================
👾 PS.CHAT – CLIENTE LEVE
========================================
📡 IP do servidor (ex: 192.168.0.123): 192.168.0.100
🔑 Token da sala: a1b2c3d4

🌐 Abrindo navegador em: http://192.168.0.100:5000/sala/a1b2c3d4

✅ Pronto! Escolha um nome e comece a conversar.
```

---

## 🔍 Descoberta automática (mDNS)

O cliente Python (ps.chat-cli.py) tenta encontrar o servidor automaticamente na rede local usando mDNS (ZeroConf).

Se o servidor estiver rodando o ps.chat-mdns.py, o cliente detectará automaticamente o IP – você só precisará digitar o token.

Para que a descoberta funcione:

· Servidor e cliente devem estar na mesma rede local
· Servidor deve estar com ps.chat-mdns.py em execução (ou integrado ao ps.chat-adm.py v1.0+)

---

## 📱 No Termux (Android)

**Instalação rápida (recomendado)**

```bash
pkg update && pkg upgrade
pkg install git python
git clone https://github.com/seu-usuario/ps.chat-client.git
cd ps.chat-client
pip install zeroconf
python ps.chat-cli.py
```

**Executar sem instalar Python (bash puro)**

```bash
pkg install bash
curl -O https://raw.githubusercontent.com/seu-usuario/ps.chat-client/main/ps.chat-lite.sh
bash ps.chat-lite.sh
```

---

## 🐛 Troubleshooting

Problema Solução
termux-open-url: command not found Instale termux-api: pkg install termux-api
zeroconf module not found Instale zeroconf: pip install zeroconf
Navegador não abre No Termux, execute termux-open-url http://... manualmente para testar
"Conexão recusada" Verifique se o servidor está rodando e se o IP está correto
"Sala não encontrada" Token inválido ou sala já foi fechada pelo admin

---

## 📋 Estrutura do repositório

```
ps.chat-client/
├── ps.chat-cli.py           # Cliente Python (recomendado)
├── ps.chat-lite.sh          # Cliente bash (minimalista)
├── ps.chat-installer.sh     # Instalador automático (Termux)
├── README.md                # Este arquivo
└── LICENSE                  # Licença MIT
```

---

## 🔗 Links úteis

· Repositório do servidor (admin)
· Documentação completa
· Reportar bug

---

## 🤝 Contribuindo

1. Faça um fork do projeto
2. Crie uma branch (git checkout -b feature/nova-feature)
3. Commit suas alterações (git commit -m 'Adiciona nova feature')
4. Push para a branch (git push origin feature/nova-feature)
5. Abra um Pull Request

---

## 📄 Licença

Distribuído sob a licença MIT. Veja LICENSE para mais informações.

---

Desenvolvido por PeekSecurity – Acesso rápido e simples.

---

---

## ✅ Check antes de subir

- [ ] Substitua `seu-usuario` pelo seu usuário real do GitHub
- [ ] Adicione uma imagem/screenshot real do cliente em ação (substitua o placeholder `https://via.placeholder.com/...`)
- [ ] Crie o arquivo `LICENSE` (MIT) no repositório
- [ ] Teste os comandos `curl` no Termux para garantir que funcionam

## 📦 Comandos para criar o repositório e subir

```bash
# No diretório do ps.chat-client
git init
git add .
git commit -m "Release v1.0.0 - PS.Chat Client"
git remote add origin https://github.com/seu-usuario/ps.chat-client.git
git push -u origin main
git tag -a v1.0.0 -m "Primeira versão estável do cliente"
git push origin v1.0.0
```
