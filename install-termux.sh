#!/bin/bash
# ps.chat-installer.sh - Instala dependências e conecta (sem QR code)

set -e
PS_VERSION="1.0"
PS_TITLE="👾 PS.CHAT CLIENTE AUTO"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${MAGENTA}"
echo "╔═════════════════════════════════════════════╗"
echo "║   $PS_TITLE v$PS_VERSION                     ║"
echo "║   Instalação automática + conexão rápida     ║"
echo "╚═════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ -d /data/data/com.termux ]]; then
    IS_TERMUX=true
    echo -e "${CYAN}📱 Ambiente Termux detectado.${NC}"
else
    IS_TERMUX=false
fi

if $IS_TERMUX; then
    echo -e "${CYAN}🔧 Atualizando repositórios...${NC}"
    pkg update -y
    pkg upgrade -y
    pip install zeroconf
    # Instala termux-api (para abrir navegador)
    if ! command -v termux-open-url &>/dev/null; then
        echo -e "${YELLOW}📦 Instalando termux-api...${NC}"
        pkg install -y termux-api
    fi
fi

# Comando para abrir navegador
if $IS_TERMUX; then
    OPEN_CMD="termux-open-url"
elif command -v xdg-open &>/dev/null; then
    OPEN_CMD="xdg-open"
elif command -v open &>/dev/null; then
    OPEN_CMD="open"
elif command -v start &>/dev/null; then
    OPEN_CMD="start"
else
    OPEN_CMD=""
fi

read -p "$(echo -e ${CYAN}📡 IP do servidor: ${NC})" SERVER_IP
[ -z "$SERVER_IP" ] && { echo -e "${RED}❌ IP não informado.${NC}"; exit 1; }

read -p "$(echo -e ${CYAN}🔑 Token da sala: ${NC})" TOKEN
[ -z "$TOKEN" ] && { echo -e "${RED}❌ Token não informado.${NC}"; exit 1; }

URL="http://$SERVER_IP:5000/sala/$TOKEN"
echo -e "\n${GREEN}✅ URL de acesso: $URL${NC}"

if [[ -n "$OPEN_CMD" ]]; then
    echo -e "${YELLOW}🌐 Abrindo navegador...${NC}"
    $OPEN_CMD "$URL"
else
    echo -e "${RED}➤ Abra manualmente: $URL${NC}"
fi

echo -e "\n${GREEN}🎉 Concluído! No navegador, escolha um nome e converse.${NC}"
echo -e "${MAGENTA}🔚 Pressione ENTER para sair...${NC}"
read -r
