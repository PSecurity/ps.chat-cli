#!/bin/bash
# ps.chat-lite.sh - Cliente terminal minimalista (sem QR code)

PS_CHAT_VERSION="1.2"
PS_CHAT_TITLE="👾 PS.CHAT LITE"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${MAGENTA}"
echo "╔═══════════════════════════════════════╗"
echo "║   $PS_CHAT_TITLE v$PS_CHAT_VERSION   ║"
echo "║      Terminal Chat Client (Web)       ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

read -p "$(echo -e ${CYAN}📡 IP do servidor: ${NC})" SERVER_IP
[ -z "$SERVER_IP" ] && { echo -e "${RED}❌ IP não informado.${NC}"; exit 1; }

read -p "$(echo -e ${CYAN}🔑 Token da sala: ${NC})" TOKEN
[ -z "$TOKEN" ] && { echo -e "${RED}❌ Token não informado.${NC}"; exit 1; }

URL="http://$SERVER_IP:5000/sala/$TOKEN"
echo -e "\n${GREEN}✅ Conectando em: $URL${NC}"
echo -e "${YELLOW}➤ Abrindo navegador...${NC}"

# Abre URL
if command -v termux-open-url &>/dev/null; then
    termux-open-url "$URL"
elif command -v xdg-open &>/dev/null; then
    xdg-open "$URL"
elif command -v open &>/dev/null; then
    open "$URL"
elif command -v start &>/dev/null; then
    start "$URL"
else
    echo -e "${RED}⚠️ Abra manualmente no navegador:${NC} $URL"
fi

echo -e "\n${GREEN}🎉 Pronto! No navegador, escolha um nome e converse.${NC}"
echo -e "${MAGENTA}🔚 Pressione ENTER para sair...${NC}"
read -r