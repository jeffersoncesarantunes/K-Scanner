#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Building K-Scanner...${NC}"
if make clean && make; then
    echo -e "${GREEN}Build successful! Binary at ./kscanner${NC}"
    ls -la kscanner
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
