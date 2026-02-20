#!/bin/bash
# K-Scanner build script
# Handles clean build and provides feedback

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Building K-Scanner...${NC}"

# Clean and build
make clean && make

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful! Binary at bin/kscanner${NC}"
    ls -la bin/
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
