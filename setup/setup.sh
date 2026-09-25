#!/bin/bash
set -e

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

if ! command_exists docker; then
    echo "Installing Docker..."
    sudo apt update
    sudo apt install -y docker.io
fi

if command_exists docker && ! docker compose version >/dev/null 2>&1; then
    echo "Installing Docker Compose plugin..."
    sudo apt update
    sudo apt install -y docker-compose-v2 || sudo apt install -y docker-compose-plugin
fi

mkdir -p benchmark/machines/kali/tmp_script
# Sentinel the driver checks before clearing this directory on every reset,
# so a misconfigured KALISCRIPTS cannot wipe another path.
touch benchmark/machines/kali/tmp_script/leave_me_here

# Set or update path variables without clobbering other .env keys
# (e.g. OPENAI_API_KEY).
touch .env
if grep -q '^AUTOPENBENCH=' .env; then
    sed -i "s|^AUTOPENBENCH=.*|AUTOPENBENCH=$(pwd)/benchmark|" .env
else
    echo "AUTOPENBENCH=$(pwd)/benchmark" >> .env
fi
if grep -q '^KALISCRIPTS=' .env; then
    sed -i "s|^KALISCRIPTS=.*|KALISCRIPTS=$(pwd)/benchmark/machines/kali/tmp_script|" .env
else
    echo "KALISCRIPTS=$(pwd)/benchmark/machines/kali/tmp_script" >> .env
fi

pip3 install -e .