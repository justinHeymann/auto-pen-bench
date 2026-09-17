#!/bin/bash

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Docker is installed; if not, install it
if ! command_exists docker; then
    echo "Installing Docker..."
    sudo apt update
    sudo apt install -y docker.io
fi

# Check if Docker Compose (v2 plugin) is installed; if not, install it
if command_exists docker && ! docker compose version >/dev/null 2>&1; then
    echo "Installing Docker Compose plugin..."
    sudo apt update
    sudo apt install -y docker-compose-v2 || sudo apt install -y docker-compose-plugin
fi

mkdir -p benchmark/machines/kali/tmp_script

# Set or update the environment variables without clobbering other .env keys
# (e.g. OPENAI_API_KEY)
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