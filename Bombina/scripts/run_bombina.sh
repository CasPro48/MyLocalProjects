#!/bin/bash
# Bombina - Cybersecurity AI Assistant Launcher

echo "🐸 Starting Bombina - Cybersecurity AI Assistant"
echo "================================================"

# Check if Ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama service..."
    sudo systemctl start ollama
    sleep 2
fi

# Launch Bombina
echo "Launching Bombina (qwen2.5-coder:3b fine-tuned for security)..."
echo "Type 'exit' or Ctrl+C to quit"
echo ""

ollama run bombina
