#!/bin/bash


#----Configuration Settings---

COW_HOST="localhost"
COW_PORT="2224"
USER="root"
PASS="12345"  # Hardcoded authentication info for testing purposes

COMMANDS=(
	"ls -la"
	"sleep 1"
	"cat /etc/passwd"
	"sleep 1"
	"whoami"
	"sleep 1"
	"uname -a"
	"sleep 1"
	"ps aux > /dev/null"
	"sleep 1"
	"ls"
	"sleep 1"
	"exit"
)

echo "[*] Starting Cowrie Test"
echo "[*] Auth_data: ${USER}@${COW_HOST}  pass:${PASS}"

INPUT_SCRIPT=$(printf "%s\n" "${COMMANDS[@]}")

sshpass -p "$PASS" ssh -p "$COW_PORT" -o StrictHostKeyChecking=no -q "$USER@$COW_HOST" "$INPUT_SCRIPT"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
	echo "SUCESS"
else
	echo "ERROR"
	echo "ecit code: $EXIT_CODE"

fi

echo "done"

