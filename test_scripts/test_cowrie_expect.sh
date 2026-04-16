#!/usr/bin/expect -f

# Configuration info
set timeout 20
set host "localhost"
set port "2224"
set user "root"
set pass "12345"

# SSH connection
spawn ssh -p $port $user@$host
expect "password:"
send "$pass\r"
expect "$ "  ;# Wait for the shell prompt (e.g., root@cowrie:~#)

# Define commands
set commands {
    "ls -la"
    "cat /etc/passwd"
    "uname -a"
    "whoami"
    "ps aux > /dev/null"
    "echo 'Test complete'"
}

# Loop through commands
foreach cmd $commands {
    puts "\n[>] Sending: $cmd"
    send "$cmd\r"
    
    # Wait for the prompt
    expect "$ " 
    
    # small delay
    sleep 1
}

# Close session
send "exit\r"
expect eof
