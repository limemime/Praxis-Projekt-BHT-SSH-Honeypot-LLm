import os # Standard library for environment variables
import chromadb # Client to interact with the Chroma Vector Database
from langchain_huggingface import HuggingFaceEmbeddings # Tool to convert text into vectors (embeddings)

# --- STEP 1: Setup Connection ---
chroma_host = os.getenv("CHROMA_HOST", "localhost")
chroma_client = chromadb.HttpClient(host=chroma_host, port=8000)
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
collection = chroma_client.get_or_create_collection(name="ssh_knowledge")

# --- STEP 2: Define "Legit" System Knowledge ---
# We provide the LLM with the "ground truth" for the most common attacker commands
knowledge_base = [
    # --- System Information & Identification ---
    {"id": "etc_passwd", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", "metadata": {"source": "/etc/passwd"}},
    {"id": "etc_shadow", "text": "root:$6$8wJqX6f3$V8S.r...:19045:0:99999:7:::\nwww-data:*:19045:0:99999:7:::\n", "metadata": {"source": "/etc/shadow"}},
    {"id": "uname_a", "text": "Linux ubuntu-honeypot 5.15.0-72-generic #79-Ubuntu SMP Wed May 17 22:19:59 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux", "metadata": {"source": "uname -a"}},
    {"id": "etc_os_release", "text": "PRETTY_NAME=\"Ubuntu 22.04.2 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.2 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n", "metadata": {"source": "/etc/os-release"}},
    {"id": "hostname", "text": "ubuntu-honeypot", "metadata": {"source": "hostname"}},
    
    # --- File System & Navigation ---
    {"id": "root_ls", "text": "total 28\ndrwx------  4 root root 4096 May 22 10:00 .\ndrwxr-xr-x 20 root root 4096 May 22 09:30 ..\n-rw-------  1 root root  854 May 22 10:05 .bash_history\n-rw-r--r--  1 root root 3106 Dec  5 2021 .bashrc\n-rw-r--r--  1 root root  161 Dec  5 2021 .profile\ndrwx------  2 root root 4096 May 22 10:00 .ssh\n-rw-r--r--  1 root root   20 May 22 10:10 flag.txt\n", "metadata": {"source": "ls -la /root"}},
    {"id": "bin_ls", "text": "total 10484\n-rwxr-xr-x 1 root root 1168776 Apr 18  2022 bash\n-rwxr-xr-x 1 root root   34888 Mar  2  2022 cat\n-rwxr-xr-x 1 root root   63864 Mar  2  2022 chgrp\n-rwxr-xr-x 1 root root   63864 Mar  2  2022 chmod\n-rwxr-xr-x 1 root root   63864 Mar  2  2022 chown\n-rwxr-xr-x 1 root root  142144 Mar  2  2022 cp\n-rwxr-xr-x 1 root root  121464 Mar  2  2022 date\n-rwxr-xr-x 1 root root   76496 Mar  2  2022 dd\n-rwxr-xr-x 1 root root   93736 Mar  2  2022 df\n", "metadata": {"source": "ls -la /bin"}},
    {"id": "etc_ls", "text": "total 1024\ndrwxr-xr-x 105 root root 12288 May 22 09:30 .\ndrwxr-xr-x  20 root root  4096 May 22 09:30 ..\n-rw-r--r--   1 root root  3028 May 22 09:30 adduser.conf\n-rw-r--r--   1 root root    40 May 22 09:30 hostname\n-rw-r--r--   1 root root   150 May 22 09:30 hosts\n-rw-r--r--   1 root root   854 May 22 09:30 issue\n-rw-r--r--   1 root root    22 May 22 09:30 issue.net\ndrwxr-xr-x   2 root root  4096 May 22 09:30 pam.d\n-rw-r--r--   1 root root  2048 May 22 09:30 passwd\n-rw-r-----   1 root shadow  1024 May 22 09:30 shadow\n", "metadata": {"source": "ls -la /etc"}},

    # --- Networking (Standard Attacker Checks) ---
    {"id": "ifconfig", "text": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.15  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n        RX packets 12542  bytes 10452341 (10.4 MB)\n        TX packets 8432   bytes 954123 (954.1 KB)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n", "metadata": {"source": "ifconfig"}},
    {"id": "ip_addr", "text": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    inet 192.168.1.15/24 brd 192.168.1.255 scope global eth0\n", "metadata": {"source": "ip addr"}},
    {"id": "netstat_antp", "text": "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      842/sshd            \ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      954/nginx: master   \ntcp        0     64 192.168.1.15:22         192.168.1.5:54231       ESTABLISHED 1234/sshd: root@pts \n", "metadata": {"source": "netstat -antp"}},
    {"id": "ss_tulpn", "text": "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess\ntcp   LISTEN 0      128          0.0.0.0:22           0.0.0.0:*    users:((\"sshd\",pid=842,fd=3))\ntcp   LISTEN 0      511          0.0.0.0:80           0.0.0.0:*    users:((\"nginx\",pid=954,fd=6))\n", "metadata": {"source": "ss -tulpn"}},

    # --- Processes & System Status ---
    {"id": "ps_aux", "text": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.2 166248 11232 ?        Ss   09:00   0:01 /sbin/init\nroot       842  0.0  0.1  15876  7124 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\nroot       954  0.0  0.2  45632 12544 ?        Ss   09:01   0:00 nginx: master process /usr/sbin/nginx\nwww-data   955  0.0  0.1  46124  8432 ?        S    09:01   0:00 nginx: worker process\nroot      1234  0.1  0.1  16432  7532 ?        Ss   10:15   0:00 sshd: root@pts/0\nroot      1245  0.0  0.0   8432  3124 pts/0    R+   10:20   0:00 ps aux\n", "metadata": {"source": "ps aux"}},
    {"id": "top_snapshot", "text": "top - 10:20:05 up 1:20,  1 user,  load average: 0.00, 0.01, 0.05\nTasks: 104 total,   1 running, 103 sleeping,   0 stopped,   0 zombie\n%Cpu(s):  0.3 us,  0.3 sy,  0.0 ni, 99.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\nMiB Mem :   1984.5 total,   1432.1 free,    245.2 used,    307.2 buff/cache\n", "metadata": {"source": "top"}},
    {"id": "free_m", "text": "              total        used        free      shared  buff/cache   available\nMem:           1984         245        1432          12         307        1620\nSwap:          2047           0        2047\n", "metadata": {"source": "free -m"}},

    # --- User Activity & History ---
    {"id": "bash_history", "text": "apt update\napt install -y nginx\nsystemctl start nginx\ncd /var/www/html\nls\ncat index.html\nuseradd -m testuser\npasswd testuser\nls -la /root\nexit\n", "metadata": {"source": "cat ~/.bash_history"}},
    {"id": "last_logins", "text": "root     pts/0        192.168.1.5      Wed May 22 10:15   still logged in\nreboot   system boot  5.15.0-72-generi Wed May 22 09:00   up (01:20)\nroot     tty1                          Wed May 22 08:55 - 09:00  (00:04)\n", "metadata": {"source": "last"}},
    {"id": "who_am_i", "text": "root     pts/0        May 22 10:15 (192.168.1.5)", "metadata": {"source": "who"}},

    # --- Common "Enumeration" Commands ---
    {"id": "id_root", "text": "uid=0(root) gid=0(root) groups=0(root)", "metadata": {"source": "id"}},
    {"id": "mount_info", "text": "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\nsysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n", "metadata": {"source": "mount"}},
    {"id": "df_h", "text": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        20G  4.2G   15G  22% /\nudev            980M     0  980M   0% /dev\ntmpfs           200M  1.2M  199M   1% /run\n", "metadata": {"source": "df -h"}},
    {"id": "find_perm_4000", "text": "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/chsh\n/usr/bin/gpasswd\n/usr/bin/newgrp\n/usr/bin/chfn\n", "metadata": {"source": "find / -perm -4000 -type f 2>/dev/null"}},
    {"id": "lsmod", "text": "Module                  Size  Used by\nnls_utf8               16384  1\nisofs                  49152  1\njoydev                 28672  0\ninput_leds             16384  0\npsmouse               176128  0\n", "metadata": {"source": "lsmod"}},
    {"id": "crontab_l", "text": "# m h  dom mon dow   command\n*/15 * * * * /usr/local/bin/backup.sh > /dev/null 2>&1\n", "metadata": {"source": "crontab -l"}},

    # --- Application Specific (Web Server) ---
    {"id": "nginx_conf", "text": "server {\n    listen 80 default_server;\n    root /var/www/html;\n    index index.html;\n    server_name _;\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n", "metadata": {"source": "/etc/nginx/sites-enabled/default"}},
    {"id": "index_html", "text": "<html>\n<head><title>Welcome to Ubuntu</title></head>\n<body>\n<h1>Honeypot Internal Dashboard</h1>\n<p>Status: Online</p>\n</body>\n</html>\n", "metadata": {"source": "/var/www/html/index.html"}},

    # --- Environment & Variables ---
    {"id": "env_vars", "text": "SHELL=/bin/bash\nPWD=/root\nLOGNAME=root\nHOME=/root\nLANG=en_US.UTF-8\nTERM=xterm-256color\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n", "metadata": {"source": "env"}},
    {"id": "alias_check", "text": "alias l='ls -CF'\nalias la='ls -A'\nalias ll='ls -alF'\nalias ls='ls --color=auto'\n", "metadata": {"source": "alias"}},

    # --- System Logs ---
    {"id": "dmesg_tail", "text": "[    0.000000] Linux version 5.15.0-72-generic (buildd@lcy02-amd64-079) \n[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-72-generic root=UUID=... ro quiet splash\n[    1.234567] systemd[1]: Detected architecture x86-64.\n", "metadata": {"source": "dmesg | tail"}},
    {"id": "auth_log_tail", "text": "May 22 10:15:01 ubuntu sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.5  user=root\nMay 22 10:15:10 ubuntu sshd[1234]: Accepted password for root from 192.168.1.5 port 54231 ssh2\n", "metadata": {"source": "tail /var/log/auth.log"}},

    # --- Common Tools Check ---
    {"id": "which_curl", "text": "/usr/bin/curl", "metadata": {"source": "which curl"}},
    {"id": "which_wget", "text": "/usr/bin/wget", "metadata": {"source": "which wget"}},
    {"id": "which_python", "text": "/usr/bin/python3", "metadata": {"source": "which python3"}},
    {"id": "gcc_version", "text": "gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0\nCopyright (C) 2021 Free Software Foundation, Inc.\n", "metadata": {"source": "gcc --version"}},
]

# --- STEP 3: Upload to Vector Database ---
print(f"Seeding {len(knowledge_base)} documents to ChromaDB at {chroma_host}...")

for entry in knowledge_base:
    collection.add(
        documents=[entry["text"]],
        metadatas=[entry["metadata"]],
        ids=[entry["id"]]
    )

print(f"Successfully seeded {len(knowledge_base)} system documents into 'ssh_knowledge' collection.")
