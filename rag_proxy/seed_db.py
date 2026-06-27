import os # Standard library for environment variables
import chromadb # Client to interact with the Chroma Vector Database
from langchain_huggingface import HuggingFaceEmbeddings # Tool to convert text into vectors (embeddings)

# --- STEP 1: Setup Connection ---
chroma_host = os.getenv("CHROMA_HOST", "localhost")
chroma_client = chromadb.HttpClient(host=chroma_host, port=8000)
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
collection = chroma_client.get_or_create_collection(name="ssh_knowledge")

# --- STEP 2: Define "Legit" System Knowledge ---
# LAMP stack on Ubuntu 22.04 LTS — Apache2 + MySQL 8.0 + PHP 8.1
# Attacker profiles covered: privilege escalation, data exfiltration
knowledge_base = [

    # =========================================================================
    # SYSTEM INFORMATION & IDENTIFICATION
    # =========================================================================
    {"id": "etc_passwd", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false\ndeployer:x:1001:1001:,,,:/home/deployer:/bin/bash\n", "metadata": {"source": "/etc/passwd"}},
    {"id": "etc_shadow", "text": "root:$6$8wJqX6f3$V8S.r...:19045:0:99999:7:::\nwww-data:*:19045:0:99999:7:::\nmysql:!:19045:0:99999:7:::\ndeployer:$6$kL3mN9pQ$X7T.s...:19045:0:99999:7:::\n", "metadata": {"source": "/etc/shadow"}},
    {"id": "uname_a", "text": "Linux ubuntu-lamp 5.15.0-72-generic #79-Ubuntu SMP Wed May 17 22:19:59 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux", "metadata": {"source": "uname -a"}},
    {"id": "etc_os_release", "text": "PRETTY_NAME=\"Ubuntu 22.04.2 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.2 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n", "metadata": {"source": "/etc/os-release"}},
    {"id": "hostname", "text": "ubuntu-lamp", "metadata": {"source": "hostname"}},
    {"id": "etc_hosts", "text": "127.0.0.1 localhost\n127.0.1.1 ubuntu-lamp\n192.168.1.20 db-internal\n::1     localhost ip6-localhost ip6-loopback\n", "metadata": {"source": "/etc/hosts"}},

    # =========================================================================
    # FILE SYSTEM & NAVIGATION
    # =========================================================================
    {"id": "root_ls", "text": "total 40\ndrwx------  5 root root 4096 May 22 10:00 .\ndrwxr-xr-x 20 root root 4096 May 22 09:30 ..\n-rw-------  1 root root 1024 May 22 10:05 .bash_history\n-rw-r--r--  1 root root 3106 Dec  5 2021 .bashrc\n-rw-r--r--  1 root root  161 Dec  5 2021 .profile\ndrwx------  2 root root 4096 May 22 10:00 .ssh\n-rw-r--r--  1 root root   20 May 22 10:10 flag.txt\ndrwxr-xr-x  2 root root 4096 May 22 09:40 backups\n-rw-------  1 root root  512 May 22 09:45 .mysql_history\n", "metadata": {"source": "ls -la /root"}},
    {"id": "var_www_ls", "text": "total 24\ndrwxr-xr-x  3 root     root      4096 May 22 09:30 .\ndrwxr-xr-x 14 root     root      4096 May 22 09:30 ..\ndrwxr-xr-x  8 www-data www-data  4096 May 22 11:00 html\n", "metadata": {"source": "ls -la /var/www"}},
    {"id": "var_www_html_ls", "text": "total 64\ndrwxr-xr-x 8 www-data www-data 4096 May 22 11:00 .\ndrwxr-xr-x 3 root     root     4096 May 22 09:30 ..\n-rw-r--r-- 1 www-data www-data  648 May 22 10:00 index.php\n-rw-r--r-- 1 www-data www-data  312 May 22 10:00 config.php\ndrwxr-xr-x 2 www-data www-data 4096 May 22 10:00 uploads\ndrwxr-xr-x 2 www-data www-data 4096 May 22 10:00 admin\ndrwxr-xr-x 2 www-data www-data 4096 May 22 10:00 includes\n-rw-r--r-- 1 www-data www-data 1024 May 22 10:00 .htaccess\n", "metadata": {"source": "ls -la /var/www/html"}},
    {"id": "etc_ls", "text": "total 1200\ndrwxr-xr-x 110 root root 12288 May 22 09:30 .\ndrwxr-xr-x  20 root root  4096 May 22 09:30 ..\n-rw-r--r--   1 root root  3028 May 22 09:30 adduser.conf\ndrwxr-xr-x   8 root root  4096 May 22 09:30 apache2\ndrwxr-xr-x   2 root root  4096 May 22 09:30 cron.d\n-rw-r--r--   1 root root    40 May 22 09:30 hostname\n-rw-r--r--   1 root root   150 May 22 09:30 hosts\ndrwxr-xr-x   2 root root  4096 May 22 09:30 mysql\n-rw-r--r--   1 root root  2048 May 22 09:30 passwd\n-rw-r-----   1 root shadow 1024 May 22 09:30 shadow\ndrwxr-xr-x   3 root root  4096 May 22 09:30 php\n", "metadata": {"source": "ls -la /etc"}},
    {"id": "root_backups_ls", "text": "total 48\ndrwxr-xr-x 2 root root  4096 May 22 09:40 .\ndrwx------ 5 root root  4096 May 22 10:00 ..\n-rw------- 1 root root 14312 May 22 03:00 db_backup_20230522.sql.gz\n-rw------- 1 root root 13988 May 21 03:00 db_backup_20230521.sql.gz\n", "metadata": {"source": "ls -la /root/backups"}},
    {"id": "tmp_ls", "text": "total 28\ndrwxrwxrwt 7 root root 4096 May 22 10:30 .\ndrwxr-xr-x 20 root root 4096 May 22 09:30 ..\ndrwxrwxrwt 2 root root 4096 May 22 09:30 .ICE-unix\ndrwxrwxrwt 2 root root 4096 May 22 09:30 .X11-unix\n-rw-r--r-- 1 www-data www-data  512 May 22 10:28 sess_a3f8b2c1d4e5\n", "metadata": {"source": "ls -la /tmp"}},

    # =========================================================================
    # NETWORKING
    # =========================================================================
    {"id": "ifconfig", "text": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.15  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n        RX packets 12542  bytes 10452341 (10.4 MB)\n        TX packets 8432   bytes 954123 (954.1 KB)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n", "metadata": {"source": "ifconfig"}},
    {"id": "ip_addr", "text": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    inet 192.168.1.15/24 brd 192.168.1.255 scope global eth0\n", "metadata": {"source": "ip addr"}},
    {"id": "ip_route", "text": "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.15 metric 100\n192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.15\n", "metadata": {"source": "ip route"}},
    {"id": "netstat_antp", "text": "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      842/sshd\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      954/apache2\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1012/mysqld\ntcp        0     64 192.168.1.15:22         192.168.1.5:54231       ESTABLISHED 1234/sshd: root@pts\n", "metadata": {"source": "netstat -antp"}},
    {"id": "ss_tulpn", "text": "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\ntcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=842,fd=3))\ntcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*     users:((\"apache2\",pid=954,fd=4))\ntcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*     users:((\"mysqld\",pid=1012,fd=23))\n", "metadata": {"source": "ss -tulpn"}},

    # =========================================================================
    # PROCESSES & SYSTEM STATUS
    # =========================================================================
    {"id": "ps_aux", "text": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.2 166248 11232 ?        Ss   09:00   0:01 /sbin/init\nroot       842  0.0  0.1  15876  7124 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\nroot       954  0.0  0.3  65432 16544 ?        Ss   09:01   0:00 /usr/sbin/apache2 -k start\nwww-data   955  0.0  0.2  65748 12432 ?        S    09:01   0:00 /usr/sbin/apache2 -k start\nwww-data   956  0.0  0.2  65748 12432 ?        S    09:01   0:00 /usr/sbin/apache2 -k start\nmysql     1012  0.2  4.5 1823456 92340 ?       Ssl  09:01   0:12 /usr/sbin/mysqld\nroot      1234  0.1  0.1  16432  7532 ?        Ss   10:15   0:00 sshd: root@pts/0\nroot      1245  0.0  0.0   8432  3124 pts/0    R+   10:20   0:00 ps aux\n", "metadata": {"source": "ps aux"}},
    {"id": "top_snapshot", "text": "top - 10:20:05 up 1:20,  1 user,  load average: 0.12, 0.08, 0.05\nTasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n%Cpu(s):  1.2 us,  0.4 sy,  0.0 ni, 98.1 id,  0.3 wa,  0.0 hi,  0.0 si,  0.0 st\nMiB Mem :   3984.5 total,   1832.1 free,   1245.2 used,    907.2 buff/cache\n", "metadata": {"source": "top"}},
    {"id": "free_m", "text": "              total        used        free      shared  buff/cache   available\nMem:           3984        1245        1832          24         907        2530\nSwap:          2047           0        2047\n", "metadata": {"source": "free -m"}},

    # =========================================================================
    # USER ACTIVITY & HISTORY
    # =========================================================================
    {"id": "bash_history", "text": "apt update\napt install -y apache2 mysql-server php libapache2-mod-php php-mysql\nsystemctl start apache2\nsystemctl start mysql\nmysql_secure_installation\nmysql -u root -p\ncd /var/www/html\nls -la\ncat config.php\nuseradd -m deployer\npasswd deployer\nusermod -aG sudo deployer\nls -la /root/backups\nmysqldump -u root -p myappdb > /root/backups/db_backup_20230522.sql\ngzip /root/backups/db_backup_20230522.sql\nexit\n", "metadata": {"source": "cat ~/.bash_history"}},
    {"id": "mysql_history", "text": "show databases;\nuse myappdb;\nshow tables;\nselect * from users limit 5;\nselect username, password from users;\ngrant all privileges on myappdb.* to 'appuser'@'localhost' identified by 'Str0ng#Pass2023';\nflush privileges;\n", "metadata": {"source": "cat ~/.mysql_history"}},
    {"id": "last_logins", "text": "root     pts/0        192.168.1.5      Wed May 22 10:15   still logged in\ndeployer pts/1        192.168.1.8      Wed May 22 09:45 - 10:10  (00:25)\nreboot   system boot  5.15.0-72-generi Wed May 22 09:00   up (01:20)\nroot     tty1                          Wed May 22 08:55 - 09:00  (00:04)\n", "metadata": {"source": "last"}},
    {"id": "who_am_i", "text": "root     pts/0        May 22 10:15 (192.168.1.5)", "metadata": {"source": "who"}},

    # =========================================================================
    # PRIVILEGE ESCALATION — ENUMERATION
    # =========================================================================
    {"id": "id_root", "text": "uid=0(root) gid=0(root) groups=0(root)", "metadata": {"source": "id"}},
    {"id": "sudo_l", "text": "Matching Defaults entries for www-data on ubuntu-lamp:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\nUser www-data may run the following commands on ubuntu-lamp:\n    (ALL) NOPASSWD: /usr/bin/find\n", "metadata": {"source": "sudo -l"}},
    {"id": "find_perm_4000", "text": "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/chsh\n/usr/bin/gpasswd\n/usr/bin/newgrp\n/usr/bin/chfn\n/usr/bin/at\n/usr/sbin/apache2\n", "metadata": {"source": "find / -perm -4000 -type f 2>/dev/null"}},
    {"id": "find_writable_dirs", "text": "/tmp\n/var/tmp\n/var/www/html/uploads\n/dev/shm\n", "metadata": {"source": "find / -writable -type d 2>/dev/null | grep -v proc"}},
    {"id": "find_world_writable_files", "text": "/etc/passwd\n/var/www/html/uploads/tmp_upload_8f3a.php\n", "metadata": {"source": "find / -perm -0002 -type f 2>/dev/null | grep -v proc"}},
    {"id": "capabilities_check", "text": "/usr/bin/python3.10 cap_setuid=eip\n/usr/bin/perl cap_setuid=eip\n", "metadata": {"source": "getcap -r / 2>/dev/null"}},
    {"id": "sudoers", "text": "#\n# This file MUST be edited with the 'visudo' command as root.\n#\nroot    ALL=(ALL:ALL) ALL\n%sudo   ALL=(ALL:ALL) ALL\ndeployer ALL=(ALL) NOPASSWD: /usr/bin/git, /usr/bin/composer\nwww-data ALL=(ALL) NOPASSWD: /usr/bin/find\n", "metadata": {"source": "cat /etc/sudoers"}},
    {"id": "etc_crontab", "text": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 * * * * root  cd / && run-parts --report /etc/cron.hourly\n25 6 * * * root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n47 6 * * 7 root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n0  3 * * * root  /root/backups/backup.sh > /dev/null 2>&1\n*/15 * * * * www-data /var/www/html/scripts/health_check.sh\n", "metadata": {"source": "cat /etc/crontab"}},
    {"id": "crontab_l", "text": "# Deployer user crontab\n*/15 * * * * /usr/local/bin/backup.sh > /dev/null 2>&1\n0 2 * * * /usr/bin/mysqldump -u appuser -pStr0ng#Pass2023 myappdb > /home/deployer/db_export.sql\n", "metadata": {"source": "crontab -l"}},
    {"id": "etc_cron_d_ls", "text": "total 28\ndrwxr-xr-x   2 root root 4096 May 22 09:30 .\ndrwxr-xr-x 110 root root 4096 May 22 09:30 ..\n-rw-r--r--   1 root root  102 May 22 09:30 .placeholder\n-rw-r--r--   1 root root  285 May 22 09:30 apache2\n-rw-r--r--   1 root root  396 May 22 09:30 mysql-backup\n", "metadata": {"source": "ls -la /etc/cron.d"}},
    {"id": "kernel_version", "text": "5.15.0-72-generic", "metadata": {"source": "uname -r"}},
    {"id": "dpkg_list", "text": "ii  apache2                   2.4.52-1ubuntu4.3  amd64  Apache HTTP Server\nii  apache2-bin               2.4.52-1ubuntu4.3  amd64  Apache HTTP Server (modules and other binary files)\nii  libapache2-mod-php8.1     8.1.2-1ubuntu2.11  amd64  server-side, HTML-embedded scripting language\nii  mysql-server-8.0          8.0.32-0ubuntu0.22.04.2  amd64  MySQL database server binaries\nii  php8.1                    8.1.2-1ubuntu2.11  amd64  server-side, HTML-embedded scripting language\nii  php8.1-mysql              8.1.2-1ubuntu2.11  amd64  MySQL module for php\nii  openssh-server            1:8.9p1-3ubuntu0.1  amd64  secure shell (SSH) server\nii  sudo                      1.9.9-1ubuntu2.4   amd64  Provide limited super user privileges to specific users\n", "metadata": {"source": "dpkg -l | grep -E 'apache|mysql|php|ssh|sudo'"}},
    {"id": "passwd_writable_check", "text": "-rw-rw-rw- 1 root root 2048 May 22 09:30 /etc/passwd", "metadata": {"source": "ls -la /etc/passwd"}},
    {"id": "lsmod", "text": "Module                  Size  Used by\nnls_utf8               16384  1\nisofs                  49152  1\njoydev                 28672  0\ninput_leds             16384  0\npsmouse               176128  0\n", "metadata": {"source": "lsmod"}},
    {"id": "ssh_authorized_keys", "text": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3... deployer@workstation", "metadata": {"source": "cat /root/.ssh/authorized_keys"}},
    {"id": "ssh_config_sshd", "text": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords no\nX11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n", "metadata": {"source": "cat /etc/ssh/sshd_config"}},
    {"id": "env_vars", "text": "SHELL=/bin/bash\nPWD=/root\nLOGNAME=root\nHOME=/root\nLANG=en_US.UTF-8\nTERM=xterm-256color\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nDB_PASS=Str0ng#Pass2023\nDB_USER=appuser\nDB_NAME=myappdb\n", "metadata": {"source": "env"}},

    # =========================================================================
    # DATA EXFILTRATION — APPLICATION & DATABASE
    # =========================================================================
    {"id": "config_php", "text": "<?php\n// Database configuration\ndefine('DB_HOST', 'localhost');\ndefine('DB_USER', 'appuser');\ndefine('DB_PASS', 'Str0ng#Pass2023');\ndefine('DB_NAME', 'myappdb');\n\n$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);\nif ($conn->connect_error) {\n    die('Connection failed: ' . $conn->connect_error);\n}\n?>", "metadata": {"source": "/var/www/html/config.php"}},
    {"id": "index_php", "text": "<?php\nrequire_once 'config.php';\n$result = $conn->query('SELECT id, username, email FROM users LIMIT 10');\nwhile ($row = $result->fetch_assoc()) {\n    echo $row['username'] . ' - ' . $row['email'] . '<br>';\n}\n?>", "metadata": {"source": "/var/www/html/index.php"}},
    {"id": "mysql_databases", "text": "+--------------------+\n| Database           |\n+--------------------+\n| information_schema |\n| myappdb            |\n| mysql              |\n| performance_schema |\n| sys                |\n+--------------------+", "metadata": {"source": "mysql -u root -e 'show databases;'"}},
    {"id": "mysql_tables", "text": "+------------------+\n| Tables_in_myappdb|\n+------------------+\n| orders           |\n| products         |\n| sessions         |\n| users            |\n+------------------+", "metadata": {"source": "mysql -u root -e 'use myappdb; show tables;'"}},
    {"id": "mysql_users_schema", "text": "+------------+--------------+------+-----+---------+----------------+\n| Field      | Type         | Null | Key | Default | Extra          |\n+------------+--------------+------+-----+---------+----------------+\n| id         | int          | NO   | PRI | NULL    | auto_increment |\n| username   | varchar(64)  | NO   | UNI | NULL    |                |\n| email      | varchar(128) | NO   | UNI | NULL    |                |\n| password   | varchar(255) | NO   |     | NULL    |                |\n| role       | enum('admin','user') | NO | | 'user' |              |\n| created_at | datetime     | YES  |     | NULL    |                |\n+------------+--------------+------+-----+---------+----------------+", "metadata": {"source": "mysql -u root -e 'use myappdb; describe users;'"}},
    {"id": "mysql_users_sample", "text": "+----+----------+------------------------------+--------------------------------------------------------------+-------+\n| id | username | email                        | password                                                     | role  |\n+----+----------+------------------------------+--------------------------------------------------------------+-------+\n|  1 | admin    | admin@company-internal.local | $2y$10$eImiTXuWVxfM37uY4JANjQ==...                           | admin |\n|  2 | jsmith   | j.smith@company-internal.local | $2y$10$TKh8H1.PfJH3KiKLQx0V9u...                           | user  |\n|  3 | mwilson  | m.wilson@company-internal.local | $2y$10$Xf3RqK9pL2mN7vT4sY8jAe...                          | user  |\n+----+----------+------------------------------+--------------------------------------------------------------+-------+", "metadata": {"source": "mysql -u root -e 'use myappdb; select id,username,email,password,role from users limit 5;'"}},
    {"id": "mysql_orders_schema", "text": "+----------------+--------------+------+-----+---------+----------------+\n| Field          | Type         | Null | Key | Default | Extra          |\n+----------------+--------------+------+-----+---------+----------------+\n| id             | int          | NO   | PRI | NULL    | auto_increment |\n| user_id        | int          | NO   | MUL | NULL    |                |\n| cc_number      | varchar(255) | YES  |     | NULL    |                |\n| cc_expiry      | varchar(7)   | YES  |     | NULL    |                |\n| amount         | decimal(10,2)| NO   |     | NULL    |                |\n| status         | varchar(32)  | NO   |     | pending |                |\n+----------------+--------------+------+-----+---------+----------------+", "metadata": {"source": "mysql -u root -e 'use myappdb; describe orders;'"}},
    {"id": "mysql_root_grants", "text": "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION\nGRANT ALL PRIVILEGES ON *.* TO 'appuser'@'localhost' IDENTIFIED BY PASSWORD '*A1B2C3D4E5F6...' WITH GRANT OPTION\n", "metadata": {"source": "mysql -u root -e 'show grants;'"}},
    {"id": "mysql_cnf", "text": "[mysqld]\nbind-address = 127.0.0.1\nmax_connections = 150\nslow_query_log = 1\nslow_query_log_file = /var/log/mysql/mysql-slow.log\nlong_query_time = 2\n[client]\nuser=root\npassword=r00tMySQL!2023\n", "metadata": {"source": "cat /etc/mysql/my.cnf"}},

    # =========================================================================
    # DATA EXFILTRATION — FILES & SECRETS
    # =========================================================================
    {"id": "find_config_files", "text": "/var/www/html/config.php\n/var/www/html/includes/db.php\n/home/deployer/.env\n/etc/mysql/my.cnf\n/root/.my.cnf\n", "metadata": {"source": "find / -name '*.php' -o -name '.env' -o -name 'my.cnf' 2>/dev/null | head -20"}},
    {"id": "deployer_env", "text": "APP_ENV=production\nAPP_KEY=base64:xK9mN3pQ7rT2vW5yZ0aB4cD6eF8gH1iJ\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=myappdb\nDB_USERNAME=appuser\nDB_PASSWORD=Str0ng#Pass2023\nMAIL_HOST=smtp.mailgun.org\nMAIL_USERNAME=postmaster@mg.company-internal.local\nMAIL_PASSWORD=key-3a8b9c1d2e4f5g6h\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=eu-central-1\n", "metadata": {"source": "cat /home/deployer/.env"}},
    {"id": "root_my_cnf", "text": "[client]\nuser=root\npassword=r00tMySQL!2023\n", "metadata": {"source": "cat /root/.my.cnf"}},
    {"id": "find_ssh_keys", "text": "/root/.ssh/id_rsa\n/root/.ssh/id_rsa.pub\n/root/.ssh/authorized_keys\n/home/deployer/.ssh/id_rsa\n/home/deployer/.ssh/authorized_keys\n", "metadata": {"source": "find / -name 'id_rsa' -o -name 'authorized_keys' 2>/dev/null"}},
    {"id": "apache_access_log_tail", "text": "192.168.1.5 - - [22/May/2023:09:45:12 +0000] \"GET / HTTP/1.1\" 200 648 \"-\" \"Mozilla/5.0\"\n192.168.1.5 - - [22/May/2023:09:45:15 +0000] \"GET /admin/ HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"\n192.168.1.5 - - [22/May/2023:10:05:32 +0000] \"POST /admin/login.php HTTP/1.1\" 302 0 \"-\" \"Mozilla/5.0\"\n192.168.1.9 - - [22/May/2023:10:10:44 +0000] \"GET /config.php HTTP/1.1\" 200 512 \"-\" \"curl/7.81.0\"\n", "metadata": {"source": "tail /var/log/apache2/access.log"}},
    {"id": "apache_error_log_tail", "text": "[Mon May 22 09:45:00.123456 2023] [php:error] [pid 956] [client 192.168.1.9:51234] PHP Warning: include(/var/www/html/includes/../../etc/passwd): failed to open stream: Permission denied in /var/www/html/index.php on line 14\n[Mon May 22 10:05:00.654321 2023] [php:notice] [pid 955] [client 192.168.1.5:54231] PHP Notice: Undefined variable: user_id in /var/www/html/admin/dashboard.php on line 8\n", "metadata": {"source": "tail /var/log/apache2/error.log"}},

    # =========================================================================
    # APACHE2 CONFIGURATION
    # =========================================================================
    {"id": "apache2_conf", "text": "ServerRoot \"/etc/apache2\"\nDefaultRuntimeDir ${APACHE_RUN_DIR}\nPidFile ${APACHE_PID_FILE}\nTimeout 300\nKeepAlive On\nMaxKeepAliveRequests 100\nKeepAliveTimeout 5\nUser ${APACHE_RUN_USER}\nGroup ${APACHE_RUN_GROUP}\nHostnameLookups Off\nErrorLog ${APACHE_LOG_DIR}/error.log\nLogLevel warn\nIncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\nInclude ports.conf\nIncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n", "metadata": {"source": "cat /etc/apache2/apache2.conf"}},
    {"id": "apache_vhost", "text": "<VirtualHost *:80>\n    ServerAdmin webmaster@localhost\n    DocumentRoot /var/www/html\n    ServerName ubuntu-lamp\n    ErrorLog ${APACHE_LOG_DIR}/error.log\n    CustomLog ${APACHE_LOG_DIR}/access.log combined\n    <Directory /var/www/html>\n        Options Indexes FollowSymLinks\n        AllowOverride All\n        Require all granted\n    </Directory>\n</VirtualHost>", "metadata": {"source": "cat /etc/apache2/sites-enabled/000-default.conf"}},
    {"id": "php_ini", "text": "[PHP]\nengine = On\nshort_open_tag = Off\noutput_buffering = 4096\nmax_execution_time = 30\nmemory_limit = 128M\nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\ndisplay_errors = Off\ndisplay_startup_errors = Off\nlog_errors = On\nerror_log = /var/log/php/error.log\nallow_url_fopen = On\nallow_url_include = Off\nfile_uploads = On\nupload_max_filesize = 10M\n", "metadata": {"source": "cat /etc/php/8.1/apache2/php.ini | grep -v ';' | grep -v '^$'"}},
    {"id": "php_version", "text": "PHP 8.1.2-1ubuntu2.11 (cli) (built: Feb 22 2023 22:56:18) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.1.2, Copyright (c) Zend Technologies\n    with Zend OPcache v8.1.2-1ubuntu2.11, Copyright (c), by Zend Technologies\n", "metadata": {"source": "php -v"}},
    {"id": "apache2_version", "text": "Server version: Apache/2.4.52 (Ubuntu)\nServer built:   2023-03-08T17:32:01\n", "metadata": {"source": "apache2 -v"}},
    {"id": "mysql_version", "text": "mysql  Ver 8.0.32-0ubuntu0.22.04.2 for Linux on x86_64 ((Ubuntu))\n", "metadata": {"source": "mysql --version"}},

    # =========================================================================
    # SYSTEM LOGS & MONITORING
    # =========================================================================
    {"id": "auth_log_tail", "text": "May 22 10:15:01 ubuntu sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.5  user=root\nMay 22 10:15:10 ubuntu sshd[1234]: Accepted password for root from 192.168.1.5 port 54231 ssh2\nMay 22 10:16:22 ubuntu sudo: deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/usr/bin/git pull\n", "metadata": {"source": "tail /var/log/auth.log"}},
    {"id": "syslog_tail", "text": "May 22 10:00:01 ubuntu CRON[1198]: (root) CMD (/root/backups/backup.sh > /dev/null 2>&1)\nMay 22 10:15:10 ubuntu sshd[1234]: Accepted password for root from 192.168.1.5 port 54231 ssh2\nMay 22 10:15:11 ubuntu systemd[1]: Started Session 4 of user root.\n", "metadata": {"source": "tail /var/log/syslog"}},
    {"id": "dmesg_tail", "text": "[    0.000000] Linux version 5.15.0-72-generic (buildd@lcy02-amd64-079)\n[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-72-generic root=UUID=... ro quiet splash\n[    1.234567] systemd[1]: Detected architecture x86-64.\n", "metadata": {"source": "dmesg | tail"}},

    # =========================================================================
    # COMMON ENUMERATION COMMANDS
    # =========================================================================
    {"id": "mount_info", "text": "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\nsysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n", "metadata": {"source": "mount"}},
    {"id": "df_h", "text": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G  8.7G   30G  23% /\nudev            1.9G     0  1.9G   0% /dev\ntmpfs           398M  1.4M  397M   1% /run\n", "metadata": {"source": "df -h"}},
    {"id": "alias_check", "text": "alias l='ls -CF'\nalias la='ls -A'\nalias ll='ls -alF'\nalias ls='ls --color=auto'\n", "metadata": {"source": "alias"}},
    {"id": "which_curl", "text": "/usr/bin/curl", "metadata": {"source": "which curl"}},
    {"id": "which_wget", "text": "/usr/bin/wget", "metadata": {"source": "which wget"}},
    {"id": "which_python", "text": "/usr/bin/python3", "metadata": {"source": "which python3"}},
    {"id": "which_nc", "text": "/usr/bin/nc", "metadata": {"source": "which nc"}},
    {"id": "which_mysql", "text": "/usr/bin/mysql", "metadata": {"source": "which mysql"}},
    {"id": "gcc_version", "text": "gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0\nCopyright (C) 2021 Free Software Foundation, Inc.\n", "metadata": {"source": "gcc --version"}},
    {"id": "linpeas_hint", "text": "drwxrwxrwt 7 root root 4096 May 22 10:30 /tmp\n-rw-r--r-- 1 root root 789012 May 22 10:31 /tmp/linpeas.sh\n", "metadata": {"source": "ls -la /tmp/linpeas.sh"}},
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
