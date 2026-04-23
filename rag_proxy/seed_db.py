import os # Standard library for environment variables
import chromadb # Client to interact with the Chroma Vector Database
from langchain_huggingface import HuggingFaceEmbeddings # Tool to convert text into vectors (embeddings)

# --- STEP 1: Setup Connection ---
# We connect to the ChromaDB service. 
# We use 'localhost' as default for running manually, but it will use 'chromadb' inside Docker.
chroma_host = os.getenv("CHROMA_HOST", "localhost")
chroma_client = chromadb.HttpClient(host=chroma_host, port=8000)

# Define the same embedding model used in main.py to ensure the "math" matches
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Create or get the collection where our knowledge will live
collection = chroma_client.get_or_create_collection(name="ssh_knowledge")

# --- STEP 2: Define "Fake" System Knowledge ---
# These are the documents that the RAG will retrieve when an attacker types a command
knowledge_base = [
    {
        "id": "etc_passwd",
        "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\n",
        "metadata": {"source": "/etc/passwd", "description": "User account information"}
    },
    {
        "id": "etc_shadow",
        "text": "root:$6$8wJqX6f3$V8S.r...:19045:0:99999:7:::\ndaemon:*:19045:0:99999:7:::\nbin:*:19045:0:99999:7:::\nsys:*:19045:0:99999:7:::\n",
        "metadata": {"source": "/etc/shadow", "description": "Encrypted password hashes"}
    },
    {
        "id": "uname_a",
        "text": "Linux ubuntu-honeypot 5.15.0-72-generic #79-Ubuntu SMP Wed May 17 22:19:59 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
        "metadata": {"source": "uname -a", "description": "Kernel and system version"}
    },
    {
        "id": "etc_issue",
        "text": "Ubuntu 22.04.2 LTS \\n \\l\n\nWelcome to the system. Unauthorized access is prohibited.",
        "metadata": {"source": "/etc/issue", "description": "Login banner information"}
    },
    {
        "id": "var_log_auth",
        "text": "May 22 10:15:01 ubuntu sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.5  user=root",
        "metadata": {"source": "/var/log/auth.log", "description": "Security and authentication logs"}
    },
    {
        "id": "root_dir",
        "text": "total 28\ndrwx------  4 root root 4096 May 22 10:00 .\ndrwxr-xr-x 20 root root 4096 May 22 09:30 ..\n-rw-------  1 root root  154 May 22 10:05 .bash_history\n-rw-r--r--  1 root root 3106 Dec  5 2021 .bashrc\n-rw-r--r--  1 root root  161 Dec  5 2021 .profile\ndrwx------  2 root root 4096 May 22 10:00 .ssh\n-rw-r--r--  1 root root   20 May 22 10:10 flag.txt",
        "metadata": {"source": "ls -la /root", "description": "Contents of the root directory"}
    }
]

# --- STEP 3: Upload to Vector Database ---
print(f"Seeding knowledge base to ChromaDB at {chroma_host}...")

for entry in knowledge_base:
    # We add each document one by one. Chroma handles the embedding automatically.
    collection.add(
        documents=[entry["text"]], # The actual text of the fake file
        metadatas=[entry["metadata"]], # Extra info about the file
        ids=[entry["id"]] # A unique ID so we don't add duplicates
    )

print("Successfully seeded 6 system documents into 'ssh_knowledge' collection.")
