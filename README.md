# RAG-Enhanced SSH Honeypot

## What It Does
This project integrates the Cowrie SSH honeypot with a local LLM and RAG system to automatically analyze and classify SSH attack logs. It deceives attackers by providing dynamic, context-aware responses while collecting threat intelligence through ELK Stack logging.

## Why?
DIt provides automated threat analysis and detection engineering for mid-sized companies seeking lightweight, cost-effective defensive measures against automated reconnaissance attacks and AI-powered intrusion attempts.

## How It Works
- **Tech Stack**: Cowrie SSH honeypot + ELK Stack (Elasticsearch, Logstash, Kibana) + HuggingFace/LangChain RAG proxy with ChromaDB vector database
- **Architecture**: Attacker → SSH connection → Cowrie → RAG-LLM response → logs → ELK visualization → threat classification
- **Key Features**: 
  - Real-time log processing with JSON parsing into Elasticsearch
  - RAG-based contextual attack classification using vector retrieval
  - Local LLM execution (Qwen2.5-1.5B-Instruct, 4-bit quantization via BitsandBytesConfig)
  - Docker containerized deployment (GPU minimum: 2GB VRAM recommended)
  - Multi-message context retention in chromadb (last 6 messages)
  - Pre-seeded baseline context for consistent honeypot identity

## How to Run It

### Prerequisites
- **NVIDIA GPU** with 2GB+ dedicated VRAM (Install Nvidia Container toolkit)
- **8GB RAM** minimum, 16GB recommended
- **Docker**

### Deployment Steps
 **Step 1:** Build all containers
docker-compose up

**Step 2:** Initialize vector database with baseline context
docker exec -it rag-proxy python seed_db.py

**Step 3:** Verify ELK health (wait ~2 minutes for services to initialize)
curl http://localhost:5601/api/status

**Step 4:** Connect to honeypot
ssh -p 2222 root@localhost

### Testing
Generate test traffic with Expect script
chmod +x test_script.exp
./test_script.exp

Have fun and do not forget: This was a research project, so any use outside of research is your responsibility.

  
