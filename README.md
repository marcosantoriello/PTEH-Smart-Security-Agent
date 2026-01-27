# AI Security Agent: Automated Firewall Rule Generation using LLM and RAG

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
![Keywords](https://img.shields.io/badge/Keywords-Cybersecurity%20%7C%20AI%20%7C%20RAG%20%7C%20LLM%20%7C%20IDS-0078D4)
> **⚠️ EXPERIMENTAL RESEARCH PROJECT**  
> Developed as part of the "Penetration Testing and Ethical Hacking" course at University of Salerno, this project explores the feasibility of using Large Language Models for automated security policy generation.

## 📋 Table of Contents

- [AI Security Agent: Automated Firewall Rule Generation using LLM and RAG](#ai-security-agent-automated-firewall-rule-generation-using-llm-and-rag)
  - [📋 Table of Contents](#-table-of-contents)
  - [🎯 Overview](#-overview)
  - [🔬 Research Question](#-research-question)
  - [✨ Key Features](#-key-features)
  - [🏗️ Architecture](#️-architecture)
    - [Data Flow](#data-flow)
  - [🛠️ Technologies](#️-technologies)
  - [📊 Evaluation Results](#-evaluation-results)
  - [🚀 Getting Started](#-getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Deployment](#deployment)
  - [💻 Usage](#-usage)
    - [Run Simulated Attacks](#run-simulated-attacks)
    - [Monitor AI Agent Activity](#monitor-ai-agent-activity)
    - [Run Evaluation](#run-evaluation)
    - [Shutdown](#shutdown)
  - [🤝 Contributing](#-contributing)
    - [How to Contribute](#how-to-contribute)
    - [Contribution Guidelines](#contribution-guidelines)
    - [Areas for Improvement](#areas-for-improvement)
  - [⚠️ Limitations](#️-limitations)
  - [📄 License](#-license)
  - [🙏 Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

This project implements an **end-to-end AI-driven security automation system** that combines:
- **Anomaly-Based IDS**: A multiclass Random Forest classifier trained on CIC-IDS2017 dataset
- **AI Security Agent**: An LLM-powered agent (Llama 3) enhanced with Retrieval-Augmented Generation (RAG)
- **Dynamic Enforcement**: Automated firewall rule generation and application via iptables

Unlike traditional rule-based systems, this approach leverages the **reasoning capabilities of Large Language Models** to generate context-aware, semantically appropriate firewall rules in response to network intrusions detected in real-time.

## 🔬 Research Question

**"Can a Large Language Model, enhanced with Retrieval-Augmented Generation, automatically generate syntactically correct and semantically appropriate firewall rules in response to network attacks detected by an anomaly-based IDS? What accuracy can be achieved and what are the intrinsic limitations?"**

## ✨ Key Features

- **🤖 AI-Powered Rule Generation**: Uses Llama 3 LLM to translate attack classifications into iptables rules
- **📚 RAG Integration**: ChromaDB-based semantic retrieval of validated rule templates to improve consistency
- **🔍 Multiclass IDS**: Detects 14 different attack types (DoS, DDoS, Port Scan, SQL Injection, XSS, Brute Force, etc.)
- **🛡️ Multi-Layer Validation**: Triple validation (regex, sanitization, kernel-level) prevents malformed rules
- **🐳 Fully Containerized**: Docker Compose orchestration with network segmentation


## 🏗️ Architecture

The system consists of 7 containerized components across two isolated networks:

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXTERNAL NETWORK (172.20.0.0/24)            │
│  ┌─────────────────┐                                            │
│  │   Attacker      │  Metasploit Framework                      │
│  │   172.20.0.10   │                                            │
│  └────────┬────────┘                                            │
└───────────┼─────────────────────────────────────────────────────┘
            │
    ┌───────▼──────────────────────┐
    │  FIREWALL GATEWAY (Multi-NIC)│
    │  ┌──────────────────────────┐│
    │  │  Traffic Sniffer (Scapy) ││
    │  │  Firewall Enforcer       ││
    │  └──────────────────────────┘│
    │  eth0: .2  │  eth1: .5       │
    └────────────┼─────────────────┘
                 │
┌────────────────┼────────────────────────────────────────────────┐
│                │     INTERNAL NETWORK (172.21.0.0/24)           │
│   ┌────────────▼──────────┐    ┌──────────────────┐             │
│   │  Feature Extractor    │───▶│     Redis        │             │
│   │  NTLFlowLyzer :5001   │    │     :6379        │             │
│   └───────────────────────┘    └─────────┬────────┘             │
│                                          │                      │
│   ┌───────────────────────┐              │                      │
│   │  IDS Module           │◀─────────────┤                      │
│   │  Random Forest        │              │                      │
│   └───────────────────────┘              │                      │
│                                          │                      │
│   ┌───────────────────────┐              │                      │
│   │  AI Security Agent    │◀─────────────┤                      │
│   │  Llama 3 + ChromaDB   │              │                      │
│   └───────────────────────┘              │                      │
│                                          │                      │
│   ┌───────────────────────┐              │                      │
│   │  DVWA Target          │◀─────────────┘                      │
│   │  172.21.0.10          │                                     │
│   └───────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Traffic Capture**: Sniffer captures packets on eth0, batches into PCAP files
2. **Feature Extraction**: NTLFlowLyzer processes PCAPs → statistical features → Redis
3. **Detection**: IDS polls Redis, classifies flows (15 classes), saves predictions
4. **Rule Generation**: AI Agent polls attacks from Redis, retrieves RAG template, generates iptables rule
5. **Enforcement**: Firewall Enforcer validates and applies rule via kernel

## 🛠️ Technologies

| Component | Technology |
|-----------|-----------|
| **IDS Classifier** | Random Forest (scikit-learn), CIC-IDS2017 dataset |
| **LLM** | Llama 3 (via Ollama) |
| **RAG Database** | ChromaDB (sentence-transformers embeddings) |
| **Feature Extraction** | NTLFlowLyzer |
| **Traffic Capture** | Scapy |
| **Database** | Redis (Sorted Sets for temporal indexing) |
| **Firewall rules** | iptables |
| **Orchestration** | Docker Compose |
| **Target Application** | DVWA (Damn Vulnerable Web Application) |
| **Attack Framework** | Metasploit Framework |

## 📊 Evaluation Results

The AI Agent was evaluated on **2,578 generated rules** across 3 attack types:

| Attack Type | Correct | Wrong | Total | Accuracy |
|-------------|---------|-------|-------|----------|
| **Port_Scan** | 934 | 89 | 1023 | **91.30%** |
| **DDoS_LOIT** | 1554 | 0 | 1554 | **100.00%** |
| **DoS_Hulk** | 1 | 0 | 1 | **100.00%** |
| **OVERALL** | **2489** | **89** | **2578** | **96.55%** |

## 🚀 Getting Started

### Prerequisites

- **Docker Engine** ≥ 20.10
- **Docker Compose** ≥ 2.0
- **Ollama** with Llama 3 model installed on host
- **Git**

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/marcosantoriello/PTEH-Smart-IDS-Firewall-Agent.git
cd ./PTEH-Smart-IDS-Firewall-Agent
```

**2. Install and configure Ollama**

```bash
# Download and Install Ollama
https://ollama.com/download


# Pull Llama 3 model
ollama pull llama3

# Start Ollama server
ollama serve
```

**3. Setup NTLFlowLyzer and fix a typo (required)**

```bash
cd architecture/feature-extractor/libs/NTLFlowLyzer
git checkout v0.1.0

# Apply fix automatically
sed -i 's/NLFlowLyzer/NTLFlowLyzer/g' NTLFlowLyzer/__init__.py

cd ../../../../
```

### Deployment

**Start the infrastructure**

```bash
docker compose up --build
```

**Verify all containers are running**

```bash
docker compose ps
```

Expected output: All services in `running` state.

**Check logs**

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f ai-agent
docker compose logs -f ids-module
```

## 💻 Usage

### Run Simulated Attacks

Access the attacker container:

```bash
docker exec -it attacker bash
```

Example Port Scan:

```bash
nmap -T4 172.21.0.10
```

### Monitor AI Agent Activity

```bash
# View generated rules
docker compose logs ai-agent | grep "Generated rule"

# View firewall rules applied
curl http://172.21.0.5:5002/list-rules
```

### Run Evaluation

```bash
cd evaluation
python evaluator.py
```

Generates `evaluation_results.json` with accuracy metrics.

### Shutdown

```bash
# Stop containers
docker compose down

# Remove volumes (clean slate)
docker compose down -v
```

## 🤝 Contributing

Contributions are welcome and improvements are appreciated.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-improvement`)
3. **Commit your changes** (`git commit -m 'Add RAG optimization'`)
4. **Push to the branch** (`git push origin feature/amazing-improvement`)
5. **Open a Pull Request**

### Contribution Guidelines

- Follow existing code structure and naming conventions
- Add unit tests for new components
- Update documentation for API changes
- Run evaluation framework to verify no regression
- Cite relevant papers if implementing research-based features

### Areas for Improvement

- [ ] Support for additional attack types (currently 14)
- [ ] Implement a better IDS model
- [ ] Fine-tuning Llama 3 on firewall rule dataset
- [ ] Implement rule deduplication mechanism
- [ ] Human-in-the-loop approval workflow
- [ ] Extend RAG knowledge base with edge cases and experience

## ⚠️ Limitations

This is a **proof-of-concept research project** with known limitations:

1. **Non-determinism**: LLMs are probabilistic; slight output variation is expected
2. **Limited attack coverage**: Evaluation covers only 3/14 attack types
3. **No rule deduplication**: Continuous attacks generate redundant rules (by design for evaluation)
4. **Single-target scenario**: Not tested in multi-target enterprise environments
5. **ChromaDB single-node**: RAG database not distributed
6. **No adversarial testing**: Resilience to prompt injection or model poisoning not evaluated

**⚠️ DO NOT DEPLOY IN PRODUCTION ENVIRONMENTS**  
This system is designed for research and educational purposes only.

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [**CIC-IDS2017 Dataset**](https://www.unb.ca/cic/datasets/ids-2017.html): Canadian Institute for Cybersecurity, University of New Brunswick
- [**NTLFlowLyzer**](https://github.com/ahlashkari/NTLFlowLyzer/tree/master): Network Traffic Flow Analysis tool


---


**Author**: Marco Santoriello  

---
