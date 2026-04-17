# Trinetra — Deep Packet Inspection & Traffic Intelligence System

Trinetra is a full-stack network traffic analysis platform. It combines a high-performance C++ DPI engine with a Python-based web platform — upload a PCAP file through a browser UI, process it through the engine, and get detailed traffic statistics and application breakdowns.

---

## Table of Contents

1. [What is Trinetra?](#1-what-is-trinetra)
2. [Project Structure](#2-project-structure)
3. [System Architecture](#3-system-architecture)
4. [Networking Background](#4-networking-background)
5. [The DPI Engine (C++)](#5-the-dpi-engine-c)
   - [Simple Version](#51-simple-version-single-threaded)
   - [Multi-threaded Version](#52-multi-threaded-version)
   - [Component Deep Dive](#53-component-deep-dive)
   - [SNI Extraction](#54-how-sni-extraction-works)
   - [Blocking Rules](#55-how-blocking-works)
6. [The Platform (Python)](#6-the-platform-python)
   - [Backend (FastAPI)](#61-backend-fastapi)
   - [Frontend (Streamlit)](#62-frontend-streamlit)
   - [API Reference](#63-api-reference)
7. [Building & Running](#7-building--running)
   - [Build the Engine](#71-build-the-engine)
   - [Run the Backend](#72-run-the-backend)
   - [Run the Frontend](#73-run-the-frontend)
8. [Understanding the Output](#8-understanding-the-output)
9. [Extending the Project](#9-extending-the-project)

---

## 1. What is Trinetra?

**Trinetra** (Sanskrit for "three eyes") is a DPI-based traffic analysis system. It inspects network packets at the application layer — identifying which apps and domains are generating traffic — and can selectively block flows based on configurable rules.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Trinetra System                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Streamlit   │───►│   FastAPI    │───►│   C++ DPI Engine │  │
│  │  Frontend    │    │   Backend    │    │   (dpi_engine)   │  │
│  │  :8501       │◄───│   :8000      │◄───│                  │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                                                                 │
│  User uploads PCAP → Engine analyzes → Results shown in UI     │
└─────────────────────────────────────────────────────────────────┘
```

### What it does:
- Parses raw PCAP captures (Wireshark/tcpdump format)
- Identifies applications: YouTube, Facebook, Google, DNS, etc.
- Extracts domain names from TLS SNI and HTTP Host headers
- Blocks traffic flows based on IP, app type, or domain rules
- Exposes results via REST API and a browser dashboard

---

## 2. Project Structure

```
trinetra/
├── engine/                         # C++ DPI Engine
│   ├── include/                    # Header files
│   │   ├── pcap_reader.h           # PCAP file reading
│   │   ├── packet_parser.h         # Protocol parsing (Ethernet/IP/TCP/UDP)
│   │   ├── sni_extractor.h         # TLS SNI + HTTP Host extraction
│   │   ├── types.h                 # FiveTuple, AppType, Flow structs
│   │   ├── rule_manager.h          # Blocking rules
│   │   ├── connection_tracker.h    # Flow state tracking
│   │   ├── load_balancer.h         # LB thread (multi-threaded)
│   │   ├── fast_path.h             # FP thread (multi-threaded)
│   │   ├── thread_safe_queue.h     # Thread-safe queue
│   │   └── dpi_engine.h            # Main orchestrator
│   ├── src/                        # Implementation files
│   │   ├── main_working.cpp        # ★ Simple single-threaded entry point
│   │   ├── dpi_mt.cpp              # ★ Multi-threaded entry point
│   │   ├── pcap_reader.cpp
│   │   ├── packet_parser.cpp
│   │   ├── sni_extractor.cpp
│   │   ├── types.cpp
│   │   ├── connection_tracker.cpp
│   │   ├── load_balancer.cpp
│   │   ├── fast_path.cpp
│   │   └── rule_manager.cpp
│   ├── CMakeLists.txt
│   ├── generate_test_pcap.py       # Generates test PCAP data
│   └── test_dpi.pcap               # Sample capture file
│
├── platform/                       # Python Web Platform
│   ├── backend/
│   │   ├── main.py                 # FastAPI app — POST /analyze
│   │   ├── requirements.txt
│   │   └── services/
│   │       ├── runner.py           # Subprocess wrapper for C++ binary
│   │       └── parser.py           # Reads and parses stats.json
│   └── frontend/
│       ├── app.py                  # Streamlit UI
│       └── requirements.txt
│
└── README.md                       # This file
```

---

## 3. System Architecture

### End-to-End Flow

```
User (Browser)
     │
     │  Upload .pcap file
     ▼
┌─────────────────────┐
│  Streamlit Frontend │  (platform/frontend/app.py)
│  localhost:8501     │
└──────────┬──────────┘
           │  POST /analyze  (multipart/form-data)
           ▼
┌─────────────────────┐
│  FastAPI Backend    │  (platform/backend/main.py)
│  localhost:8000     │
│                     │
│  1. Save to disk    │
│  2. Invoke binary   │
│  3. Read stats.json │
└──────────┬──────────┘
           │  subprocess call
           ▼
┌─────────────────────────────────────────────────────┐
│  C++ DPI Engine  (engine/dpi_engine)                │
│                                                     │
│  input.pcap → [Parse → Classify → Block] → output.pcap  │
│                              ↓                      │
│                         stats.json                  │
└─────────────────────────────────────────────────────┘
           │
           │  JSON response
           ▼
┌─────────────────────┐
│  Streamlit Frontend │  Renders metrics + bar chart
└─────────────────────┘
```

---

## 4. Networking Background

### The Network Stack

```
┌──────────────────────────────────────────────┐
│ Layer 7: Application  │ HTTP, TLS, DNS        │
├──────────────────────────────────────────────┤
│ Layer 4: Transport    │ TCP (reliable), UDP   │
├──────────────────────────────────────────────┤
│ Layer 3: Network      │ IP addresses          │
├──────────────────────────────────────────────┤
│ Layer 2: Data Link    │ MAC addresses         │
└──────────────────────────────────────────────┘
```

### Packet Structure

Every packet is a nested set of headers:

```
┌─────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                          │
│  ┌───────────────────────────────────────────────┐  │
│  │ IP Header (20 bytes)                          │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │ TCP Header (20 bytes)                   │  │  │
│  │  │  ┌───────────────────────────────────┐  │  │  │
│  │  │  │ Payload (TLS Client Hello, etc.)  │  │  │  │
│  │  │  └───────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### The Five-Tuple

A connection (flow) is uniquely identified by:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's app identifier |
| Destination Port | 443 | Service (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

All packets sharing the same five-tuple belong to the same connection.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS handshake. When your browser connects to `https://www.youtube.com`, it sends a Client Hello containing the domain name **in plaintext** — before encryption begins. This is the key to DPI: even HTTPS traffic leaks the destination domain in the first packet.

```
TLS Client Hello:
└── Extensions:
    └── SNI Extension (type 0x0000):
        └── Server Name: "www.youtube.com"  ← extracted here
```

---

## 5. The DPI Engine (C++)

### 5.1 Simple Version (Single-threaded)

`src/main_working.cpp` — best for learning and small captures.

**Packet journey:**

```
Read PCAP → Parse Headers → Create Five-Tuple → Look Up Flow
    → Extract SNI → Classify App → Check Rules → Forward or Drop
```

1. **Read PCAP** — `PcapReader` opens the file, validates the 24-byte global header, then reads packets one by one (16-byte packet header + variable data).

2. **Parse Headers** — `PacketParser::parse()` extracts Ethernet → IP → TCP/UDP fields. Uses `ntohs()`/`ntohl()` to handle network byte order.

3. **Flow Lookup** — A hash map `FiveTuple → Flow` tracks connection state. New five-tuples create new flows; existing ones update the same flow.

4. **SNI Extraction** — For port 443 traffic, `SNIExtractor::extract()` parses the TLS Client Hello and pulls the hostname. For port 80, `HTTPHostExtractor` reads the `Host:` header.

5. **App Classification** — `sniToAppType()` maps the SNI string to an `AppType` enum (YOUTUBE, FACEBOOK, GOOGLE, etc.).

6. **Blocking** — `RuleManager::isBlocked()` checks source IP, app type, and domain substring against configured rules.

7. **Output** — Non-blocked packets are written to the output PCAP. Stats are accumulated and printed at the end.

---

### 5.2 Multi-threaded Version

`src/dpi_mt.cpp` — production-grade, scales with CPU cores.

```
Reader Thread
     │
     │  hash(5-tuple) % num_lbs
     ▼
┌─────────┐   ┌─────────┐
│  LB 0   │   │  LB 1   │   Load Balancer threads
└────┬────┘   └────┬────┘
     │              │
     │ hash % fps   │ hash % fps
     ▼              ▼
┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
│ FP 0 │ │ FP 1 │ │ FP 2 │ │ FP 3 │   Fast Path threads
└──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘
   └────────┴────────┴────────┘
                  │
                  ▼
          Output Queue → Writer Thread → output.pcap
```

**Why consistent hashing?**
The same five-tuple always routes to the same Fast Path thread. This means all packets of a connection are processed by one thread — no locking needed on the flow table.

**Thread-Safe Queue** (`thread_safe_queue.h`):
```cpp
void push(T item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(item);
    not_empty_.notify_one();
}

T pop() {
    std::unique_lock<std::mutex> lock(mutex_);
    not_empty_.wait(lock, [&]{ return !queue_.empty(); });
    T item = queue_.front(); queue_.pop();
    return item;
}
```

---

### 5.3 Component Deep Dive

| Component | File | Responsibility |
|-----------|------|----------------|
| `PcapReader` | `pcap_reader.cpp` | Read PCAP global header + packet records |
| `PacketParser` | `packet_parser.cpp` | Parse Ethernet / IP / TCP / UDP headers |
| `SNIExtractor` | `sni_extractor.cpp` | Extract hostname from TLS Client Hello |
| `RuleManager` | `rule_manager.cpp` | Evaluate block rules (IP / app / domain) |
| `ConnectionTracker` | `connection_tracker.cpp` | Maintain per-flow state |
| `LoadBalancer` | `load_balancer.cpp` | Distribute packets to Fast Path threads |
| `FastPath` | `fast_path.cpp` | Classify + block + forward packets |
| `TSQueue<T>` | `thread_safe_queue.h` | Mutex + condvar bounded queue |

**Key data structures (`types.h`):**

```cpp
struct FiveTuple {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  protocol;
};

enum class AppType {
    UNKNOWN, HTTP, HTTPS, DNS,
    GOOGLE, YOUTUBE, FACEBOOK, ...
};
```

---

### 5.4 How SNI Extraction Works

TLS Client Hello layout (simplified):

```
[0]     Content Type  = 0x16 (Handshake)
[1-2]   TLS Version
[3-4]   Record Length
[5]     Handshake Type = 0x01 (Client Hello)
[6-8]   Handshake Length
[9-10]  Client Version
[11-42] Random (32 bytes)
[43]    Session ID Length → skip
...     Cipher Suites    → skip
...     Compression      → skip
...     Extensions:
          Type 0x0000 (SNI):
            SNI List Length
            SNI Type = 0x00
            SNI Length
            SNI Value → "www.youtube.com"  ← extracted
```

The extractor walks the extensions list until it finds type `0x0000`, then reads the hostname string directly from the bytes.

---

### 5.5 How Blocking Works

Rules are evaluated in order:

```
Is source IP blocked?       → DROP
Is app type blocked?        → DROP
Does SNI match blocked domain? → DROP
Otherwise                   → FORWARD
```

Blocking is **flow-based**: once a flow is marked blocked (after SNI is seen), all subsequent packets of that connection are dropped — even before the SNI appears again.

```
Packet 1 (SYN)          → no SNI yet → FORWARD
Packet 2 (Client Hello) → SNI: youtube.com → BLOCKED → DROP
Packet 3 (Data)         → flow already blocked → DROP
```

---

## 6. The Platform (Python)

### 6.1 Backend (FastAPI)

`platform/backend/main.py`

**Single endpoint:** `POST /analyze`

Flow:
1. Validate the uploaded file is `.pcap`
2. Create a unique job directory under `jobs/<uuid>/`
3. Save the uploaded file as `input.pcap`
4. Call `runner.run_analysis()` → invokes `../../engine/dpi_engine.exe`
5. Read `stats.json` via `parser.load_stats()`
6. Return JSON response

**runner.py** wraps the binary call:
```python
BINARY_PATH = Path("../../engine/dpi_engine.exe")

cmd = [str(BINARY_PATH), input_path, output_path, stats_path]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
```

**parser.py** reads the output:
```python
def load_stats(stats_path: Path) -> dict:
    with open(stats_path) as f:
        return json.load(f)
```

---

### 6.2 Frontend (Streamlit)

`platform/frontend/app.py`

- File uploader (`.pcap` only)
- "Analyze" button → POSTs to `http://localhost:8000/analyze`
- Displays:
  - `Total Packets` metric
  - `Dropped Packets` metric
  - `Application Breakdown` bar chart

---

### 6.3 API Reference

#### `POST /analyze`

**Request:** `multipart/form-data`

| Field | Type | Description |
|-------|------|-------------|
| `file` | `.pcap` file | Network capture to analyze |

**Response (200):**
```json
{
  "total_packets": 15000,
  "dropped_packets": 42,
  "application_breakdown": {
    "YouTube": 4200,
    "DNS": 3100,
    "HTTPS": 6800,
    "Unknown": 900
  }
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | File is not a `.pcap` |
| 500 | Binary not found, execution failed, or `stats.json` not produced |

#### `stats.json` Schema (produced by the engine)

```json
{
  "total_packets": 15000,
  "dropped_packets": 42,
  "application_breakdown": {
    "<app_name>": <packet_count>
  }
}
```

---

## 7. Building & Running

### Prerequisites

- C++17 compiler (`g++` or `clang++`)
- Python 3.10+
- `pthread` support (Linux/macOS) or equivalent on Windows

---

### 7.1 Build the Engine

**Simple version:**
```bash
g++ -std=c++17 -O2 -I engine/include -o engine/dpi_simple \
    engine/src/main_working.cpp \
    engine/src/pcap_reader.cpp \
    engine/src/packet_parser.cpp \
    engine/src/sni_extractor.cpp \
    engine/src/types.cpp
```

**Multi-threaded version:**
```bash
g++ -std=c++17 -pthread -O2 -I engine/include -o engine/dpi_engine \
    engine/src/dpi_mt.cpp \
    engine/src/pcap_reader.cpp \
    engine/src/packet_parser.cpp \
    engine/src/sni_extractor.cpp \
    engine/src/types.cpp \
    engine/src/connection_tracker.cpp \
    engine/src/load_balancer.cpp \
    engine/src/fast_path.cpp \
    engine/src/rule_manager.cpp
```

**Or use CMake:**
```bash
cmake -S engine -B engine/build
cmake --build engine/build
```

**Run the engine directly:**
```bash
# Basic
./engine/dpi_engine engine/test_dpi.pcap output.pcap

# With blocking rules
./engine/dpi_engine engine/test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook

# Configure thread counts
./engine/dpi_engine input.pcap output.pcap --lbs 2 --fps 4
```

**Generate test data:**
```bash
python3 engine/generate_test_pcap.py
```

---

### 7.2 Run the Backend

```bash
cd platform/backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Runs on `http://localhost:8000`.

> The backend expects the compiled binary at `../../engine/dpi_engine.exe` relative to the backend directory (i.e., `engine/dpi_engine.exe` from the repo root). Adjust `BINARY_PATH` in `runner.py` if needed.

---

### 7.3 Run the Frontend

```bash
cd platform/frontend
pip install -r requirements.txt
streamlit run app.py
```

Runs on `http://localhost:8501`. Open in your browser, upload a `.pcap` file, and click **Analyze**.

---

## 8. Understanding the Output

### Engine Console Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Forwarded:                    69                             ║
║ Dropped:                       8                             ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS          39  50.6% ##########                          ║
║ YouTube         4   5.2% # (BLOCKED)                         ║
║ DNS             4   5.2% #                                   ║
║ Facebook        3   3.9%                                     ║
╚══════════════════════════════════════════════════════════════╝

[Detected SNIs]
  - www.youtube.com  → YouTube
  - www.facebook.com → Facebook
  - www.google.com   → Google
```

### Platform UI

The Streamlit dashboard shows:
- **Total Packets** and **Dropped Packets** as metric cards
- **Application Breakdown** as an interactive bar chart

---

## 9. Extending the Project

**Add more app signatures** (`engine/src/types.cpp`):
```cpp
if (sni.find("twitch") != std::string::npos)
    return AppType::TWITCH;
```

**Add bandwidth throttling:**
```cpp
if (shouldThrottle(flow)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}
```

**Add more API endpoints** (`platform/backend/main.py`):
```python
@app.get("/jobs/{job_id}/output")
async def download_output(job_id: str):
    # Return filtered output.pcap as file download
    ...
```

**Add live stats** — a separate thread printing metrics every second, or a WebSocket endpoint streaming results to the frontend.

---

## Requirements Summary

| Component | Requirement |
|-----------|-------------|
| Engine | C++17, `g++`/`clang++`, `pthread` |
| Backend | Python 3.10+, FastAPI, uvicorn, python-multipart |
| Frontend | Python 3.10+, Streamlit, requests |
| Test data | Python 3 + `generate_test_pcap.py` |
