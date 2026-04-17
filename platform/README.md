# Trinetra Platform — Deep Packet Inspection & Traffic Intelligence System

A full-stack network traffic analysis tool. Upload a PCAP file through a Streamlit UI, process it via a FastAPI backend, and get packet statistics powered by a compiled C++ binary.

---

## Project Structure

```
.
├── backend/
│   ├── main.py                  # FastAPI app — POST /analyze endpoint
│   ├── requirements.txt
│   └── services/
│       ├── runner.py            # Subprocess wrapper for the C++ binary
│       └── parser.py            # Reads and parses stats.json output
├── frontend/
│   ├── app.py                   # Streamlit UI
│   └── requirements.txt
└── bin/
    └── analyzer                 # Compiled C++ binary (you provide this)
```

---

## How It Works

1. User uploads a `.pcap` file in the Streamlit UI and clicks **Analyze**
2. The frontend POSTs the file to `POST /analyze` on the FastAPI backend
3. The backend saves the file to disk under `uploads/<job_id>/`
4. It invokes the C++ binary: `analyzer <input.pcap> <output.pcap> <stats.json>`
5. The binary writes `output.pcap` and `stats.json` to the job directory
6. The backend reads `stats.json` and returns it as a JSON response
7. The frontend renders packet metrics and application breakdown charts

---

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Runs on `http://localhost:8000`.

### Frontend

```bash
cd frontend
pip install -r requirements.txt
streamlit run app.py
```

Runs on `http://localhost:8501`.

### C++ Binary

Place your compiled binary at `bin/analyzer` relative to the backend working directory.

Expected call signature:

```
analyzer <input.pcap> <output.pcap> <stats.json>
```

The binary must exit with code `0` on success and write both output files.

---

## API

### `POST /analyze`

**Request:** `multipart/form-data` with a `.pcap` file field named `file`

**Response:**

```json
{
  "total_packets": 15000,
  "dropped_packets": 42,
  "application_breakdown": {
    "HTTP": 6200,
    "DNS": 3100,
    "TLS": 4800,
    "Other": 900
  }
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | File is not a `.pcap` |
| 500 | Binary not found, execution failed, or no output produced |

---

## stats.json Schema

The C++ binary is expected to produce a `stats.json` with at minimum:

```json
{
  "total_packets": <int>,
  "dropped_packets": <int>,
  "application_breakdown": {
    "<app_name>": <packet_count>,
    ...
  }
}
```

---

## Requirements

- Python 3.10+
- A compiled C++ binary placed at `bin/analyzer`
