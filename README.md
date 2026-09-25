
# CTI Security Intelligence Platform

A standalone and local-first intelligence platform designed to extract, enrich, and map Indicators of Compromise (IoCs) from unstructured Cyber Threat Intelligence (CTI) reports (Arabic/English). It features a trainable Conditional Random Fields (CRF) NER model, MITRE ATT&CK integration, STIX 2.1 exporting, and a dark CAD-styled Arabic web dashboard.

---

## 🚀 Key Features

* **Advanced NER Engine:** Powered by Conditional Random Fields (`sklearn-crfsuite`/lbfgs + Viterbi) combined with intelligence dictionaries and MITRE expressions.
* **Threat Enrichment:** Integrates with VirusTotal, AbuseIPDB, and AlienVault OTX, alongside a built-in offline fallback intelligence database.
* **MITRE ATT&CK Mapping:** Automatic indexing and mapping of attack techniques and tags.
* **Knowledge Graph Generation:** Visualizes relationships and co-occurrences between extracted entities (`co-occur`, `exploits`, `maps_to`).
* **STIX 2.1 Export:** Generates standardized STIX bundles (`indicators`, `malware`, `threat-actor`, `attack-pattern`).
* **Modern Web Dashboard:** A responsive dark-themed RTL Arabic dashboard featuring live extraction, evaluation metrics, and system health status.

---

## 🛠️ Project Structure

```text
cti-platform/
├── app/
│   ├── ner/            # CRF core, intel dictionaries, and patterns
│   ├── eval/           # Evaluation metrics and confusion matrices
│   ├── enrichment/     # VirusTotal, AbuseIPDB, OTX, and offline base
│   ├── mitre/          # ATT&CK technique index and tag mapping
│   ├── graph/          # Knowledge graph generator
│   └── stix/           # STIX 2.1 bundle exporter
├── web/                # Arabic frontend dashboard
├── tests/              # Automated test suite
├── data/               # Offline intelligence database
├── requirements.txt    # Project dependencies
└── run.py              # Main application launcher

```

---

## ⚙️ Installation & Setup (طريقة التثبيت)

Follow these steps to set up and run the platform locally on your machine:

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/cti-platform.git
cd cti-platform

```

### 2. Create and Activate a Virtual Environment (Python 3.11)

Run the following commands in your terminal to create a dedicated virtual environment:

```bash
py -3.11 -m venv .venv

```

Activate the virtual environment:

* **On Windows (PowerShell/CMD):**
```powershell
.\.venv\Scripts\Activate.ps1

```


* **On Linux/macOS:**
```bash
source .venv/bin/activate

```



### 3. Install Dependencies

Upgrade pip and install the required Python packages from `requirements.txt`:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

```

### 4. Configure Enrichment API Keys (Optional)

*Note: This step is completely optional. If keys are omitted, the platform will automatically fall back to the built-in offline intelligence database.*

* **On Windows (PowerShell):**
```powershell
$env:CTI_VT_KEY="your_virustotal_api_key"
$env:CTI_ABUSEIPDB_KEY="your_abuseipdb_api_key"
$env:CTI_OTX_KEY="your_otx_api_key"

```


* **On Linux/macOS:**
```bash
export CTI_VT_KEY="your_virustotal_api_key"
export CTI_ABUSEIPDB_KEY="your_abuseipdb_api_key"
export CTI_OTX_KEY="your_otx_api_key"

```



---

## 🚀 Running the Platform (طريقة التشغيل)

You can run the application using one of the following methods:

### Option A: Using the Launcher Script

```bash
python run.py

```

### Option B: Directly via Uvicorn

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8010

```

Once the server is up and running, open your browser and navigate to:
👉 **`http://localhost:8010`**

---

## 🧪 Running Tests

To verify that all modules, evaluation scripts, and REST endpoints are functioning correctly, run the automated test suite using pytest:

```bash
python -m pytest tests -q

```

---

## 📊 Performance & Evaluation

* **Training Corpus:** 304 generated records (including 270 annotated sentences with 573 annotated tokens and mixed multi-entity templates).
* **Test Corpus:** 142 real, unseen manual records.
* **CRF Model Performance:** Token Macro F1 = **0.868**, Span F1 = **0.804**.
* **Full Pipeline Performance (regex + CRF + dictionaries + MITRE):** Reaches an outstanding overall F1 score of **0.982**, with perfect 1.0 scores on `VULN`, `URL`, `CVE`, `EMAIL`, `DOMAIN`, `HASH`, and `TECHNIQUE`.

---

## 🛡️ License

This project is developed for academic and operational cybersecurity research. Feel free to fork and customize.
