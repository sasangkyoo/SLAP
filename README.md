# SLAP Inspector Agent v1.0

The **SLAP (Structure, Loading, Access Protection) Inspector** is an automated reconnaissance tool for web scrapers. It analyzes target websites to determine crawlability difficulty, providing actionable strategies and technical insights.

## 🚀 Features

* **S-Axis (Structure):** Detects CSR (Client-Side Rendering), SSR (Server-Side Rendering), and Virtualization/Infinite Scroll patterns
* **L-Axis (Loading):** Analyzes network traffic to identify APIs, GraphQL endpoints, and JSON data sources
* **AP-Axis (Access Protection):** Detects Auth walls (401/403), Rate Limiting (429), CAPTCHAs, Login pages, and Soft Blocks
* **Strategy Generator:** Provides deterministic, priority-based advice (e.g., "Use Headless Browser", "Reverse-Engineer API", "Requires CAPTCHA Solver")
* **🤖 AI-Powered Code Generation (MVP-7):** Uses GPT-4o-mini to generate executive summaries and ready-to-use Playwright code snippets tailored to detected obstacles
* **Dual Mode:** Supports both Single URL Inspection (with HTML report) and Batch CSV Processing
* **Evidence-Based:** All classifications backed by concrete metrics and traceable evidence
* **Traffic Light System:** Visual color-coded difficulty tiers (Green/Yellow/Orange/Red)

## 🛠️ Installation

1. **Clone & Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Playwright Browsers:**
   ```bash
   playwright install chromium
   ```

## 📖 Usage

### 1. Single Site Inspection
Generates a detailed HTML report and rich JSON data for a single URL.

```bash
python slap_agent.py https://news.ycombinator.com
```

**Output:**
- `runs/{timestamp}/report/index.html` - Visual HTML report with strategy guidance
- `runs/{timestamp}/result/` - JSON files (html_stats.json, network_summary.json, dom_diff.json, ap_signals.json, labels.json, score.json)
- `runs/{timestamp}/raw/` - Raw data (initial.html, network_requests.jsonl, dom_snapshots/)

### 2. Batch Processing
Analyzes multiple sites from a CSV file and generates a consolidated JSON summary.

**Prepare `dataset.csv` with URL column header:**
```csv
url
https://news.ycombinator.com
https://github.com/login
https://www.reddit.com
```

**Run the batch agent:**
```bash
python batch_runner.py dataset.csv
```

**Output:** `batch_results.json`
```json
[
  {
    "url": "https://news.ycombinator.com",
    "timestamp": "2025-12-23T17:10:00",
    "status": "success",
    "tier": "EASY",
    "score": 6,
    "strategy": "SUCCESS: Standard HTTP requests with HTML parsing should work.",
    "drivers": ["S-SSR"]
  },
  {
    "url": "https://broken-site.com",
    "status": "error",
    "error_msg": "TimeoutError: Navigation timeout"
  }
]
```

## 📊 Output Explanation

### Score (0-100)
Higher scores indicate greater scraping difficulty. Calculated using weighted formula:
```
Total Score = (AP × 0.5) + (S × 0.3) + (L × 0.2)
```

### Difficulty Tiers

- **🟢 EASY (0-20):** Static/SSR sites with no protection. Standard HTTP requests work.
- **🟡 MEDIUM (21-50):** CSR/API-driven sites. May need headless browser or API reverse-engineering.
- **🟠 HARD (51-80):** Virtualized rendering or rate-limited. Requires complex logic.
- **🔴 HELL (81+):** CAPTCHA or hard auth walls. Commercial solvers or valid credentials required.

### Strategy Messages

The agent provides deterministic advice based on detected patterns (priority order):

1. **ABORT (🚫):** CAPTCHA/Auth detected → Commercial solver or credentials required
2. **WARN (⚠️):** Virtualized DOM → Reverse-engineer JSON API, visual scraping will fail
3. **CAUTION (⚡):** Rate limits/Bot detection → Use exponential backoff and rotation
4. **INFO (ℹ️):** CSR detected → Headless browser needed, wait for hydration
5. **SUCCESS (✅):** No major obstacles → Standard parsing works

## 📂 Project Structure

```
├── slap_agent.py          # Core Analysis Engine (All 7 MVPs)
├── batch_runner.py        # Batch Processing Wrapper
├── requirements.txt       # Python Dependencies
├── dataset.csv            # Input CSV for batch mode (url column)
├── runs/                  # Output directory for single-run reports
│   └── {timestamp}/
│       ├── report/index.html   # Visual HTML report
│       ├── result/             # Analysis JSONs
│       └── raw/                # Raw captured data
└── batch_results.json     # Batch processing output (generated)
```

## 🤖 AI-Powered Code Generation (MVP-7)

The SLAP Agent can optionally generate **custom Playwright code** tailored to the specific obstacles detected on each site.

### Setup

Set your OpenAI API key as an environment variable:

**Windows:**
```cmd
setx OPENAI_API_KEY "your-api-key-here"
```

**Linux/Mac:**
```bash
export OPENAI_API_KEY="your-api-key-here"
```

Then restart your terminal and run the agent normally. The AI Blueprint section will appear in the HTML report.

### What It Generates

- **Executive Summary:** 2-3 sentence analysis of the scraping approach
- **Ready-to-Use Code:** Production-ready Playwright snippet that:
  - Handles detected obstacles (CSR, virtualization, rate limits, etc.)
  - Includes proper wait strategies if needed
  - Shows API interception for GraphQL/API patterns
  - Adds rate limiting protection
  - Is copy-paste ready with minimal modifications

### Cost Efficiency

Uses **GPT-4o-mini** exclusively (~$0.15 per 1M input tokens, ~$0.60 per 1M output tokens):
- Single site: ~$0.001 per report
- Batch (50 URLs): ~$0.05 total
- Cost-effective enough for large-scale analysis

### Fail-Safe Design

If no API key is found, the agent skips AI generation gracefully and produces the standard MVP-6 report.

---

## 🔬 Technical Details

### MVPs (Minimum Viable Products)

The SLAP Agent implements 7 complete MVPs:

1. **MVP-1:** HTML Snapshot & Basic Stats Collector
2. **MVP-2:** Network Traffic & API Detector
3. **MVP-3:** DOM Diff & Scroll Simulator
4. **MVP-4:** Access Protection Decision Engine
5. **MVP-5:** SLAP Scoring & Labeling Engine
6. **MVP-6:** Human-Readable HTML Report Generator
7. **MVP-7:** AI-Powered Code Generation (GPT-4o-mini)

### Evidence Sources

- **HTTP Status Codes:** 200, 401, 403, 429 detection
- **HTML Structure:** Root div, text ratio, semantic tags, CAPTCHA keywords
- **Network Patterns:** XHR/Fetch count, GraphQL detection, JSON ratio
- **DOM Timeline:** t0 (server), t1 (hydrated), t2 (scrolled) node counts
- **Growth Metrics:** Hydration growth, scroll growth, virtualization detection

### Single-Session Constraint

All analysis occurs in a **single browser session** (~12-15 seconds per site):
- Capture initial HTML (t0)
- Attach network listeners
- Navigate and wait 2s for hydration (t1)
- Perform incremental scroll simulation (t2)
- Analyze all evidence and generate reports

No multi-session polling or delayed checks.

## 🎯 Use Cases

1. **Pre-Scraping Reconnaissance:** Assess difficulty before building scrapers
2. **Batch Site Analysis:** Evaluate hundreds of targets quickly
3. **Strategy Planning:** Get concrete technical recommendations
4. **Team Communication:** Share HTML reports with stakeholders
5. **Monitoring:** Track site changes that affect crawlability

## ⚙️ Configuration

The agent uses hardcoded, production-tested heuristics. No configuration needed.

Key thresholds (see source code for details):
- Text ratio > 0.05 for SSR detection
- Hydration growth > 0.2 for CSR confirmation
- Scroll growth > 0.1 for infinite scroll detection
- XHR count > 5 + JSON ratio > 0.5 for API classification

## 🐛 Troubleshooting

**Error: "Executable doesn't exist at..."**
```bash
playwright install chromium
```

**CSV Error: "KeyError: 'url'"**
- Ensure CSV has header row with `url` column

**Timeout Errors:**
- Some sites may timeout (default 30s). This is expected for very slow or blocked sites.
- Batch mode handles errors gracefully and continues processing.

## 📄 License

MIT License - Use freely for commercial or personal projects.

## 🙏 Credits

- Playwright (browser automation)
- BeautifulSoup4 (HTML parsing)
- TailwindCSS (report styling)

---

**Version:** 1.0  
**Last Updated:** December 2025  
**Status:** Production-Ready ✅

