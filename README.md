# SecPR-Benchmark

SecPR-Benchmark is a CLI tool designed to evaluate the effectiveness of AI-based and static security analyzers in detecting vulnerabilities in real-world historical commits. The tool runs a multi-phase pipeline that extracts ground truth vulnerability data from real commits, evaluates AI detection accuracy, compares it to SonarQube's output, and generates a comprehensive SQLite database and a basic html report.

## 📋 Features

- Automatically clones a target GitHub repository
- Extracts security-related fixes and traces original vulnerable commits (ground truth)
- Evaluates:

  - **AI-based vulnerability detection** using OpenAI GPT
  - **Static analysis results** using SonarQube REST API

- Outputs classification metrics (TP, FP, FN, SKIPPED)
- Generates a basic `report.html` with charts and tables
- Easily configurable and modular (run phases individually or end-to-end)

---

## ⚙️ Prerequisites

Before using SecPR-Benchmark, ensure you have:

- **Node.js** (>= 18)
- **SonarQube** instance (hosted or local)
- **`sonar-scanner`** installed and in PATH
- A **GitHub personal access token** with repo access
- An **OpenAI API key**

---

## 💾 Installation

```bash
git clone https://github.com/your-username/SecPR-Benchmark.git
cd SecPR-Benchmark
npm install
```

Create a `.env` file in the root directory:

```ini
GITHUB_TOKEN=your_github_token
OPENAI_API_KEY=your_openai_key
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=your_sonarqube_token
SONARQUBE_ORG=optional_org_key
DB_PATH=./data/security_analysis.db
```

---

## 🚀 Running the Full Pipeline

Use `main.js` to execute all four phases in sequence:

```bash
node src/main.js --repo "https://github.com/user/repo" --limit 50
```

### Optional Flags:

- `--repo` (required): GitHub repo URL
- `--limit`: Maximum number of recent commits to analyze (omit for all)

This runs:

1. Phase 1: Extracts ground truth vulnerabilities
2. Phase 2: Evaluates with AI (GPT)
3. Phase 3: Evaluates with SonarQube
4. Phase 4: Generates `report.html`

---

## 🔬 Running Phases Individually

### Phase 1: Ground Truth Extraction

```bash
node src/phase1.js --repo "https://github.com/user/repo" --limit 50
```

- Clones repo and finds security-related fixing commits
- Extracts associated original vulnerable commits
- Saves entries in `ground_truth` table in the SQLite DB

### Phase 2: AI Evaluation

```bash
node src/phase2.js
```

- For each `ground_truth` record, checks out the vulnerable commit
- Sends file content to GPT-4 to analyze
- Classifies each result (TP, FP, FN, SKIPPED) into `ai_results`

### Phase 3: SonarQube Evaluation

```bash
node src/phase3.js
```

- Analyzes each original commit with SonarQube
- Extracts issues via REST API and maps to CWEs
- Classifies against ground truth and stores in `sonarqube_results`

### Phase 4: Report Generation

```bash
node src/phase4.js
```

- Generates `report.html` in the root folder
- Includes:

  - Ground truth CWE frequencies
  - TP/FP/FN bars for both AI and SonarQube
  - Category donut chart (AI only)
  - Per-CWE breakdown for AI and SonarQube

**Note:** The generated HTML report is fairly basic and intended for quick review. For detailed data exploration, we recommend querying the SQLite database directly and building custom charts/graphs suited to your analysis needs.

---

## 📁 Output

### Database (`security_analysis.db`)

- `repository_info`: Tracked repo metadata
- `ground_truth`: Real-world vulnerability mappings
- `ai_results`: AI tool performance
- `sonarqube_results`: SonarQube performance

### HTML Report (`report.html`)

Located in the project root. Includes:

- CWE bar chart of ground truth
- TP/FP/FN comparison for AI vs SonarQube
- Donut chart by vulnerability type (AI only)
- CWE-specific TP/FP/FN/SKIPPED table

**Important:** While the HTML report provides useful insights, it is not exhaustive. Use the database for deeper or custom evaluations.

---

## 🧠 Use Cases

- Academic experiments and thesis work
- Benchmarking security tools
- Exploring AI performance in real-world commit analysis

---

## ⚠️ Limitations

- GPT-4 usage may incur cost and rate limits
- SonarQube results depend on the rule set and language support
- Works best on open-source repos with frequent security fixes

---

## 🤝 License

This project is licensed under the MIT License - see the LICENSE file for details.
