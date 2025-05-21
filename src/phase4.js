import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, "../data/security_analysis.db");
const outputPath = path.join(__dirname, "../report.html");

const db = new Database(dbPath);

/**
 * Counts the number of occurrences for each unique value of the specified key in the data rows.
 * @param {Array<object>} rows - Array of data rows.
 * @param {string} key - Key to group by.
 * @returns {Object} Object where keys are unique values and values are counts.
 */
function countByCategory(rows, key) {
  return rows.reduce((acc, row) => {
    acc[row[key]] = (acc[row[key]] || 0) + 1;
    return acc;
  }, {});
}

/**
 * Counts TP, FP, FN, and SKIPPED results grouped by CWE ID.
 * @param {Array<object>} rows - Array of evaluation result rows.
 * @returns {Object} Object with CWE IDs as keys and result breakdowns as values.
 */
function countMatchesByCWE(rows) {
  const result = {};
  for (const row of rows) {
    const key = row.cwe_id || "UNKNOWN";
    result[key] = result[key] || { TP: 0, FP: 0, FN: 0, SKIPPED: 0 };
    result[key][row.evaluation_result]++;
  }
  return result;
}

/**
 * Generates an HTML report summarizing ground truth and evaluation results.
 * Includes charts and tables for CWE breakdowns and performance stats.
 * @param {number} gtTotal - Total number of ground truth vulnerabilities.
 * @param {Object} groundTruthCounts - Counts of CWEs in ground truth.
 * @param {Object} aiStats - Evaluation results for AI-based tool.
 * @param {Object} sonarStats - Evaluation results for SonarQube.
 * @param {Object} categories - Vulnerability type distribution.
 * @param {Object} cweBreakdown - Unused in current implementation (placeholder).
 * @param {string} aiTableRows - HTML rows for AI-based CWE evaluation.
 * @param {string} sonarTableRows - HTML rows for SonarQube CWE evaluation.
 * @returns {string} Full HTML report content.
 */
function generateHTMLReport(
  gtTotal,
  groundTruthCounts,
  aiStats,
  sonarStats,
  categories,
  cweBreakdown,
  aiTableRows,
  sonarTableRows
) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Tool Benchmark Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: sans-serif; padding: 2rem; }
    canvas { max-width: 500px; margin-bottom: 3rem; }
    table { border-collapse: collapse; width: 100%; margin-top: 2rem; }
    th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; }
    th { background: #f0f0f0; }
    h2 { margin-top: 3rem; }
    .chart-container { display: flex; flex-wrap: wrap; gap: 2rem; }
  </style>
</head>
<body>
  <h1>Security Tool Benchmark Report</h1>
  <p><strong>Total Ground Truth Vulnerabilities:</strong> ${gtTotal}</p>

  <h2>Ground Truth Vulnerabilities by CWE</h2>
  <canvas id="gtChart"></canvas>
  <table>
    <thead><tr><th>CWE</th><th>Count</th></tr></thead>
    <tbody>
      ${Object.entries(groundTruthCounts)
        .map(([cwe, count]) => `<tr><td>${cwe}</td><td>${count}</td></tr>`)
        .join("")}
    </tbody>
  </table>

  <h2>True Positives / False Positives / False Negatives</h2>
  <canvas id="evaluationChart"></canvas>

  <h2>Vulnerability Types Evaluated (AI-based)</h2>
  <canvas id="categoryChart"></canvas>

  <h2>CWE-Level Performance (AI)</h2>
  <table>
    <thead><tr><th>CWE</th><th>TP</th><th>FP</th><th>FN</th><th>SKIPPED</th></tr></thead>
    <tbody>
      ${aiTableRows}
    </tbody>
  </table>

  <h2>CWE-Level Performance (SonarQube)</h2>
  <table>
    <thead><tr><th>CWE</th><th>TP</th><th>FP</th><th>FN</th><th>SKIPPED</th></tr></thead>
    <tbody>
      ${sonarTableRows}
    </tbody>
  </table>

  <script>
    const gtLabels = ${JSON.stringify(Object.keys(groundTruthCounts))};
    const gtData = ${JSON.stringify(Object.values(groundTruthCounts))};
    new Chart(document.getElementById("gtChart"), {
      type: "bar",
      data: {
        labels: gtLabels,
        datasets: [{
          label: "Ground Truth CWE Frequency",
          data: gtData,
          backgroundColor: "rgba(153, 102, 255, 0.6)",
        }]
      },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });

    new Chart(document.getElementById("evaluationChart"), {
      type: "bar",
      data: {
        labels: ["TP", "FP", "FN"],
        datasets: [
          {
            label: "AI-Based",
            data: [${aiStats.TP || 0}, ${aiStats.FP || 0}, ${aiStats.FN || 0}],
            backgroundColor: "rgba(75, 192, 192, 0.6)",
          },
          {
            label: "SonarQube",
            data: [${sonarStats.TP || 0}, ${sonarStats.FP || 0}, ${
    sonarStats.FN || 0
  }],
            backgroundColor: "rgba(255, 99, 132, 0.6)",
          }
        ]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: "top" } },
        scales: { y: { beginAtZero: true } }
      }
    });

    const catLabels = ${JSON.stringify(Object.keys(categories))};
    const catData = ${JSON.stringify(Object.values(categories))};
    new Chart(document.getElementById("categoryChart"), {
      type: "doughnut",
      data: {
        labels: catLabels,
        datasets: [{
          data: catData,
          backgroundColor: [
            "#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF",
            "#FF9F40", "#C9CBCF", "#7CB342", "#E91E63", "#3F51B5"
          ]
        }]
      },
      options: { plugins: { legend: { display: true, position: "bottom" } } }
    });
  </script>
</body>
</html>
`;
}

/**
 * Runs the final report aggregation.
 * Collects evaluation results, computes statistics, generates HTML, and writes it to disk.
 */
function runReport() {
  const gtCount = db
    .prepare("SELECT COUNT(*) as count FROM ground_truth")
    .get().count;

  const aiResults = db
    .prepare(
      "SELECT evaluation_result, vulnerability_type, cwe_id FROM ai_results"
    )
    .all();

  const sonarResults = db
    .prepare("SELECT evaluation_result, cwe_id FROM sonarqube_results")
    .all();

  const groundTruthCWEs = db.prepare("SELECT cwe_id FROM ground_truth").all();

  const aiStats = countByCategory(aiResults, "evaluation_result");
  const sonarStats = countByCategory(sonarResults, "evaluation_result");
  const categories = countByCategory(
    aiResults.filter((r) => r.vulnerability_type),
    "vulnerability_type"
  );

  const cweBreakdownAI = countMatchesByCWE(aiResults);
  const cweBreakdownSonar = countMatchesByCWE(sonarResults);
  const groundTruthCounts = countByCategory(groundTruthCWEs, "cwe_id");

  const aiTableRows = Object.entries(cweBreakdownAI)
    .map(
      ([cwe, s]) =>
        `<tr><td>${cwe}</td><td>${s.TP}</td><td>${s.FP}</td><td>${
          s.FN
        }</td><td>${s.SKIPPED || 0}</td></tr>`
    )
    .join("");

  const sonarTableRows = Object.entries(cweBreakdownSonar)
    .map(
      ([cwe, s]) =>
        `<tr><td>${cwe}</td><td>${s.TP}</td><td>${s.FP}</td><td>${
          s.FN
        }</td><td>${s.SKIPPED || 0}</td></tr>`
    )
    .join("");

  const html = generateHTMLReport(
    gtCount,
    groundTruthCounts,
    aiStats,
    sonarStats,
    categories,
    {},
    aiTableRows,
    sonarTableRows
  );

  fs.writeFileSync(outputPath, html);
  console.log(`📊 Report generated at: ${outputPath}`);
}

runReport();