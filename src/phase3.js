import { simpleGit } from "simple-git";
import Database from "better-sqlite3";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs/promises";
import { execSync } from "child_process";
import axios from "axios";
import OpenAI from "openai";
import os from "os";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const db = new Database(
  process.env.DB_PATH || path.join(process.cwd(), "data/security_analysis.db")
);

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

db.exec(`
  CREATE TABLE IF NOT EXISTS sonarqube_results (
    vulnerability_id TEXT,
    file_path TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    fix_commit_hash TEXT NOT NULL,
    original_commit_hash TEXT NOT NULL,
    vulnerability_type TEXT,
    evaluation_result TEXT NOT NULL,
    evaluation_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vulnerability_id, file_path, cwe_id)
  )
`);

/**
 * Retrieves the most recent repository information from the database.
 * @returns {{owner: string, repo: string}} Repository owner and name.
 */
function getRepositoryInfo() {
  return db
    .prepare(
      `SELECT owner, repo FROM repository_info ORDER BY created_at DESC LIMIT 1`
    )
    .get();
}

/**
 * Checks if a given command exists in the system's PATH.
 * @param {string} cmd - Command to check (e.g., "sonar-scanner").
 * @returns {boolean} True if command exists, otherwise false.
 */
function commandExists(cmd) {
  try {
    if (os.platform() === "win32") {
      execSync(`where ${cmd}`, { stdio: "ignore" });
    } else {
      execSync(`command -v ${cmd}`, { stdio: "ignore" });
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Fetches vulnerability issues from the SonarQube REST API for a given project key.
 * @param {string} projectKey - The SonarQube project key.
 * @returns {Promise<Array>} List of issue objects.
 */
async function fetchSonarIssuesREST(projectKey) {
  const serverUrl = process.env.SONARQUBE_URL;
  const token = process.env.SONARQUBE_TOKEN;
  if (!serverUrl || !token || !projectKey) {
    throw new Error("SONARQUBE_* vars must be set.");
  }

  const auth = Buffer.from(`${token}:`).toString("base64");
  let issues = [],
    page = 1,
    total = 0;

  do {
    const res = await axios.get(`${serverUrl}/api/issues/search`, {
      params: {
        componentKeys: projectKey,
        types: "VULNERABILITY",
        ps: 500,
        p: page,
      },
      headers: { Authorization: `Basic ${auth}` },
    });

    if (res.data?.issues) {
      issues.push(...res.data.issues);
      total = res.data.paging.total;
      page++;
    } else break;
  } while (issues.length < total);

  return issues;
}

/**
 * Uses GPT to extract a CWE identifier from a SonarQube issue message.
 * @param {string} message - The issue message to analyze.
 * @returns {Promise<string>} The inferred CWE ID or "UNKNOWN".
 */
async function extractCWEWithGPT(message) {
  if (!message) return "UNKNOWN";

  const prompt = `You are a security analyst. A static analysis tool returned the following issue message:\n\n"${message}"\n\nDoes this message refer to a specific CWE vulnerability? If yes, respond only with the CWE identifier like CWE-79. If no, respond only with UNKNOWN.`;

  try {
    const response = await openai.chat.completions.create({
      messages: [{ role: "user", content: prompt }],
      model: "gpt-4",
      max_tokens: 10,
      temperature: 0,
    });
    const answer = response.choices[0]?.message?.content?.trim();
    return answer.match(/^CWE-\d+$/i) ? answer.toUpperCase() : "UNKNOWN";
  } catch (err) {
    console.error("❌ GPT API error:", err.message);
    return "UNKNOWN";
  }
}

/**
 * Creates and writes the sonar-project.properties file for a given commit.
 * @param {string} repoPath - Path to the local repository.
 * @param {string} commitHash - Commit hash for the current scan.
 * @returns {Promise<{propPath: string, reportPath: string}>} Paths to created files.
 */
async function ensureSonarProjectProperties(repoPath, commitHash) {
  const reportDir = path.resolve(process.cwd(), "sonar-reports");
  await fs.mkdir(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `${commitHash}.json`);

  const projectKey = `autogen_${commitHash}`;
  const sonarOrg = process.env.SONARQUBE_ORG;

  const props = [
    `sonar.projectKey=${projectKey}`,
    `sonar.sources=.`,
    `sonar.exclusions=**/*.java`,
    `sonar.c.file.suffixes=-`,
    `sonar.cpp.file.suffixes=-`,
    `sonar.objc.file.suffixes=-`,
    `sonar.coverage.exclusions=**`,
    `sonar.coverageReportPaths=`,
    `sonar.verbose=false`,
    `sonar.issuesReport.console.enable=true`,
    `sonar.scanner.skipServer=true`,
    `sonar.scanner.skip=false`,
  ];

  if (sonarOrg) {
    props.push(`sonar.organization=${sonarOrg}`);
  }

  const propPath = path.join(repoPath, "sonar-project.properties");
  await fs.writeFile(propPath, props.join("\n"), "utf-8");
  return { propPath, reportPath };
}

/**
 * Deletes the sonar-project.properties file.
 * @param {string} propPath - Path to the sonar-project.properties file.
 */
async function cleanupSonarProjectProperties(propPath) {
  try {
    await fs.unlink(propPath);
  } catch {}
}

/**
 * Main execution function to process ground truth commits,
 * run SonarQube analysis, and classify detections.
 */
async function processCommits() {
  const repoInfo = getRepositoryInfo();
  const repoPath = path.join(process.cwd(), "repos", repoInfo.repo);
  const git = simpleGit(repoPath);

  const rows = db
    .prepare(
      `
      SELECT DISTINCT vulnerability_id, file_path, cwe_id,
        fix_commit_hash, original_commit_hash, vulnerability_type
      FROM ground_truth
      WHERE original_commit_hash IS NOT NULL
    `
    )
    .all();

  const commitsByHash = new Map();
  for (const row of rows) {
    if (!commitsByHash.has(row.original_commit_hash)) {
      commitsByHash.set(row.original_commit_hash, []);
    }
    commitsByHash.get(row.original_commit_hash).push(row);
  }

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO sonarqube_results (
      vulnerability_id, file_path, cwe_id,
      fix_commit_hash, original_commit_hash, vulnerability_type,
      evaluation_result, evaluation_details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const [commitHash, vulnEntries] of commitsByHash) {
    console.log(`\n🔍 Processing commit ${commitHash}`);
    try {
      await git.reset(["--hard"]);
      await git.clean("f", ["-d"]);
      await git.checkout(commitHash);
    } catch (err) {
      console.error("❌ Git error:", err.message);
      continue;
    }

    const { propPath } = await ensureSonarProjectProperties(
      repoPath,
      commitHash
    );

    if (!commandExists("sonar-scanner")) {
      console.error("❌ sonar-scanner not found in PATH.");
      process.exit(1);
    }

    try {
      execSync("sonar-scanner", { cwd: repoPath, stdio: "inherit" });
    } catch (err) {
      console.error("❌ SonarQube scan failed:", err.message);
      await cleanupSonarProjectProperties(propPath);
      continue;
    }

    let sonarResults = [];
    try {
      sonarResults = await fetchSonarIssuesREST(`autogen_${commitHash}`);
    } catch (err) {
      console.error("❌ Could not fetch SonarQube results:", err.message);
      await cleanupSonarProjectProperties(propPath);
      continue;
    }

    const sonarMap = new Map();
    const allDetectedCWEs = new Set();

    for (const issue of sonarResults) {
      const file = issue.component?.replace(/^.*?:/, "") || issue.component;
      let cwe = issue.cwe;

      if (!cwe || cwe === "UNKNOWN") {
        cwe = await extractCWEWithGPT(issue.message);
      }

      if (!sonarMap.has(file)) sonarMap.set(file, new Set());
      sonarMap.get(file).add(cwe);
      allDetectedCWEs.add(cwe);
    }

    console.log("🧠 Detected CWEs by file:");
    for (const [file, cwes] of sonarMap.entries()) {
      console.log(`  ${file}: ${Array.from(cwes).join(", ")}`);
    }

    for (const gt of vulnEntries) {
      const expectedCWE = gt.cwe_id;
      let result = "FN";
      let detail = `Expected CWE ${expectedCWE}, found: ${Array.from(
        allDetectedCWEs
      ).join(", ")}`;

      if (allDetectedCWEs.size === 0) {
        detail = "No issues reported in scan.";
      } else if (allDetectedCWEs.has(expectedCWE)) {
        result = "TP";
        detail = `Detected expected CWE ${expectedCWE}`;
      } else {
        result = "FP";
        detail = `Detected unrelated CWEs: ${Array.from(allDetectedCWEs).join(
          ", "
        )}`;
      }

      console.log(
        `✔️ ${result} — ${
          gt.file_path
        } | Expected: ${expectedCWE} | Found: ${Array.from(
          allDetectedCWEs
        ).join(", ")}`
      );

      stmt.run(
        gt.vulnerability_id,
        gt.file_path,
        gt.cwe_id,
        gt.fix_commit_hash,
        gt.original_commit_hash,
        gt.vulnerability_type,
        result,
        detail
      );
    }

    await cleanupSonarProjectProperties(propPath);
  }

  console.log("\n✅ Phase 3 (SonarQube evaluation) complete.");
}

processCommits();
