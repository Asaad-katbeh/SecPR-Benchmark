// src/phase2.js

import { simpleGit } from "simple-git";
import { program } from "commander";
import Database from "better-sqlite3";
import dotenv from "dotenv";
import OpenAI from "openai";
import path from "path";
import fs from "fs/promises";
import { fileURLToPath } from "url";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const db = new Database(
  process.env.DB_PATH || path.join(__dirname, "../data/security_analysis.db")
);

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

db.exec(`
  CREATE TABLE IF NOT EXISTS ai_results (
    vulnerability_id TEXT,
    file_path TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    fix_commit_hash TEXT NOT NULL,
    original_commit_hash TEXT NOT NULL,
    vulnerability_type TEXT,
    evaluation_result TEXT NOT NULL,
    evaluation_details TEXT,
    detected_line_numbers TEXT,
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
 * Normalizes a CWE ID to a lower-case string without prefix.
 * @param {string} cwe - CWE ID (e.g., "CWE-79").
 * @returns {string} Normalized CWE ID (e.g., "79").
 */
function normalizeCwe(cwe) {
  return (cwe || "").toLowerCase().replace("cwe-", "").trim();
}

/**
 * Sends source code to OpenAI GPT model to analyze for security vulnerabilities.
 * Returns a strict JSON object representing detected vulnerabilities.
 * @param {string} content - Source code to analyze.
 * @returns {Promise<object>} AI-generated vulnerability analysis.
 */
async function analyzeFileWithAI(content) {
  const prompt = `
You are a security expert analyzing code for vulnerabilities using OWASP and CWE guidelines.

Only analyze the code content. Do not speculate or make assumptions. Output strict JSON with this format:
{
  "vulnerabilities": [
    {
      "cwe_id": "CWE-XXX",
      "description": "...",
      "line_numbers": [start, end],
      "impact": "...",
      "explanation": "..."
    }
  ]
}
Code:
${content}
`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4-0125-preview",
      temperature: 0.1,
      messages: [
        {
          role: "system",
          content: "You are a security vulnerability detection assistant.",
        },
        { role: "user", content: prompt },
      ],
    });

    let resultText = response.choices[0].message.content.trim();

    if (resultText.startsWith("```")) {
      resultText = resultText
        .replace(/^```[a-z]*\n?/i, "")
        .replace(/```$/, "")
        .trim();
    }

    return JSON.parse(resultText);
  } catch (error) {
    if (
      error.code === "context_length_exceeded" ||
      error.message.includes("maximum context length") ||
      error.message.includes("tokens")
    ) {
      return { skippedDueToContext: true };
    }

    console.error(`💥 Error in OpenAI call:`, error.message);
    throw error;
  }
}

/**
 * Evaluates all ground truth commits against AI-generated vulnerability results.
 * Classifies each result as TP (True Positive), FP (False Positive), or FN (False Negative).
 * Saves evaluation outcomes in the `ai_results` table.
 */
async function processCommits() {
  const repoInfo = getRepositoryInfo();
  const repoPath = path.join(__dirname, "../repos", repoInfo.repo);
  const git = simpleGit(repoPath);

  const gtCommits = db
    .prepare(
      `
      SELECT DISTINCT vulnerability_id, file_path, cwe_id, fix_commit_hash, original_commit_hash, vulnerability_type
      FROM ground_truth
      WHERE original_commit_hash IS NOT NULL
    `
    )
    .all();

  const commitsByHash = new Map();
  for (const row of gtCommits) {
    if (!commitsByHash.has(row.original_commit_hash)) {
      commitsByHash.set(row.original_commit_hash, []);
    }
    commitsByHash.get(row.original_commit_hash).push(row);
  }

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO ai_results (
      vulnerability_id, file_path, cwe_id,
      fix_commit_hash, original_commit_hash, vulnerability_type,
      evaluation_result, evaluation_details, detected_line_numbers
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const [commitHash, gtEntries] of commitsByHash) {
    console.log(`\n🔍 Checking out original commit ${commitHash}`);
    await git.checkout(commitHash);

    for (const gt of gtEntries) {
      const absFilePath = path.join(repoPath, gt.file_path);
      try {
        await fs.access(absFilePath);
      } catch {
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          gt.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "SKIPPED",
          "Skipped: file not found in original commit.",
          null
        );
        console.warn(`⚠️ SKIPPED for ${gt.file_path} (file not found)`);
        continue;
      }

      let content;
      try {
        content = await fs.readFile(absFilePath, "utf-8");
      } catch (err) {
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          gt.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "SKIPPED",
          "Skipped: failed to read file content.",
          null
        );
        console.warn(`⚠️ SKIPPED for ${gt.file_path} (read error)`);
        continue;
      }

      let aiResults;
      try {
        aiResults = await analyzeFileWithAI(content);
      } catch (e) {
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          gt.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "SKIPPED",
          `Skipped: AI error - ${e.message}`,
          null
        );
        console.warn(`⚠️ SKIPPED due to AI error: ${e.message}`);
        continue;
      }

      if (aiResults.skippedDueToContext) {
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          gt.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "SKIPPED",
          "Skipped due to context length exceeding GPT limits.",
          null
        );
        console.warn(`⚠️ SKIPPED due to context length for ${gt.file_path}`);
        continue;
      }

      const normalizedGtCWE = normalizeCwe(gt.cwe_id);
      const aiMatch = aiResults.vulnerabilities.find(
        (v) => normalizeCwe(v.cwe_id) === normalizedGtCWE
      );

      if (aiMatch) {
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          gt.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "TP",
          `Correctly detected vulnerability (CWE ${gt.cwe_id})`,
          JSON.stringify(aiMatch.line_numbers || [])
        );
        console.log(`✅ TP for ${gt.file_path} (CWE ${gt.cwe_id})`);
      } else if (aiResults.vulnerabilities.length > 0) {
        const fpVuln = aiResults.vulnerabilities[0];
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          fpVuln.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "FP",
          `False positive: AI reported ${fpVuln.cwe_id}, expected ${gt.cwe_id}`,
          JSON.stringify(fpVuln.line_numbers || [])
        );
        console.warn(
          `⚠️ FP for ${gt.file_path}: AI reported ${fpVuln.cwe_id} but expected ${gt.cwe_id}`
        );
      } else {
        stmt.run(
          gt.vulnerability_id,
          gt.file_path,
          gt.cwe_id,
          gt.fix_commit_hash,
          gt.original_commit_hash,
          gt.vulnerability_type,
          "FN",
          `Missed vulnerability: CWE ${gt.cwe_id}`,
          null
        );
        console.log(`❌ FN for ${gt.file_path} (CWE ${gt.cwe_id})`);
      }
    }
  }

  console.log("\n🎉 Phase 2 evaluation complete.");
}

program.parse(process.argv);
processCommits();
