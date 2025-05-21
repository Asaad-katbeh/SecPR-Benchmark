// src/phase1.js

import { program } from "commander";
import { Octokit } from "@octokit/rest";
import { simpleGit } from "simple-git";
import Database from "better-sqlite3";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { extractSecurityInfo } from "../config/security-patterns.js";
import fs from "fs/promises";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const db = new Database(
  process.env.DB_PATH || path.join(process.cwd(), "data/security_analysis.db")
);

/**
 * Initializes the SQLite database with required tables.
 * Drops and recreates the `ground_truth` table on each run.
 */
function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS repository_info (
      id INTEGER PRIMARY KEY,
      owner TEXT NOT NULL,
      repo TEXT NOT NULL,
      url TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    DROP TABLE IF EXISTS ground_truth;
    CREATE TABLE ground_truth (
      vulnerability_id TEXT PRIMARY KEY,
      file_path TEXT NOT NULL,
      cwe_id TEXT NOT NULL,
      fix_commit_hash TEXT NOT NULL,
      fix_commit_message TEXT,
      original_commit_hash TEXT NOT NULL,
      original_commit_message TEXT,
      vulnerability_type TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

/**
 * Extracts owner and repository name from a GitHub URL.
 * @param {string} url - GitHub repository URL.
 * @returns {{owner: string, repo: string, url: string}} - Extracted information.
 * @throws Will throw an error if the URL format is invalid.
 */
function extractRepoInfo(url) {
  const match = url.match(/github\.com\/([^\/]+)\/([^\/\.]+)/);
  if (!match) throw new Error("Invalid GitHub repository URL");
  return { owner: match[1], repo: match[2], url };
}

/**
 * Ensures the repository is cloned locally. Clones if not already present.
 * @param {string} repoPath - Path where the repo should be located.
 * @param {string} repoUrl - GitHub repo URL to clone from.
 */
async function ensureRepository(repoPath, repoUrl) {
  try {
    await fs.access(repoPath);
    console.log(`Repository already exists at ${repoPath}`);
  } catch {
    const git = simpleGit();
    console.log(`Cloning repository from ${repoUrl}...`);
    await git.clone(repoUrl, repoPath);
    console.log("Repository cloned.");
  }
}

/**
 * Finds the pull request associated with a given commit, if any.
 * @param {string} owner - GitHub repository owner.
 * @param {string} repo - GitHub repository name.
 * @param {string} sha - Commit SHA to look up.
 * @returns {Promise<number|null>} - Pull request number or null if not found.
 */
async function findPRForCommit(owner, repo, sha) {
  try {
    const { data } = await octokit.repos.listPullRequestsAssociatedWithCommit({
      owner,
      repo,
      commit_sha: sha,
    });
    return data.length ? data[0].number : null;
  } catch (err) {
    if (err.status !== 404) console.error("PR lookup error:", err.message);
    return null;
  }
}

/**
 * Processes a commit assumed to be a security fix, traces original vulnerable commit,
 * and stores vulnerability metadata in the database.
 * @param {import("simple-git").SimpleGit} git - SimpleGit instance for the repo.
 * @param {object} commit - Commit object from git.log().
 * @param {string} repoPath - Path to the local git repository.
 */
async function processFixingCommit(git, commit, repoPath) {
  const securityInfo = await extractSecurityInfo(commit.message);
  if (!securityInfo.securityRelated) return;

  const diff = await git.diff([`${commit.hash}^`, commit.hash]);
  const changedFiles = diff
    .split("\n")
    .filter((line) => line.startsWith("diff --git"))
    .map((line) => line.split(" ")[2].replace("a/", ""));

  for (const file of changedFiles) {
    try {
      await git.raw([
        "ls-tree",
        "-r",
        "--name-only",
        `${commit.hash}^`,
        "--",
        file,
      ]);

      const fileDiff = await git.diff([
        `${commit.hash}^`,
        commit.hash,
        "--",
        file,
      ]);
      const changedLines = new Set();

      let currentLine = 0;
      for (const line of fileDiff.split("\n")) {
        if (line.startsWith("@@")) {
          const match = line.match(/@@ -\d+,?\d* \+(\d+),?\d* @@/);
          if (match) currentLine = parseInt(match[1]);
        } else if (line.startsWith("+") && !line.startsWith("+++")) {
          changedLines.add(currentLine++);
        } else if (!line.startsWith("diff")) {
          currentLine++;
        }
      }

      if (!changedLines.size) continue;

      const blame = await git.raw([
        "blame",
        "-l",
        "-L",
        Array.from(changedLines).join(","),
        `${commit.hash}^`,
        "--",
        file,
      ]);
      const commitHashes = new Set();

      for (const line of blame.split("\n")) {
        const match = line.match(/^([a-f0-9]+)/);
        if (match && match[1] !== commit.hash) {
          commitHashes.add(match[1]);
        }
      }

      const originalCommit = Array.from(commitHashes).sort().pop();
      if (!originalCommit) continue;

      const originalMsg = (
        await git.show([originalCommit, "--format=%B", "-s"])
      ).trim();
      const fixMsg = commit.message.trim();

      const remote = await git.remote(["get-url", "origin"]);
      const [owner, repo] = remote
        .replace("https://github.com/", "")
        .replace(".git", "")
        .split("/");
      const prId = await findPRForCommit(owner, repo, originalCommit);
      const identifier = prId || `commit-${originalCommit}`;

      const stmt = db.prepare(`
        INSERT OR REPLACE INTO ground_truth (
          vulnerability_id, file_path, cwe_id, fix_commit_hash,
          fix_commit_message, original_commit_hash, original_commit_message,
          vulnerability_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      if (securityInfo.cweIds.length === 0) {
        console.warn(`⚠️ Skipping ${file}: No identifiable CWE.`);
        continue;
      }

      for (const cweId of securityInfo.cweIds) {
        stmt.run(
          identifier,
          file,
          cweId,
          commit.hash,
          fixMsg,
          originalCommit,
          originalMsg,
          securityInfo.vulnerabilityTypes.join(", ") || null
        );
      }

      console.log(
        `✔️ Processed ${file}, CWE(s): ${securityInfo.cweIds.join(", ")}`
      );
    } catch (err) {
      if (!err.message.includes("no such path")) {
        console.error(`Error in file ${file}: ${err.message}`);
      }
    }
  }
}

/**
 * Main CLI entry point. Parses arguments, initializes database,
 * handles repository setup, and processes commit history.
 */
async function main() {
  program
    .requiredOption("-r, --repo <path>", "GitHub repo URL or local path")
    .option("-l, --limit <number>", "Limit commits (debug)", parseInt)
    .parse(process.argv);

  const { repo: repoArg, limit } = program.opts();

  initializeDatabase();

  let repoPath;
  if (repoArg.startsWith("http")) {
    const info = extractRepoInfo(repoArg);
    repoPath = path.join(process.cwd(), "repos", info.repo);
    db.prepare(
      `INSERT OR REPLACE INTO repository_info (owner, repo, url) VALUES (?, ?, ?)`
    ).run(info.owner, info.repo, info.url);
    await ensureRepository(repoPath, repoArg);
  } else {
    repoPath = path.resolve(repoArg);
    await fs.access(repoPath);
  }

  const git = simpleGit(repoPath);
  const commits = await git.log();
  const targetCommits = limit ? commits.all.slice(0, limit) : commits.all;

  for (const commit of targetCommits) {
    await processFixingCommit(git, commit, repoPath);
  }

  console.log("✅ Ground truth extraction complete.");
}

main();
