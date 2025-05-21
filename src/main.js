// src/main.js

import { execSync } from "child_process";
import { program } from "commander";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

program
  .requiredOption("-r, --repo <url>", "GitHub repository URL")
  .option("-l, --limit <number>", "Limit number of commits", parseInt)
  .parse(process.argv);

const { repo, limit } = program.opts();

/**
 * Executes a given script file using Node.js with optional arguments.
 * If execution fails, logs the error and exits the process.
 * @param {string} scriptName - Filename of the script to run (e.g., "phase1.js").
 * @param {string} [args=""] - Additional CLI arguments to pass to the script.
 */
function runPhase(scriptName, args = "") {
  const scriptPath = path.join(__dirname, scriptName);
  console.log(`\n🚀 Running ${scriptName}...`);
  console.log(`📁 Script path: ${scriptPath}`);

  try {
    execSync(`node "${scriptPath}" ${args}`, {
      stdio: "inherit",
      cwd: process.cwd(),
    });
  } catch (err) {
    console.error(`❌ ${scriptName} failed with error:`, err.message);
    process.exit(1);
  }
}

/**
 * Main function to execute all four analysis phases sequentially.
 * Passes repository URL and optional commit limit to phase 1.
 */
(async () => {
  const repoArg = `--repo "${repo}"`;
  const limitArg = limit ? `--limit ${limit}` : "";

  runPhase("phase1.js", `${repoArg} ${limitArg}`);
  runPhase("phase2.js");
  runPhase("phase3.js");
  runPhase("phase4.js");

  console.log("\n✅ All phases complete. Check the generated report.");
})();
