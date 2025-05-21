// src/config/security-patterns.js

import dotenv from "dotenv";
dotenv.config();

import OpenAI from "openai";
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/**
 * Definitions of patterns used to detect security-related messages.
 * Includes regexes for CWE IDs, OWASP identifiers, keywords, and known vulnerability types.
 */
export const securityPatterns = {
  cwe: {
    pattern: /CWE-(\d+)/gi,
    description: "Common Weakness Enumeration",
  },
  owasp: {
    patterns: [
      {
        pattern: /OWASP[-\s]?A[1-9][0-9]?/gi,
        description: "OWASP Top 10",
      },
      {
        pattern: /OWASP[-\s]?M[1-9][0-9]?/gi,
        description: "OWASP Mobile Top 10",
      },
    ],
  },
  keywords: [
    /fix(?:es|ed)?\s+(?:security|vulnerability|exploit|bug)/i,
    /(?:security|vulnerability)\s+(?:fix|patch|update)/i,
    /CVE-\d{4}-\d{4,}/i,
    /GHSA-[a-zA-Z0-9-]+/i,
    /hotfix/i,
    /secure\s+coding/i,
    /security\s+issue/i,
  ],
  vulnerabilityTypes: [
    { pattern: /(?:SQL|NoSQL)\s+injection/i, cwe: "CWE-89" },
    { pattern: /XSS|cross[-\s]?site\s+scripting/i, cwe: "CWE-79" },
    { pattern: /CSRF|cross[-\s]?site\s+request\s+forgery/i, cwe: "CWE-352" },
    { pattern: /buffer\s+overflow/i, cwe: "CWE-120" },
    { pattern: /race\s+condition/i, cwe: "CWE-362" },
    { pattern: /path\s+traversal/i, cwe: "CWE-22" },
    { pattern: /command\s+injection/i, cwe: "CWE-78" },
    { pattern: /deserialization/i, cwe: "CWE-502" },
    { pattern: /authentication\s+bypass/i, cwe: "CWE-287" },
    { pattern: /authorization\s+bypass/i, cwe: "CWE-285" },
    { pattern: /directory\s+listing/i, cwe: "CWE-548" },
    { pattern: /hardcoded\s+(password|credential)/i, cwe: "CWE-798" },
    { pattern: /insecure\s+cookie/i, cwe: "CWE-614" },
    { pattern: /unvalidated\s+redirect/i, cwe: "CWE-601" },
  ],
};

/**
 * Extracts security information such as CWE IDs and vulnerability types from a commit message.
 * Falls back to GPT-4 to infer a CWE if none are matched but the message is deemed security-related.
 * @param {string} message - The commit message to analyze.
 * @returns {Promise<{cweIds: string[], securityRelated: boolean, vulnerabilityTypes: string[]}>}
 */
export async function extractSecurityInfo(message) {
  const result = {
    cweIds: new Set(),
    securityRelated: false,
    vulnerabilityTypes: new Set(),
  };

  const cweMatches = message.matchAll(securityPatterns.cwe.pattern);
  for (const match of cweMatches) {
    result.cweIds.add(`CWE-${match[1]}`);
    result.securityRelated = true;
  }

  for (const owaspPattern of securityPatterns.owasp.patterns) {
    const owaspMatches = message.matchAll(owaspPattern.pattern);
    for (const match of owaspMatches) {
      result.cweIds.add(match[0].toUpperCase());
      result.securityRelated = true;
    }
  }

  for (const keyword of securityPatterns.keywords) {
    if (keyword.test(message)) {
      result.securityRelated = true;
    }
  }

  for (const vulnType of securityPatterns.vulnerabilityTypes) {
    if (vulnType.pattern.test(message)) {
      result.cweIds.add(vulnType.cwe);
      result.vulnerabilityTypes.add(
        vulnType.pattern.source.replace(/[\\^$.*+?()[\]{}|]/g, "")
      );
      result.securityRelated = true;
    }
  }

  let cweIds = Array.from(result.cweIds);

  if (cweIds.length === 0 && result.securityRelated) {
    const inferredCwe = await inferCWEWithGPT(message);
    if (inferredCwe !== "UNKNOWN") {
      cweIds.push(inferredCwe);
    }
  }

  return {
    ...result,
    cweIds,
    vulnerabilityTypes: Array.from(result.vulnerabilityTypes),
  };
}

/**
 * Uses GPT-4 to infer the most likely CWE ID based on a commit message.
 * @param {string} message - The commit message to analyze.
 * @returns {Promise<string>} A CWE identifier (e.g., "CWE-79") or "UNKNOWN".
 */
export async function inferCWEWithGPT(message) {
  const prompt = `You are a security expert. Based solely on the commit message below — which describes a fix to a security vulnerability — infer the most likely CWE category this fix addresses.

  The CWE ID should be accurate and based on keywords, patterns, or semantics in the message. Only return a valid CWE ID like "CWE-79". If there is truly no way to reasonably guess the CWE, return "UNKNOWN".
  
  Commit message:
  "${message}"`;

  try {
    const response = await openai.chat.completions.create({
      messages: [{ role: "user", content: prompt }],
      model: "gpt-4",
      max_tokens: 10,
      temperature: 0,
    });

    const result = response.choices[0].message.content.trim();
    return result.match(/^CWE-\d+$/i) ? result.toUpperCase() : "UNKNOWN";
  } catch (err) {
    console.error("❌ GPT error while inferring CWE:", err.message);
    return "UNKNOWN";
  }
}
