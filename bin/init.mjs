#!/usr/bin/env node
// bin/init.mjs — called via `npx backend-audit-init`
// Copies the caller workflow into the consumer project.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const srcWorkflow = path.resolve(
  __dirname,
  "../workflows/backend-security-gate-caller.yml",
);
const destDir = path.resolve(process.cwd(), ".github", "workflows");
const destWorkflow = path.join(destDir, "backend-security-gate.yml");

console.log("\nBackend Audit - init\n");

// 1. Create .github/workflows if it doesn't exist
if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
  console.log("Created GitHub Workflows");
}

// 2. Warn if already exists
if (fs.existsSync(destWorkflow)) {
  console.log(".github/workflows/backend-security-gate.yml already exists.");
  console.log("   Delete it first if you want to re-initialise.\n");
  process.exit(0);
}

// 3. Copy workflow
fs.copyFileSync(srcWorkflow, destWorkflow);
console.log("Copied files");

// 4. Check .npmrc
const npmrcPath = path.resolve(process.cwd(), ".npmrc");
if (!fs.existsSync(npmrcPath)) {
  console.log("\nNo .npmrc found. Create one in the project root with:");
  console.log("   @achudeqxbit:registry=https://npm.pkg.github.com");
  console.log("   //npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n");
} else {
  const npmrc = fs.readFileSync(npmrcPath, "utf8");
  if (!npmrc.includes("npm.pkg.github.com")) {
    console.log("\nYour .npmrc may not be configured for GitHub Packages.");
    console.log("   Add these lines to .npmrc:");
    console.log("   @achudeqxbit:registry=https://npm.pkg.github.com");
    console.log("   //npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n");
  }
}

// 5. Remind about package.json scripts
console.log("\nAdd these scripts to your project's package.json:");
console.log(
  `   "backend:audit": "node node_modules/@achudeqxbit/backend-audit/bin/run.mjs",`,
);
console.log(`   "npm-audit":     "npm audit --audit-level=moderate"\n`);

console.log("Done!\n");
