#!/usr/bin/env node

import process from "node:process";
import path from "node:path";
import { readFileSync } from "node:fs";

// set the working directory to project root
// fs.accessSync("./package-lock.json")
const getProjectRoot = () => path.resolve(path.dirname(process.argv[1]), "../");
process.chdir(getProjectRoot());

// load the lock file
const lockFilePath = path.resolve(process.cwd(), "package-lock.json");
const lockFile = JSON.parse(readFileSync(lockFilePath));

const toLog = {
  name: lockFile.name,
  version: lockFile.version,
  lockfileVersion: lockFile.lockfileVersion,
};

// check the packages packages
const removeUndefined = (obj) =>
  Object.fromEntries(Object.entries(obj).filter((e) => e[1] !== undefined));

const results = {
  project: [],
  resolved: [],
  unresolved: [],
};
Object.entries(lockFile.packages).forEach(([name, p]) => {
  const bucket = p.name?.startsWith("@trustify-ui")
    ? results.project
    : p.resolved
    ? results.resolved
    : results.unresolved;

  bucket.push(
    removeUndefined({
      name,
      version: p.version,
      resolved: p.resolved,
      packageName: p.name,
    })
  );
});

// log findings
toLog.packages = results.project;
toLog.dependencies = {
  countResolved: results.resolved.length,
  countUnresolved: results.unresolved.length,
  unresolved: results.unresolved,
};

console.log(`package-lock.json (${lockFilePath}) status:`);
console.dir(toLog, { depth: 3 });
console.log();
if (results.unresolved.length === 0) {
  console.log("\u{1f600} lock file is ok!");
} else {
  console.log("\u{1f621} lock file contains unresolved dependencies!");
}

// exit the script with an appropriate error code
process.exit(results.unresolved.length === 0 ? 0 : 1);
