import { cp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(extensionRoot, "..", "..");
const command = process.platform === "win32" ? "cmd.exe" : "./gradlew";
const args = process.platform === "win32"
  ? ["/d", "/s", "/c", "gradlew.bat", "installDist"]
  : ["installDist"];
const result = spawnSync(command, args, {
  cwd: repositoryRoot,
  stdio: "inherit"
});
if (result.status !== 0) process.exit(result.status ?? 1);

const source = path.join(repositoryRoot, "build", "install", "depanalyzer");
if (!existsSync(source)) throw new Error(`No se generó la distribución CLI en ${source}`);
const target = path.join(extensionRoot, "cli");
await rm(target, { recursive: true, force: true });
await cp(source, target, { recursive: true });
console.log(`CLI incluido en ${target}`);
