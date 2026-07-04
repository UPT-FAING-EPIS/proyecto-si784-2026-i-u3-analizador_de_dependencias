import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

interface ExtensionManifest {
  contributes?: {
    configuration?: {
      properties?: Record<string, { scope?: string }>;
    };
  };
}

const manifest = JSON.parse(
  readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
) as ExtensionManifest;

test("analysis mode supports workspace-folder configuration", () => {
  const setting = manifest.contributes?.configuration?.properties?.["depanalyzer.analysisMode"];
  assert.equal(setting?.scope, "resource");
});
