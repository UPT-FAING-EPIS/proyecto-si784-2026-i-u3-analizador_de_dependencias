import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const source = readFileSync(path.join(__dirname, "summary-view.js"), "utf8");

test("sidebar always renders OSS Index configuration state", () => {
  assert.match(source, /OSS Index/);
  assert.match(source, /Configurado/);
  assert.match(source, /No configurado/);
});

test("sidebar only renders the configure action when no token is stored", () => {
  assert.match(source, /depanalyzer\.configureOssIndex/);
  assert.match(source, /this\.ossTokenConfigured \? ""/);
});
