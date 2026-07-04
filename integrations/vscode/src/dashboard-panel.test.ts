import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const source = readFileSync(path.join(__dirname, "dashboard-panel.js"), "utf8");

test("dashboard exposes educational and provider coverage states", () => {
  assert.match(source, /CVE \/ GHSA no evaluadas/);
  assert.match(source, /Configurar OSS Index/);
  assert.match(source, /Qué es/);
  assert.match(source, /Cómo puede afectar/);
  assert.match(source, /Qué hacer/);
});

test("update workflow keeps safe shortcuts and an explicit review step", () => {
  assert.match(source, /Solo seguridad/);
  assert.match(source, /Solo parches/);
  assert.match(source, /Revisar selección/);
  assert.match(source, /Revisa exactamente qué se modificará/);
  assert.match(source, /Aplicar cambios/);
});

test("dependency tree distinguishes expandable branches from leaf rows", () => {
  assert.match(source, /branch\?'<details class="tree-node/);
  assert.match(source, /'<div class="tree-row tree-leaf/);
  assert.match(source, /relation-badge/);
  assert.match(source, /tree-chevron/);
  assert.match(source, /tree-primary/);
  assert.match(source, /branch\?'<span class="tree-chevron"/);
  assert.doesNotMatch(source, /tree-chevron empty/);
  assert.doesNotMatch(source, /status-dot/);
  assert.match(source, /::-webkit-details-marker/);
});

test("desktop dependency rows use a uniform compact height", () => {
  assert.match(source, /height:34px;min-height:34px;max-height:34px/);
  assert.match(source, /grid-template-columns:minmax\(150px,1fr\) minmax\(125px,.7fr\) minmax\(210px,auto\)/);
  assert.match(source, /height:auto;min-height:42px;max-height:none/);
});

test("inspectors only scroll when their content exceeds the viewport", () => {
  assert.match(source, /max-height:calc\(100vh - 76px\)/);
  assert.match(source, /overflow-y:auto/);
  assert.match(source, /overscroll-behavior:contain/);
  assert.match(source, /max-height:none;overflow:visible/);
});

test("dashboard groups findings and exposes alternate dependency routes", () => {
  assert.match(source, /dependencias afectadas/);
  assert.match(source, /vulnerabilidad/);
  assert.match(source, /routes-badge/);
  assert.match(source, /Buscar dentro de las rutas/);
});

test("dashboard uses sentence case presentation labels", () => {
  assert.match(source, /Seguridad/);
  assert.doesNotMatch(source, />SEGURIDAD</);
  assert.match(source, /severityLabel/);
  assert.match(source, /relationshipLabel/);
});
