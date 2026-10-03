#!/usr/bin/env node
// publish.mjs — o Action diário do CBL-Multiservice/sdd-canon-data (STORY-710, D6).
//
// Baixa o pacote de dados de segurança que a plataforma ArchGenerator monta e ASSINA, confere tudo
// contra a chave pública fixada neste repositório (`keys.json`, formato do `canon-data.keys` do
// kit) e publica a release `data-YYYYMMDD-HHMM` como `latest` só quando o conteúdo mudou:
//   (1) GET do `latest` (URL fixa do endpoint público);
//   (2) os 5 arquivos (a rota responde 302 para uma URL pré-assinada do S3; 403 do S3 = URL
//       vencida ⇒ refaz o GET da rota uma vez), com teto de tamanho;
//   (3) bytes/sha256 do `latest`, gzSha256/gzBytes e sha256 do conteúdo do MANIFEST, esquema, tag
//       (match completo, dígitos ASCII) e assinatura ed25519 sobre os bytes do MANIFEST;
//   (4) MANIFEST da release `latest` atual: mesmo contentSha256 ⇒ nada a publicar; `syncs` menor
//       que o da atual ⇒ RECUSA (anti-rollback, mesma regra do `check_rollback` do kit);
//   (5) `gh release create <tag> --latest` com os 5 assets e notas por arquivo;
//   (6) poda: mantém as 14 releases `data-*` mais recentes (`--cleanup-tag`), nunca a nova nem
//       uma fora do padrão;
//   (7) atividade: a cada publicação, e quando o último commit tem mais de 30 dias, grava
//       `status.json` e faz commit (o GitHub desliga o agendamento após 60 dias sem atividade).
// Falha em (1)–(4) ⇒ exit 1 sem publicar. `--dry-run` = (1)–(4) + o plano, sem gh de escrita e
// sem git. Só `node:` built-ins; `gh`/`git` por execFile (sem shell).
import { execFile } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { gunzipSync } from "node:zlib";

export const LATEST_URL = "https://app.archgenerator.com/api/public/security-data/latest";
export const REPO_DEFAULT = "CBL-Multiservice/sdd-canon-data";
export const SCHEMA = "archgen-security-data/1";
export const NAMES = [
  "MANIFEST.json",
  "MANIFEST.json.sig",
  "advisories.ndjson.gz",
  "sast-rules.ndjson.gz",
  "LICENSES.md",
];
export const DATA_FILES = ["advisories.ndjson.gz", "sast-rules.ndjson.gz"];
export const TAG_RE = /^data-[0-9]{8}-[0-9]{4}$/;
export const KEEP = 14;
const HEX64 = /^[0-9a-f]{64}$/;
const TIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const CAP_LATEST = 64 * 1024;
const CAP_SMALL = 1024 * 1024;
const CAP_GZ = 64 * 1024 * 1024;
const ACTIVITY_DAYS = 30;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

class Refusal extends Error {}
const refuse = (msg) => {
  throw new Refusal(msg);
};

const execFileP = promisify(execFile);
function realDeps() {
  const run = (bin) => (args) => execFileP(bin, args, { maxBuffer: 32 * 1024 * 1024 });
  return {
    fetch: globalThis.fetch,
    gh: run("gh"),
    git: run("git"),
    env: process.env,
    now: () => new Date(),
    log: (m) => console.log(m),
    error: (m) => console.error(m),
    keysPath: fileURLToPath(new URL("../keys.json", import.meta.url)),
    statusPath: fileURLToPath(new URL("../status.json", import.meta.url)),
    tmpRoot: tmpdir(),
  };
}

async function fetchCapped(fetchFn, url, cap, what) {
  const res = await fetchFn(url, {
    redirect: "follow",
    headers: { "user-agent": "sdd-canon-data" },
  });
  if (!res.ok) {
    const e = new Refusal(`${what}: HTTP ${res.status}`);
    e.status = res.status;
    throw e;
  }
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > cap) refuse(`${what} acima do teto (${cap} bytes)`);
  const chunks = [];
  let n = 0;
  if (res.body) {
    for await (const chunk of res.body) {
      n += chunk.length;
      if (n > cap) refuse(`${what} acima do teto (${cap} bytes)`);
      chunks.push(Buffer.from(chunk));
    }
  }
  return Buffer.concat(chunks);
}

function loadKeys(file) {
  const doc = JSON.parse(readFileSync(file, "utf8"));
  const out = new Map();
  for (const e of Array.isArray(doc?.keys) ? doc.keys : []) {
    if (typeof e?.publicKey !== "string" || !HEX64.test(e.publicKey)) continue;
    const pub = Buffer.from(e.publicKey, "hex");
    if (e.keyId !== sha256(pub).slice(0, 16)) continue;
    out.set(e.keyId, pub);
  }
  return out;
}

function checkSignature(manifest, sigBytes, keys) {
  let sig;
  try {
    sig = JSON.parse(sigBytes.toString("utf8"));
  } catch {
    refuse("MANIFEST.json.sig ilegível");
  }
  if (sig?.alg !== "ed25519") refuse("assinatura não é ed25519");
  const pub = keys.get(sig.keyId);
  if (!pub) refuse(`keyId ${JSON.stringify(sig.keyId)} não é uma chave confiável`);
  if (typeof sig.signature !== "string" || !/^[0-9a-f]{128}$/.test(sig.signature)) {
    refuse("assinatura não é hex de 64 bytes");
  }
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, pub]),
    format: "der",
    type: "spki",
  });
  if (!verify(null, manifest, key, Buffer.from(sig.signature, "hex"))) refuse("assinatura inválida");
  return sig.keyId;
}

function parseManifest(bytes) {
  let m;
  try {
    m = JSON.parse(bytes.toString("utf8"));
  } catch {
    refuse("MANIFEST.json ilegível");
  }
  if (m?.schema !== SCHEMA) refuse(`esquema não suportado: ${JSON.stringify(m?.schema)}`);
  const files = Array.isArray(m.files) ? m.files : [];
  if (JSON.stringify(files.map((f) => f?.name)) !== JSON.stringify(DATA_FILES)) {
    refuse(`o MANIFEST deve listar exatamente ${DATA_FILES.join(", ")}`);
  }
  for (const f of files) {
    const ok =
      Number.isInteger(f.rows) &&
      f.rows >= 0 &&
      Number.isInteger(f.gzBytes) &&
      f.gzBytes >= 0 &&
      HEX64.test(f.sha256 ?? "") &&
      HEX64.test(f.gzSha256 ?? "");
    if (!ok) refuse(`entrada malformada no MANIFEST: ${f.name}`);
  }
  if (!HEX64.test(m.contentSha256 ?? "")) refuse("contentSha256 malformado");
  const syncs = {};
  for (const x of ["sca", "sast"]) {
    const v = m.syncs?.[x]?.finishedAt ?? null;
    if (v !== null && !(typeof v === "string" && TIME_RE.test(v))) refuse(`syncs.${x} malformado`);
    syncs[x] = v;
  }
  if (syncs.sca === null && syncs.sast === null) refuse("MANIFEST sem horário de sync");
  return { ...m, syncs };
}

/** Mesma regra do `check_rollback` do kit: nenhum sync pode andar para trás. */
function checkRollback(next, current) {
  for (const x of ["sca", "sast"]) {
    const before = current?.[x] ?? null;
    if (before === null) continue;
    const after = next[x];
    if (after === null || after < before) {
      refuse(`anti-rollback: syncs.${x} ${after} é anterior ao da release atual ${before}`);
    }
  }
}

function parseLatest(bytes) {
  let l;
  try {
    l = JSON.parse(bytes.toString("utf8"));
  } catch {
    refuse("latest ilegível");
  }
  if (typeof l?.tag !== "string" || !TAG_RE.test(l.tag)) {
    refuse(`tag fora do formato: ${JSON.stringify(l?.tag)}`);
  }
  if (!HEX64.test(l.contentSha256 ?? "")) refuse("latest.contentSha256 malformado");
  const files = Array.isArray(l.files) ? l.files : [];
  if (JSON.stringify(files.map((f) => f?.name).sort()) !== JSON.stringify([...NAMES].sort())) {
    refuse(`o latest deve listar exatamente ${NAMES.join(", ")}`);
  }
  for (const f of files) {
    if (!Number.isInteger(f.bytes) || f.bytes < 0 || !HEX64.test(f.sha256 ?? "")) {
      refuse(`entrada malformada no latest: ${f.name}`);
    }
  }
  return l;
}

async function download(d, base, latest) {
  const out = new Map();
  for (const entry of latest.files) {
    const cap = DATA_FILES.includes(entry.name) ? CAP_GZ : CAP_SMALL;
    if (entry.bytes > cap) refuse(`${entry.name} acima do teto (${cap} bytes)`);
    const url = `${base}/${latest.tag}/${entry.name}`;
    let bytes;
    try {
      bytes = await fetchCapped(d.fetch, url, cap, entry.name);
    } catch (err) {
      // 403 do S3 = URL pré-assinada vencida no caminho: pede outra à rota, uma vez.
      if (err?.status !== 403) throw err;
      bytes = await fetchCapped(d.fetch, url, cap, entry.name);
    }
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) {
      refuse(`${entry.name}: bytes/sha256 não conferem com o latest`);
    }
    out.set(entry.name, bytes);
  }
  return out;
}

function checkData(manifest, blobs) {
  const shas = [];
  for (const f of manifest.files) {
    const gz = blobs.get(f.name);
    if (gz.length !== f.gzBytes || sha256(gz) !== f.gzSha256) {
      refuse(`${f.name}: .gz não confere com o MANIFEST`);
    }
    let raw;
    try {
      raw = gunzipSync(gz, { maxOutputLength: 2 * 1024 * 1024 * 1024 });
    } catch {
      refuse(`${f.name}: gzip ilegível`);
    }
    if (sha256(raw) !== f.sha256) refuse(`${f.name}: conteúdo não confere com o MANIFEST`);
    let rows = 0;
    for (const b of raw) if (b === 0x0a) rows++;
    if (rows !== f.rows) refuse(`${f.name}: ${rows} linhas, o MANIFEST diz ${f.rows}`);
    shas.push(f.sha256);
  }
  if (sha256(shas.map((s) => `${s}\n`).join("")) !== manifest.contentSha256) {
    refuse("contentSha256 não confere com os arquivos");
  }
}

async function currentRelease(d, repo, dir) {
  let tag;
  try {
    const r = await d.gh(["api", `repos/${repo}/releases/latest`]);
    tag = JSON.parse(r.stdout).tag_name;
  } catch (err) {
    const text = `${err?.stderr ?? ""} ${err?.message ?? ""}`;
    if (/HTTP 404|Not Found/.test(text)) return null;
    throw err;
  }
  if (typeof tag !== "string" || !TAG_RE.test(tag)) {
    refuse(`a release latest atual não é data-*: ${JSON.stringify(tag)}`);
  }
  mkdirSync(dir, { recursive: true });
  await d.gh([
    "release",
    "download",
    tag,
    "--repo",
    repo,
    "--pattern",
    "MANIFEST.json",
    "--dir",
    dir,
    "--clobber",
  ]);
  const m = JSON.parse(readFileSync(path.join(dir, "MANIFEST.json"), "utf8"));
  const syncs = {
    sca: m?.syncs?.sca?.finishedAt ?? null,
    sast: m?.syncs?.sast?.finishedAt ?? null,
  };
  return { tag, contentSha256: m?.contentSha256, syncs };
}

async function prune(d, repo, newTag) {
  const r = await d.gh(["release", "list", "--repo", repo, "--limit", "200", "--json", "tagName"]);
  const others = JSON.parse(r.stdout)
    .map((x) => x?.tagName)
    .filter((t) => typeof t === "string" && TAG_RE.test(t) && t !== newTag)
    .sort()
    .reverse();
  for (const tag of others.slice(KEEP - 1)) {
    await d.gh(["release", "delete", tag, "--repo", repo, "--yes", "--cleanup-tag"]);
    d.log(`poda: ${tag}`);
  }
}

async function activity(d, published, lastTag) {
  const r = await d.git(["log", "-1", "--format=%ct"]);
  const last = Number(r.stdout.trim()) * 1000;
  const stale = !Number.isFinite(last) || d.now().getTime() - last > ACTIVITY_DAYS * 86_400_000;
  if (!published && !stale) return;
  const lastRun = d.now().toISOString();
  writeFileSync(d.statusPath, `${JSON.stringify({ lastRun, lastTag }, null, 2)}\n`);
  await d.git(["add", d.statusPath]);
  await d.git(["commit", "-m", `chore(status): ${lastRun}${published ? ` ${lastTag}` : ""}`]);
  await d.git(["push"]);
}

export async function main(argv, deps = {}) {
  const d = { ...realDeps(), ...deps };
  let dry = false;
  for (const a of argv) {
    if (a === "--dry-run") dry = true;
    else {
      d.error(`argumento desconhecido: ${a} (uso: publish.mjs [--dry-run])`);
      return 2;
    }
  }
  const latestUrl = d.env.SDD_CANON_DATA_LATEST_URL || LATEST_URL;
  const repo = d.env.GITHUB_REPOSITORY || REPO_DEFAULT;
  const base = latestUrl.replace(/\/latest$/, "");
  const tmp = mkdtempSync(path.join(d.tmpRoot, "sdd-canon-data-"));
  try {
    // (1)–(3)
    const latest = parseLatest(await fetchCapped(d.fetch, latestUrl, CAP_LATEST, "latest"));
    const blobs = await download(d, base, latest);
    const keys = loadKeys(d.keysPath);
    if (keys.size === 0) refuse("keys.json sem chave confiável");
    const keyId = checkSignature(blobs.get("MANIFEST.json"), blobs.get("MANIFEST.json.sig"), keys);
    const manifest = parseManifest(blobs.get("MANIFEST.json"));
    if (manifest.contentSha256 !== latest.contentSha256) {
      refuse("contentSha256 do latest diverge do MANIFEST assinado");
    }
    checkData(manifest, blobs);
    // (4)
    const current = await currentRelease(d, repo, path.join(tmp, "current"));
    if (current && current.contentSha256 === manifest.contentSha256) {
      d.log(`sem mudança: ${latest.tag} tem o mesmo conteúdo da release ${current.tag}`);
      if (!dry) await activity(d, false, current.tag);
      return 0;
    }
    checkRollback(manifest.syncs, current?.syncs);
    if (dry) {
      d.log(
        `plano: publicar ${latest.tag} (keyId ${keyId}, contentSha256 ${manifest.contentSha256})`,
      );
      return 0;
    }
    // (5)
    const assets = path.join(tmp, "assets");
    mkdirSync(assets);
    const files = NAMES.map((n) => {
      const p = path.join(assets, n);
      writeFileSync(p, blobs.get(n));
      return p;
    });
    const notes = path.join(tmp, "notes.md");
    writeFileSync(
      notes,
      [
        `Security data ${latest.tag} (schema ${SCHEMA}).`,
        "",
        `- contentSha256: \`${manifest.contentSha256}\``,
        `- signed by keyId \`${keyId}\` (ed25519 over MANIFEST.json)`,
        `- syncs: sca ${manifest.syncs.sca}, sast ${manifest.syncs.sast}`,
        `- rows: ${manifest.files.map((f) => `${f.name} ${f.rows}`).join(", ")}`,
        "",
        "Licenses: see LICENSES.md (informative).",
        "",
      ].join("\n"),
    );
    await d.gh([
      "release",
      "create",
      latest.tag,
      "--repo",
      repo,
      "--title",
      latest.tag,
      "--notes-file",
      notes,
      "--latest",
      ...files,
    ]);
    d.log(`publicado ${latest.tag}`);
    // (6)(7)
    await prune(d, repo, latest.tag);
    await activity(d, true, latest.tag);
    return 0;
  } catch (err) {
    d.error(`${err instanceof Refusal ? "recusado" : "falha"}: ${err?.message ?? err}`);
    return 1;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
