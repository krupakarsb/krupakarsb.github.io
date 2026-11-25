// Project tabs and the in-browser demos. Everything runs locally; output is inserted as text.
(() => {
  const tabs = [...document.querySelectorAll("[data-tab]")];
  const select = (t) => {
    tabs.forEach((b) => { const on = b === t; b.setAttribute("aria-selected", on); b.tabIndex = on ? 0 : -1; document.getElementById("p-" + b.dataset.tab).hidden = !on; });
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) { e.preventDefault(); const n = tabs[(i + d + tabs.length) % tabs.length]; n.focus(); select(n); }
    });
  });
  document.querySelectorAll('a[href="#try"]').forEach((a) => a.addEventListener("click", () => select(tabs[0])));

  // line builder: [[text, tone], ...] -> <pre>
  const write = (pre, lines) => {
    pre.replaceChildren(...lines.flatMap(([t, tone], i) => {
      const s = document.createElement("span"); if (tone) s.className = tone; s.textContent = t;
      return i < lines.length - 1 ? [s, "\n"] : [s];
    }));
  };

  // manjim 1: audit (weights and messages from manjim 0.2.0)
  const CHECKS = [
    ["MJ001", "high", 20, "config.py:1", "Hard-coded secret in file [aws-access-key: AKIA********]", "A.5.17, A.8.24, CC6.1", "AWS key hard-coded in config.py"],
    ["MJ002", "high", 20, ".env", "Sensitive file present (key, credential, .env)", "A.5.17, A.8.12, CC6.1", ".env file committed"],
    ["MJ003", "medium", 10, ".gitignore", "No .gitignore at root", "A.8.4, CC8.1", "No .gitignore"],
    ["MJ006", "medium", 10, ".github/workflows/ci.yml:4", "CI action pinned to a moving branch [actions/checkout@main]", "A.5.21, A.8.30, CC9.2", "CI uses actions/checkout@main"],
    ["MJ007", "low", 5, "SECURITY.md", "No SECURITY.md (vulnerability disclosure)", "A.5.24, A.8.8, CC7.1", "No SECURITY.md"],
    ["MJ008", "low", 5, "LICENSE", "No LICENSE file", "A.5.32", "No LICENSE"],
  ];
  const fixes = document.querySelector("[data-mj-fixes]"), mjOut = document.querySelector("[data-mj-out]");
  if (fixes) {
    CHECKS.forEach(([id, sev, , , , , label]) => {
      const l = document.createElement("label"), c = document.createElement("input"), t = document.createElement("span"), s = document.createElement("span");
      c.type = "checkbox"; c.dataset.id = id; t.textContent = "Fix: " + label; s.className = "sev"; s.textContent = sev;
      l.append(c, t, s); fixes.appendChild(l);
    });
    const audit = () => {
      const fixed = new Set([...fixes.querySelectorAll("input:checked")].map((c) => c.dataset.id));
      const open = CHECKS.filter((c) => !fixed.has(c[0]));
      const score = 100 - open.reduce((n, c) => n + c[2], 0);
      const files = 2 + (fixed.has("MJ002") ? 0 : 1) + ["MJ003", "MJ007", "MJ008"].filter((id) => fixed.has(id)).length;
      const lines = [["$ manjim audit demo --fail-under 70", "dim"], [`manjim audit demo  score ${score}/100 ${score >= 70 ? "PASS" : "FAIL"}  (${files} files)`, score >= 70 ? "ok" : "bad"]];
      open.forEach(([id, sev, , loc, msg, map]) => lines.push([`  ${sev.padEnd(6)} ${id} ${loc}  ${msg}  (${map})`, sev === "high" ? "bad" : sev === "medium" ? "warn" : "dim"]));
      lines.push(["", ""], [score >= 70 ? "exit 0: score meets --fail-under 70" : "exit 1: score below --fail-under 70", "dim"]);
      write(mjOut, lines);
    };
    fixes.addEventListener("change", audit); audit();
  }

  // manjim 2: risk score = likelihood x impact
  const L = document.querySelector("[data-mj-l]"), I = document.querySelector("[data-mj-i]"), rOut = document.querySelector("[data-mj-risk]");
  if (L) {
    const band = (s) => s >= 20 ? "critical" : s >= 10 ? "high" : s >= 5 ? "medium" : "low";
    const risk = () => {
      const l = +L.value, i = +I.value, s = l * i, b = band(s);
      document.querySelector("[data-mj-lv]").textContent = l; document.querySelector("[data-mj-iv]").textContent = i;
      write(rOut, [[`1 risks: ${b === "critical" ? 1 : 0} critical, ${b === "high" ? 1 : 0} high, ${b === "medium" ? 1 : 0} medium, ${b === "low" ? 1 : 0} low`],
        [`  ${String(s).padStart(2)} ${b.padEnd(8)} A1/R1  SQL injection on customer portal  [mitigate, owner IT]`, b === "critical" || b === "high" ? "bad" : b === "medium" ? "warn" : "ok"],
        ["", ""], [`score = likelihood ${l} x impact ${i}. Bands: 1-4 low, 5-9 medium, 10-16 high, 20-25 critical.`, "dim"]]);
    };
    L.addEventListener("input", risk); I.addEventListener("input", risk); risk();
  }

  // manjim 3: seal and verify (unkeyed seal = SHA-256 of the raw bytes)
  const rep = document.querySelector("[data-mj-report]"), sOut = document.querySelector("[data-mj-seal-out]");
  if (rep) {
    let sealed = null;
    const digest = async (t) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)))].map((b) => b.toString(16).padStart(2, "0")).join("");
    document.querySelector("[data-mj-seal]").addEventListener("click", async () => {
      sealed = await digest(rep.value);
      write(sOut, [["sealed report.json -> report.json.seal (integrity-only)", "ok"], ["sha256 " + sealed, "dim"], ["", ""], ["Now change one character and verify.", "dim"]]);
    });
    document.querySelector("[data-mj-verify]").addEventListener("click", async () => {
      if (!sealed) { write(sOut, [["Seal the report first.", "warn"]]); return; }
      const now = await digest(rep.value);
      write(sOut, now === sealed ? [["OK report.json (sha256)", "ok"]] : [["FAIL report.json: digest mismatch (sha256)", "bad"], ["sealed  " + sealed, "dim"], ["now     " + now, "dim"]]);
    });
  }

  // delbina 1: published benchmark (billed input vs full history, user turns visible)
  const DATA = { 16: { sliding: [0.59, 3.5], delbina: [0.40, 5.0] }, 32: { sliding: [1.08, 6.5], delbina: [0.57, 9.0] }, 64: { sliding: [1.51, 11.0], delbina: [0.82, 12.8] } };
  const seg = document.querySelector("[data-dl-budget]"), bars = document.querySelector("[data-dl-bars]");
  if (seg) {
    const draw = (b) => {
      const rows = [["Full history", 1.00, 13.0], ["Sliding window", ...DATA[b].sliding], ["delbina", ...DATA[b].delbina]];
      bars.replaceChildren(...rows.map(([name, cost, turns]) => {
        const r = document.createElement("div"); r.className = "bar" + (name === "delbina" ? " best" : "");
        const n = document.createElement("b"); n.textContent = name;
        const t = document.createElement("div"); t.className = "track"; const f = document.createElement("div"); f.className = "fill"; f.style.width = Math.min(cost / 1.6, 1) * 100 + "%"; t.appendChild(f);
        const v = document.createElement("span"); v.className = "v"; v.textContent = `${cost.toFixed(2)}x cost · ${turns} turns`;
        r.append(n, t, v); return r;
      }));
    };
    seg.querySelectorAll("button").forEach((btn) => btn.addEventListener("click", () => {
      seg.querySelectorAll("button").forEach((x) => x.setAttribute("aria-checked", x === btn)); draw(btn.dataset.b);
    }));
    draw(32);
  }

  // delbina 2: port of delbina's redact.py (same patterns, same overlap rules), mask or strip
  const PATTERNS = [
    ["private_key", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g],
    ["aws_access_key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
    ["github_token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g],
    ["google_api_key", /\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])/g],
    ["slack_token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
    ["stripe_key", /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g],
    ["anthropic_key", /\bsk-ant-[A-Za-z0-9_\-]{20,}/g],
    ["openai_key", /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g],
    ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g],
    ["bearer_token", /\bbearer\s+(?<v>[A-Za-z0-9._~+/\-]{20,}=*)/gid],
    ["url_password", /(?<=:\/\/)[^/\s:@]+:(?<v>[^/\s@]{3,})@/gd],
    ["assigned_secret", /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*(?:[:=]|\s+is\s+)\s*(["']?)(?<v>[^\s"',;]{6,})\1/gid],
  ];
  const PLACEHOLDER = /^(?:\[\[SECRET_\d+\]\]|\[REDACTED:[a-z_]+\])$/;
  const redact = (text, mode) => {
    let spans = [];
    PATTERNS.forEach(([kind, rx]) => {
      for (const m of text.matchAll(rx)) {
        if (m.indices && m.indices.groups && m.indices.groups.v) spans.push([...m.indices.groups.v, kind]);
        else spans.push([m.index, m.index + m[0].length, kind]);
      }
    });
    spans = spans.filter(([a, b]) => !PLACEHOLDER.test(text.slice(a, b)));
    spans.sort((x, y) => x[0] - y[0] || (y[1] - y[0]) - (x[1] - x[0]));
    const keep = []; let last = -1;
    spans.forEach((sp) => { if (sp[0] >= last) { keep.push(sp); last = sp[1]; } });
    const byValue = new Map(); let out = "", pos = 0;
    keep.forEach(([a, b, kind]) => {
      const v = text.slice(a, b);
      if (!byValue.has(v)) byValue.set(v, byValue.size + 1);
      out += text.slice(pos, a) + (mode === "strip" ? `[REDACTED:${kind}]` : `[[SECRET_${byValue.get(v)}]]`); pos = b;
    });
    return [out + text.slice(pos), keep.map((k) => k[2])];
  };
  if (typeof window !== "undefined") window.__redact = redact;
  const dIn = document.querySelector("[data-dl-in]"), dOut = document.querySelector("[data-dl-out]"), dMode = document.querySelector("[data-dl-mode]");
  if (dIn) {
    const red = () => {
      const mode = dMode.querySelector('[aria-checked="true"]').dataset.m;
      const [t, kinds] = redact(dIn.value, mode);
      write(dOut, [[mode === "mask" ? "sent to the summarizer (mask):" : "stored or published (strip):", "dim"], [t], ["", ""],
        [kinds.length ? `${kinds.length} found: ${kinds.join(", ")}${mode === "mask" ? ". Restored in the summary afterwards." : ". Removed for good."}` : "No secrets found. Pattern-based, so plain-word secrets are not caught.", kinds.length ? "ok" : "dim"]]);
    };
    dMode.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { dMode.querySelectorAll("button").forEach((x) => x.setAttribute("aria-checked", x === b)); red(); }));
    dIn.addEventListener("input", red); red();
  }

  // Hasfragis: show the screenshot only once the file exists
  document.querySelectorAll("[data-optional-shot]").forEach((f) => {
    const img = f.querySelector("img");
    const show = () => { f.hidden = false; };
    if (img.complete && img.naturalWidth) show(); else img.addEventListener("load", show);
  });

  // BitPillars games
  const GAMES = [["loopfall", "LOOPFALL", "Puzzle"], ["ouroboros", "OUROBOROS", "Arcade"], ["echo", "ECHO", "Platformer"], ["slingshot", "SLINGSHOT GARDEN", "One tap"], ["drip", "DRIP", "Arcade"],
    ["heist", "ONE MINUTE HEIST", "Stealth"], ["lumen", "LUMEN", "Puzzle"], ["sundial", "SUNDIAL", "Platformer"], ["trace", "TRACE", "Puzzle"], ["hush", "HUSH", "Stealth"]];
  const grid = document.querySelector("[data-games]");
  if (grid) grid.replaceChildren(...GAMES.map(([dir, name, genre]) => {
    const a = document.createElement("a"); a.href = `https://krupakarsb.github.io/bitpillars/${dir}/`;
    const img = document.createElement("img"); img.src = `assets/games/${dir}.webp`; img.alt = `${name} gameplay`; img.loading = "lazy"; img.width = 960; img.height = 600;
    const p = document.createElement("p"); const b = document.createElement("b"); b.textContent = name; p.append(b, genre);
    a.append(img, p); return a;
  }));
})();
