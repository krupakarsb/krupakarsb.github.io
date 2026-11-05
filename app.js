// Running UTC clock.
(() => {
  const el = document.querySelector("[data-clock]");
  const t = el.querySelector("[data-time]"), d = el.querySelector("[data-date]");
  const days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const pad = (n) => String(n).padStart(2, "0");
  const tick = () => {
    const n = new Date();
    t.textContent = `${pad(n.getUTCHours())}:${pad(n.getUTCMinutes())}:${pad(n.getUTCSeconds())}`;
    d.textContent = `${days[n.getUTCDay()]} ${pad(n.getUTCDate())} ${months[n.getUTCMonth()]} ${n.getUTCFullYear()}`;
  };
  tick();
  setInterval(tick, 1000);
})();

// The zlang demo. It runs in this page only and sends nothing anywhere.
// Output is inserted as text, never as HTML.
(() => {
  const term = document.querySelector("[data-term]");
  const out = term.querySelector("[data-out]"), form = term.querySelector("[data-form]"), input = form.querySelector("input");
  const past = []; let pos = 0;
  const vars = {};
  const bytes = (s) => new TextEncoder().encode(s);
  const text = (b) => new TextDecoder("utf-8", { fatal: true }).decode(b);
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
  const ALGOS = { sha256: "SHA-256", sha512: "SHA-512", sha1: "SHA-1" };
  const NETWORK = ["scan", "lookup", "ping", "headers"];
  const HELP = {
    hash: 'hash text "text" [sha256|sha512|sha1]   Fingerprint text. In the brackets is an optional choice.',
    encode: 'encode <base64|hex|url> "text"          Encode text.',
    decode: 'decode <base64|hex|url> "text"          Decode text.',
    generate: "generate password|pin [--length n]    Create a strong random password or PIN.",
    subnet: "subnet <network>                        Work out a network's range and host count.",
    set: "set <name> = <value>                    Create a variable, then use it as $name.",
    whoami: "whoami                                  Show who you are in this demo.",
    history: "history                                 Show past commands.",
    help: "help [command]                          List commands, or explain one.",
    clear: "clear                                   Empty the screen.",
  };

  const print = (line, tone) => {
    const p = document.createElement("p");
    if (tone) p.className = tone;
    p.textContent = line || " ";
    out.appendChild(p);
  };
  const echo = (line) => {
    const p = document.createElement("p"); p.className = "echo";
    const s = document.createElement("span"); s.textContent = "zlang › "; p.append(s, line); out.appendChild(p);
  };

  function tokenize(line) {
    const tokens = []; let i = 0;
    while (i < line.length) {
      const ch = line[i];
      if (/\s/.test(ch)) { i++; continue; }
      if (ch === "#") break;
      if (ch === '"' || ch === "'") {
        let word = "", closed = false; i++;
        while (i < line.length) {
          if (ch === '"' && line[i] === "\\" && line[i + 1] === '"') { word += '"'; i += 2; continue; }
          if (line[i] === ch) { closed = true; i++; break; }
          word += line[i++];
        }
        if (!closed) throw new Error(`Missing closing ${ch} in this line.`);
        tokens.push({ word, expand: ch === '"' });
        continue;
      }
      const start = i;
      while (i < line.length && !/\s/.test(line[i])) i++;
      tokens.push({ word: line.slice(start, i), expand: true });
    }
    return tokens;
  }
  const expand = (t) => !t.expand ? t.word : t.word.replace(/\$([A-Za-z_]\w*)/g, (_, name) => {
    if (!(name in vars)) throw new Error(`$${name} is not set. Use: set ${name} = value`);
    return vars[name];
  });
  const below = (n) => {               // an unbiased whole number from 0 up to n
    const limit = Math.floor(0x100000000 / n) * n, box = new Uint32Array(1);
    do { crypto.getRandomValues(box); } while (box[0] >= limit);
    return box[0] % n;
  };
  const usage = (name) => { throw new Error("Usage: " + HELP[name].split(/\s{2,}/)[0]); };

  function convert(mode, format, value) {
    if (mode === "encode") {
      const raw = bytes(value);
      if (format === "base64") return btoa(String.fromCharCode(...raw));
      if (format === "hex") return hex(raw);
      return encodeURIComponent(value).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
    }
    try {
      if (format === "base64") {
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4) throw 0;
        return text(Uint8Array.from(atob(value), (c) => c.charCodeAt(0)));
      }
      if (format === "hex") {
        if (value.length % 2 || /[^0-9a-f]/i.test(value)) throw 0;
        return text(Uint8Array.from(value.match(/../g) || [], (h) => parseInt(h, 16)));
      }
      return decodeURIComponent(value);
    } catch (e) { throw new Error(`That is not valid ${format} text.`); }
  }

  async function run(line) {
    const tokens = tokenize(line);
    if (!tokens.length) return;
    if (tokens.some((t) => t.word === "|" && !/["']/.test(line.slice(line.indexOf("|") - 1, line.indexOf("|") + 2)))) { print("Pipelines run in the full zlang. This demo runs one command at a time.", "warn"); return; }
    const name = tokens[0].word.toLowerCase();
    const args = tokens.slice(1).map(expand);
    if (NETWORK.includes(name)) { print(`Refused: ${args[0] || "that target"} is not in scope. This demo has no network access.`, "bad"); return; }
    if (name === "help") {
      if (args[0]) { const h = HELP[args[0].toLowerCase()]; print(h || `Unknown command: ${args[0]}.`, h ? "dim" : "bad"); return; }
      Object.values(HELP).forEach((h) => print(h, "dim"));
      print("scan, lookup, ping and headers are off here. They run in the full zlang.", "warn");
      return;
    }
    if (name === "hash") {
      if (args[0]?.toLowerCase() !== "text" || args.length < 2 || args.length > 3) usage("hash");
      const algo = (args[2] || "sha256").toLowerCase();
      if (!ALGOS[algo]) throw new Error(`Unknown algorithm: ${algo}. Choose from sha256, sha512, sha1.`);
      if (!crypto.subtle) throw new Error("Hashing needs a secure https page.");
      print(hex(await crypto.subtle.digest(ALGOS[algo], bytes(args[1]))), "ok");
      if (algo === "sha1") print("sha1 is broken for security use. Fine for matching old records.", "warn");
      return;
    }
    if (name === "encode" || name === "decode") {
      const format = (args[0] || "").toLowerCase();
      if (args.length !== 2) usage(name);
      if (!["base64", "hex", "url"].includes(format)) throw new Error(`Unknown format: ${format}. Choose from base64, hex, url.`);
      print(convert(name, format, args[1]), "ok");
      return;
    }
    if (name === "generate") {
      const kind = (args[0] || "").toLowerCase();
      const at = args.indexOf("--length"), length = at > 0 ? Number(args[at + 1]) : (kind === "pin" ? 6 : 20);
      if (!["password", "pin"].includes(kind)) usage("generate");
      const [low, high] = kind === "pin" ? [4, 12] : [8, 128];
      if (!Number.isInteger(length) || length < low || length > high) throw new Error(`Length must be from ${low} to ${high}.`);
      const pool = kind === "pin" ? "0123456789" : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
      print(Array.from({ length }, () => pool[below(pool.length)]).join(""), "ok");
      print("Made in your browser. It was not sent or saved.", "dim");
      return;
    }
    if (name === "subnet") {
      const m = (args[0] || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
      if (!m || m.slice(1, 5).some((x) => +x > 255) || +m[5] > 32) throw new Error("Example: subnet 192.168.56.0/24");
      const prefix = +m[5], ip = m.slice(1, 5).reduce((n, x) => n * 256 + +x, 0), size = 2 ** (32 - prefix), network = Math.floor(ip / size) * size;
      const dotted = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");
      const edge = prefix <= 30 ? 1 : 0;
      print(`network       ${dotted(network)}/${prefix}`);
      print(`first host    ${dotted(network + edge)}`);
      print(`last host     ${dotted(network + size - 1 - edge)}`);
      print(`usable hosts  ${(prefix <= 30 ? size - 2 : size).toLocaleString("en-US")}`);
      return;
    }
    if (name === "set") {
      if (args.length !== 3 || args[1] !== "=" || !/^[A-Za-z_]\w*$/.test(args[0])) usage("set");
      vars[args[0]] = args[2]; print(`${args[0]} = ${args[2]}`, "dim");
      return;
    }
    if (name === "whoami") { print("user  visitor\nrole  demo\nnote  Commands stay in this page."); return; }
    if (name === "history") { past.slice(0, -1).forEach((l, i) => print(`${String(i + 1).padStart(3)}  ${l}`, "dim")); return; }
    throw new Error(`Unknown command: ${name}. Type 'help' for the list.`);
  }

  async function submit(line) {
    past.push(line); pos = past.length;
    echo(line);
    if (line.toLowerCase() === "clear") { out.replaceChildren(); return; }
    try { await run(line); } catch (e) { print(e.message, "bad"); }
    out.scrollTop = out.scrollHeight;
  }

  term.addEventListener("click", () => { if (!window.getSelection().toString()) input.focus(); });
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const line = input.value.trim();
    input.value = "";
    if (line) submit(line);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp" && pos > 0) { e.preventDefault(); input.value = past[--pos]; }
    else if (e.key === "ArrowDown") { e.preventDefault(); pos = Math.min(pos + 1, past.length); input.value = past[pos] || ""; }
    else if (e.key === "Tab" && input.value && !input.value.includes(" ")) {
      e.preventDefault();
      const hits = Object.keys(HELP).filter((n) => n.startsWith(input.value.toLowerCase()));
      if (hits.length === 1) input.value = hits[0] + " ";
      else if (hits.length) { echo(input.value); print(hits.join("   "), "dim"); out.scrollTop = out.scrollHeight; }
    }
  });
  document.querySelectorAll("[data-try]").forEach((b) => b.addEventListener("click", () => { submit(b.dataset.try); input.focus({ preventScroll: true }); }));
})();
