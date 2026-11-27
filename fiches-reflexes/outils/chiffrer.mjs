// Chiffre / déchiffre le contenu des fiches réflexes.
//
//   node fiches-reflexes/outils/chiffrer.mjs chiffrer    → lit data.js (en clair, jamais commité) et écrit data.enc.json
//   node fiches-reflexes/outils/chiffrer.mjs dechiffrer  → recrée data.js à partir de data.enc.json pour le modifier
//
// Le mot de passe est demandé dans la variable d'environnement FR_MDP :
//   FR_MDP='...' node fiches-reflexes/outils/chiffrer.mjs chiffrer
//
// Chiffrement : PBKDF2-SHA256 (600 000 itérations) + AES-GCM 256, déchiffré dans le navigateur par WebCrypto.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLAIR = join(DIR, "data.js"), CHIFFRE = join(DIR, "data.enc.json");
const ITER = 600000;
const { subtle } = globalThis.crypto;
const b64 = u => Buffer.from(u).toString("base64");
const unb64 = s => new Uint8Array(Buffer.from(s, "base64"));

const mdp = process.env.FR_MDP;
if (!mdp) { console.error("Mettre le mot de passe dans FR_MDP"); process.exit(1); }

async function cle(sel){
  const base = await subtle.importKey("raw", new TextEncoder().encode(mdp), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({name: "PBKDF2", salt: sel, iterations: ITER, hash: "SHA-256"}, base, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
}

const mode = process.argv[2];
if (mode === "chiffrer"){
  const src = readFileSync(CLAIR, "utf8");
  const json = JSON.stringify(new Function("const window={};" + src + ";return window.FICHES;")());
  const sel = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({name: "AES-GCM", iv}, await cle(sel), new TextEncoder().encode(json));
  writeFileSync(CHIFFRE, JSON.stringify({v: 1, iter: ITER, sel: b64(sel), iv: b64(iv), data: b64(new Uint8Array(ct))}));
  console.log("data.enc.json écrit");
} else if (mode === "dechiffrer"){
  const e = JSON.parse(readFileSync(CHIFFRE, "utf8"));
  const pt = await subtle.decrypt({name: "AES-GCM", iv: unb64(e.iv)}, await cle(unb64(e.sel)), unb64(e.data));
  writeFileSync(CLAIR, "// Fiches réflexes PCPS (en clair, NE PAS COMMITER)\nwindow.FICHES = " + JSON.stringify(JSON.parse(new TextDecoder().decode(pt)), null, 1) + ";\n");
  console.log("data.js recréé");
} else {
  console.error("Usage : chiffrer | dechiffrer");
}
