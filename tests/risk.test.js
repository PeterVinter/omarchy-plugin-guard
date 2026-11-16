// node tests/risk.test.js
const fs = require("fs")
const path = require("path")
const assert = require("assert")
const src = fs.readFileSync(path.join(__dirname, "..", "Risk.js"), "utf8").replace(".pragma library", "")
const R = new Function(src + "; return { parseHex, parseColors, contrast, levelColor, derive, readable, snippetParts, diffKind, fits, bySeverity, shortSha }")()

assert.deepStrictEqual(R.parseHex("#ff0080"), { r: 255, g: 0, b: 128 })
assert.deepStrictEqual(R.parseHex("#80ff0080"), { r: 255, g: 0, b: 128 })
assert.strictEqual(R.parseHex("red"), null)
assert.strictEqual(Math.round(R.contrast("#000000", "#ffffff")), 21)

const colors = R.parseColors('accent = "#f38d70"\nred = "#fd6883"\ngreen = "#adda78" # note\nyellow = "#f9cc6c"\nbroken = nope\n')
assert.strictEqual(colors.green, "#adda78")
assert.strictEqual(colors.broken, undefined)

// A theme's own colours are used as they are when they read on the background.
assert.strictEqual(R.levelColor(colors, "safe", "#fd6883", "#2c2525", "#e6d9db"), "#adda78")
assert.strictEqual(R.levelColor(colors, "caution", "#fd6883", "#2c2525", "#e6d9db"), "#f9cc6c")
assert.strictEqual(R.levelColor(colors, "danger", "#fd6883", "#2c2525", "#e6d9db"), "#fd6883")

// Matte Black calls an amber "green" and a red "yellow": hue wins over the name.
const matte = { green: "#ffc107", yellow: "#b91c1c", red: "#d35f5f" }
assert.ok(!R.fits(matte.green, "safe"))
assert.strictEqual(R.levelColor(matte, "caution", matte.red, "#121212", "#bebebe"), "#ffc107")
assert.ok(R.fits(R.levelColor(matte, "safe", matte.red, "#121212", "#bebebe"), "safe"))

// No palette at all: derived from the theme's red, still the right hue and readable.
for (const level of ["safe", "caution", "danger"]) {
  const c = R.levelColor({}, level, "#a55555", "#101315", "#cacccc")
  assert.ok(R.fits(c, level), level + " " + c)
  assert.ok(R.contrast(c, "#101315") >= 3, level)
}

// Monochrome theme stays monochrome, danger strongest.
const mono = { red: "#2a2a2a", green: "#3a3a3a", yellow: "#4a4a4a" }
const md = R.levelColor(mono, "danger", "#2a2a2a", "#ffffff", "#000000")
const ms = R.levelColor(mono, "safe", "#2a2a2a", "#ffffff", "#000000")
assert.ok(R.contrast(md, "#ffffff") > R.contrast(ms, "#ffffff"))
assert.ok(R.contrast(ms, "#ffffff") >= 3)

// Light theme: a pale yellow is pulled toward the foreground until readable.
assert.ok(R.contrast(R.levelColor({ yellow: "#f9e2af" }, "caution", "#d20f39", "#eff1f5", "#4c4f69"), "#eff1f5") >= 3)

assert.deepStrictEqual(R.snippetParts("abc MATCH tail", 4, 9), { before: "abc ", match: "MATCH", after: " tail" })
assert.strictEqual(R.snippetParts("x".repeat(60) + "HIT", 60, 63, 10).before, "…" + "x".repeat(10))
assert.deepStrictEqual(R.snippetParts("<img src=x>", 0, 0), { before: "", match: "", after: "<img src=x>" })
assert.strictEqual(R.diffKind("+++ b/x"), "h")
assert.strictEqual(R.diffKind("+added"), "+")
assert.strictEqual(R.diffKind("-gone"), "-")
assert.strictEqual(R.diffKind("@@ -1 +1 @@"), "@")
assert.strictEqual(R.bySeverity([{ severity: "high" }, { severity: "info" }, null], "high").length, 1)
console.log("risk.test.js: ok")
