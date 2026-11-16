.pragma library

// Pure helpers for Plugin Guard: colour maths for the risk levels and small
// formatters. No QML types in here, so it runs under node for tests.

function parseHex(value) {
  var s = String(value || "").trim()
  var m = s.match(/^#([0-9a-fA-F]{2})?([0-9a-fA-F]{6})$/)
  if (!m) {
    var short = s.match(/^#([0-9a-fA-F])([0-9a-fA-F])([0-9a-fA-F])$/)
    if (!short) return null
    m = [null, null, short[1] + short[1] + short[2] + short[2] + short[3] + short[3]]
  }
  return {
    r: parseInt(m[2].substr(0, 2), 16),
    g: parseInt(m[2].substr(2, 2), 16),
    b: parseInt(m[2].substr(4, 2), 16)
  }
}

function toHex(c) {
  function part(n) {
    var v = Math.max(0, Math.min(255, Math.round(n))).toString(16)
    return v.length < 2 ? "0" + v : v
  }
  return "#" + part(c.r) + part(c.g) + part(c.b)
}

// The named colours of a theme's colors.toml, as { name: "#rrggbb" }.
function parseColors(raw) {
  var out = {}
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(/^\s*([A-Za-z0-9_-]+)\s*=\s*["']?(#[0-9A-Fa-f]{6})\b/)
    if (m) out[m[1]] = m[2].toLowerCase()
  }
  return out
}

function luminance(c) {
  function channel(v) {
    v /= 255
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)
  }
  return 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b)
}

function contrast(a, b) {
  var ca = parseHex(a), cb = parseHex(b)
  if (!ca || !cb) return 1
  var la = luminance(ca), lb = luminance(cb)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

function mix(a, b, t) {
  var ca = parseHex(a), cb = parseHex(b)
  if (!ca || !cb) return a
  return toHex({ r: ca.r + (cb.r - ca.r) * t, g: ca.g + (cb.g - ca.g) * t, b: ca.b + (cb.b - ca.b) * t })
}

function toHsl(c) {
  var r = c.r / 255, g = c.g / 255, b = c.b / 255
  var max = Math.max(r, g, b), min = Math.min(r, g, b)
  var h = 0, s = 0, l = (max + min) / 2
  if (max !== min) {
    var d = max - min
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
    if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) * 60
    else if (max === g) h = ((b - r) / d + 2) * 60
    else h = ((r - g) / d + 4) * 60
  }
  return { h: h, s: s, l: l }
}

function fromHsl(h, s, l) {
  function hue(p, q, t) {
    if (t < 0) t += 1
    if (t > 1) t -= 1
    if (t < 1 / 6) return p + (q - p) * 6 * t
    if (t < 1 / 2) return q
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6
    return p
  }
  var q = l < 0.5 ? l * (1 + s) : l + s - l * s
  var p = 2 * l - q
  var k = h / 360
  return toHex({ r: hue(p, q, k + 1 / 3) * 255, g: hue(p, q, k) * 255, b: hue(p, q, k - 1 / 3) * 255 })
}

// A colour for a risk level when the theme does not name one: the theme's
// own red, turned to the level's hue, so it keeps the palette's weight.
var HUES = { safe: 135, caution: 45, danger: 0 }

function derive(level, urgent) {
  var base = parseHex(urgent)
  var hsl = base ? toHsl(base) : { h: 0, s: 0.6, l: 0.55 }
  return fromHsl(HUES[level] !== undefined ? HUES[level] : hsl.h, Math.max(0.45, hsl.s), Math.max(0.35, Math.min(0.7, hsl.l)))
}

// Move a colour toward the foreground until it reads on the background.
function readable(color, background, foreground, minimum) {
  var want = minimum || 3
  if (!parseHex(color)) return foreground
  if (contrast(color, background) >= want) return color
  for (var step = 1; step <= 10; step++) {
    var next = mix(color, foreground, step / 10)
    if (contrast(next, background) >= want) return next
  }
  return foreground
}

// Hue windows a colour must fall in to mean a level. A theme's "green" is not
// always green: Matte Black names an amber "green" and a red "yellow".
var RANGES = { safe: [[70, 175]], caution: [[28, 70]], danger: [[335, 360], [0, 28]] }
var NAMES = {
  safe: ["green", "color2", "bright_green", "color10"],
  caution: ["yellow", "color3", "orange", "bright_yellow", "color11"],
  danger: ["red", "color1", "bright_red", "color9"]
}

function fits(hex, level) {
  var c = parseHex(hex)
  if (!c) return false
  var hsl = toHsl(c)
  if (hsl.s < 0.2 || hsl.l < 0.08 || hsl.l > 0.95) return false
  var ranges = RANGES[level] || []
  for (var i = 0; i < ranges.length; i++)
    if (hsl.h >= ranges[i][0] && hsl.h < ranges[i][1]) return true
  return false
}

function maxSaturation(colors) {
  var top = 0
  for (var key in colors) {
    var c = parseHex(colors[key])
    if (!c) continue
    var hsl = toHsl(c)
    if (hsl.l > 0.08 && hsl.l < 0.95) top = Math.max(top, hsl.s)
  }
  return top
}

// The colour for a risk level, made readable on `background`.
//   colors   parseColors() of the active theme
//   level    "safe" | "caution" | "danger"
// In order: the theme's own name for it (green, yellow, red) when that really
// has the hue; any other palette colour with the hue; for a monochrome theme a
// grey ramp, strongest for danger, so the theme stays monochrome; otherwise the
// theme's red turned to the hue.
function levelColor(colors, level, urgent, background, foreground, minimum) {
  var palette = colors || {}
  var names = NAMES[level] || []
  var picked = ""
  for (var i = 0; i < names.length && !picked; i++)
    if (fits(palette[names[i]], level)) picked = palette[names[i]]
  if (!picked) {
    var best = -1
    for (var key in palette) {
      if (!fits(palette[key], level)) continue
      var s = toHsl(parseHex(palette[key])).s
      if (s > best) { best = s; picked = palette[key] }
    }
  }
  if (!picked && level === "danger" && fits(urgent, "danger")) picked = urgent
  if (!picked) {
    var anchor = parseHex(urgent) ? urgent : foreground
    if (Math.max(maxSaturation(palette), parseHex(urgent) ? toHsl(parseHex(urgent)).s : 0) < 0.15)
      picked = mix(foreground, background, level === "danger" ? 0 : (level === "caution" ? 0.25 : 0.45))
    else
      picked = derive(level, anchor)
  }
  return readable(picked, background, foreground, minimum)
}

function levelOf(severity) {
  return severity === "high" ? "danger" : (severity === "medium" ? "caution" : "info")
}

// "+", "-", "@", "h" (file header) or " " for one line of a unified diff.
function diffKind(line) {
  var s = String(line || "")
  if (s.indexOf("diff --git") === 0 || s.indexOf("index ") === 0 || s.indexOf("+++") === 0 || s.indexOf("---") === 0
      || s.indexOf("new file") === 0 || s.indexOf("deleted file") === 0 || s.indexOf("Binary files") === 0) return "h"
  if (s.charAt(0) === "@") return "@"
  if (s.charAt(0) === "+") return "+"
  if (s.charAt(0) === "-") return "-"
  return " "
}

// Split a snippet around its match so the match stays in view:
// { before, match, after }.
function snippetParts(snippet, start, end, lead) {
  var s = String(snippet || "")
  var a = Math.max(0, Math.min(s.length, Number(start) || 0))
  var b = Math.max(a, Math.min(s.length, Number(end) || 0))
  var keep = lead === undefined ? 34 : lead
  var before = s.substring(0, a)
  if (b > a && before.length > keep + 1) before = "…" + before.substring(before.length - keep)
  return { before: before, match: s.substring(a, b), after: s.substring(b) }
}

function shortSha(sha) {
  return String(sha || "").substring(0, 7)
}

function bySeverity(findings, severity) {
  var out = []
  var list = findings || []
  for (var i = 0; i < list.length; i++)
    if (list[i] && list[i].severity === severity) out.push(list[i])
  return out
}
