// The colours cannot be looked at from a test, so their arithmetic is checked instead: every
// text/background pair the stylesheet uses must reach WCAG AA (4.5:1) in both themes, and the two
// copies of the dark theme (system preference, explicit choice) must not drift apart.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");

function block(selector: string): string {
  const start = css.indexOf(selector + " {");
  if (start < 0) throw new Error(`no block for ${selector}`);
  const open = css.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    if (css[i] === "}" && --depth === 0) return css.slice(open + 1, i);
  }
  throw new Error(`unterminated block for ${selector}`);
}

function tokens(body: string): Record<string, string> {
  const found: Record<string, string> = {};
  for (const match of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) found[match[1]] = match[2].trim();
  return found;
}

const light = tokens(block(":root"));
const dark = tokens(block(':root[data-theme="dark"]'));
const systemDark = tokens(block(':root:not([data-theme="light"])'));

function channel(hex: string, at: number): number {
  const value = parseInt(hex.slice(at, at + 2), 16) / 255;
  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  if (!/^#[0-9a-f]{6}$/i.test(hex)) throw new Error(`not a plain #rrggbb colour: ${hex}`);
  return 0.2126 * channel(hex, 1) + 0.7152 * channel(hex, 3) + 0.0722 * channel(hex, 5);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// [foreground token, background token]: text that is actually drawn on that background.
const PAIRS: [string, string][] = [
  ["text", "bg"],
  ["text", "surface"],
  ["text", "surface-2"],
  ["muted", "bg"],
  ["muted", "surface"],
  ["muted", "surface-2"],
  ["accent", "surface"],
  ["accent", "bg"],
  ["accent", "accent-soft"],
  ["accent-contrast", "accent"],
  ["accent-contrast", "accent-hover"],
  ["danger-contrast", "danger"],
  ["danger-contrast", "danger-hover"],
  ["danger-fg", "danger-bg"],
  ["ok-fg", "ok-bg"],
  ["warn-fg", "warn-bg"],
  ["info-fg", "info-bg"],
  ["sev-low-fg", "sev-low-bg"],
  ["sev-medium-fg", "sev-medium-bg"],
  ["sev-high-fg", "sev-high-bg"],
  ["sev-critical-fg", "sev-critical-bg"],
];

describe.each([
  ["light", light],
  ["dark", dark],
])("%s theme", (_name, theme) => {
  it.each(PAIRS)("%s on %s reaches WCAG AA (4.5:1)", (fg, bg) => {
    expect(theme[fg], `--${fg} is defined`).toBeDefined();
    expect(theme[bg], `--${bg} is defined`).toBeDefined();
    expect(contrast(theme[fg], theme[bg])).toBeGreaterThanOrEqual(4.5);
  });

  it("colours drawn as shapes (map points, focus) stay visible against the surface", () => {
    for (const level of ["low", "medium", "high", "critical"]) {
      expect(contrast(theme[`dot-${level}`], theme.surface)).toBeGreaterThanOrEqual(2.2);
    }
  });
});

// Tokens that do not change with the theme are defined once, in the light block.
const SHARED = new Set(["radius", "radius-sm"]);

describe("theme definitions", () => {
  it("define the same tokens in both themes", () => {
    const themed = Object.keys(light)
      .filter((name) => !SHARED.has(name))
      .sort();
    expect(Object.keys(dark).sort()).toEqual(themed);
  });

  it("keep the two copies of the dark theme identical", () => {
    expect(systemDark).toEqual(dark);
  });
});
