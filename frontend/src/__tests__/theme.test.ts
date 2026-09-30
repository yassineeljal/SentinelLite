import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { applyTheme, effectiveTheme, saveTheme, storedTheme } from "../theme";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});
afterEach(() => vi.restoreAllMocks());

describe("theme", () => {
  it("follows the system when nothing was chosen", () => {
    expect(storedTheme()).toBeNull();
    applyTheme(null);
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("stores and restores an explicit choice, and applies it to the page", () => {
    saveTheme("dark");
    expect(storedTheme()).toBe("dark");

    applyTheme("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");

    saveTheme("light");
    applyTheme("light");
    expect(storedTheme()).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("clearing the choice goes back to the system", () => {
    saveTheme("dark");
    applyTheme("dark");

    saveTheme(null);
    applyTheme(null);

    expect(storedTheme()).toBeNull();
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("ignores a stored value that is not a theme", () => {
    localStorage.setItem("sl-theme", "purple");
    expect(storedTheme()).toBeNull();
  });

  it("works when storage is unavailable", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(storedTheme()).toBeNull();
    expect(() => saveTheme("dark")).not.toThrow();
  });

  it("resolves the effective theme from the choice, else from the system", () => {
    expect(effectiveTheme("dark")).toBe("dark");
    expect(effectiveTheme("light")).toBe("light");

    vi.stubGlobal("matchMedia", (query: string) => ({ matches: query.includes("dark") }));
    expect(effectiveTheme(null)).toBe("dark");
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
    expect(effectiveTheme(null)).toBe("light");
    vi.unstubAllGlobals();
  });

  it("falls back to light when the browser cannot say", () => {
    vi.stubGlobal("matchMedia", undefined);
    expect(effectiveTheme(null)).toBe("light");
    vi.unstubAllGlobals();
  });
});
