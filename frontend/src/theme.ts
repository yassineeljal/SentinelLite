// Light / dark theme. No stored choice means "follow the system" (the CSS media query does that);
// an explicit choice is kept in localStorage and applied as `data-theme` on <html>, which the CSS
// lets win over the system setting. Storage can be unavailable (private mode, blocked): every
// access is guarded and the app then simply follows the system.

export type ThemeChoice = "light" | "dark" | null;

const KEY = "sl-theme";

export function storedTheme(): ThemeChoice {
  try {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function saveTheme(choice: ThemeChoice): void {
  try {
    if (choice) localStorage.setItem(KEY, choice);
    else localStorage.removeItem(KEY);
  } catch {
    // Not persisted: the choice still applies to this page view.
  }
}

export function applyTheme(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice) root.dataset.theme = choice;
  else delete root.dataset.theme;
}

export function effectiveTheme(choice: ThemeChoice): "light" | "dark" {
  if (choice) return choice;
  const dark =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;
  return dark ? "dark" : "light";
}
