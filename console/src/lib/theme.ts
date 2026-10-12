export type Theme = "light" | "dark";
export type ThemePref = Theme | "system";
const KEY = "zkfsm-theme";
const listeners = new Set<(t: Theme) => void>();

export function getPref(): ThemePref {
  const t = localStorage.getItem(KEY);
  return t === "light" || t === "dark" ? t : "system";
}

function systemTheme(): Theme {
  return matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function getTheme(): Theme {
  const p = getPref();
  return p === "system" ? systemTheme() : p;
}

/** Stores the preference, applies it and notifies subscribers (the shell's toggle). */
export function setTheme(t: ThemePref) {
  if (t === "system") localStorage.removeItem(KEY);
  else localStorage.setItem(KEY, t);
  const eff = getTheme();
  applyTheme(eff);
  listeners.forEach((l) => l(eff));
}

export function onThemeChange(fn: (t: Theme) => void): () => void {
  listeners.add(fn);
  return () => void listeners.delete(fn);
}

export function applyTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
}
