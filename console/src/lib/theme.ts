export type Theme = "light" | "dark";
const KEY = "zkfsm-theme";

export function getTheme(): Theme {
  const t = localStorage.getItem(KEY);
  if (t === "light" || t === "dark") return t;
  return matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function setTheme(t: Theme) {
  localStorage.setItem(KEY, t);
}

export function applyTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
}
