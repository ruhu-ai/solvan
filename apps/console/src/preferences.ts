import type { UserPreferences } from "./types";

const STORAGE_KEY = "solvan.console.preferences.v1";
const CHANGE_EVENT = "solvan-preferences-change";

type StoredPreferences = {
  version: number;
  updated_at: string;
  preferences: UserPreferences;
};

export type PreferenceWriteResult = {
  preferences: UserPreferences;
  persisted: boolean;
};

export const defaultPreferences: UserPreferences = {
  theme: "SYSTEM",
  density: "COMFORTABLE",
  motion: "SYSTEM",
  timezone_mode: "BROWSER",
  timezone: null,
};

function validTimezone(value: unknown): value is string {
  if (typeof value !== "string" || !value || value.length > 64) return false;
  try {
    new Intl.DateTimeFormat("en", { timeZone: value }).format();
    return true;
  } catch {
    return false;
  }
}

export function normalizePreferences(value: unknown): UserPreferences {
  if (!value || typeof value !== "object") return { ...defaultPreferences };
  const input = value as Partial<UserPreferences>;
  const theme = ["SYSTEM", "LIGHT", "DARK"].includes(input.theme ?? "") ? input.theme! : "SYSTEM";
  const density = ["COMFORTABLE", "COMPACT"].includes(input.density ?? "") ? input.density! : "COMFORTABLE";
  const motion = ["SYSTEM", "REDUCED", "FULL"].includes(input.motion ?? "") ? input.motion! : "SYSTEM";
  const timezoneMode = ["BROWSER", "UTC", "NAMED"].includes(input.timezone_mode ?? "") ? input.timezone_mode! : "BROWSER";
  const timezone = timezoneMode === "NAMED" && validTimezone(input.timezone) ? input.timezone : null;
  return { theme, density, motion, timezone_mode: timezoneMode, timezone };
}

function readStored(): StoredPreferences | null {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "null") as Partial<StoredPreferences> | null;
    if (!parsed || typeof parsed !== "object") return null;
    return {
      version: typeof parsed.version === "number" ? parsed.version : 0,
      updated_at: typeof parsed.updated_at === "string" ? parsed.updated_at : "",
      preferences: normalizePreferences(parsed.preferences),
    };
  } catch {
    return null;
  }
}

export function readPreferences(): UserPreferences {
  return readStored()?.preferences ?? { ...defaultPreferences };
}

export function applyPreferences(preferences: UserPreferences): void {
  const root = document.documentElement;
  const dark = preferences.theme === "DARK"
    || (preferences.theme === "SYSTEM" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  const reduced = preferences.motion === "REDUCED"
    || (preferences.motion === "SYSTEM" && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  root.dataset.themePreference = preferences.theme.toLowerCase();
  root.dataset.theme = dark ? "dark" : "light";
  root.dataset.density = preferences.density.toLowerCase();
  root.dataset.motion = reduced ? "reduced" : "full";
  root.style.colorScheme = dark ? "dark" : "light";
}

export function writePreferences(preferences: UserPreferences): PreferenceWriteResult {
  const normalized = normalizePreferences(preferences);
  const current = readStored();
  const stored: StoredPreferences = {
    version: (current?.version ?? 0) + 1,
    updated_at: new Date().toISOString(),
    preferences: normalized,
  };
  let persisted = false;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
    persisted = true;
  } catch {
    // Applying a personal display preference must remain safe when browser
    // storage is disabled, full, or blocked by enterprise policy.
  }
  applyPreferences(normalized);
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT, { detail: normalized }));
  return { preferences: normalized, persisted };
}

export function initializePreferences(): void {
  applyPreferences(readPreferences());
}

export function subscribePreferences(listener: (preferences: UserPreferences) => void): () => void {
  const colorQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const refresh = () => {
    const preferences = readPreferences();
    applyPreferences(preferences);
    listener(preferences);
  };
  const changed = (event: Event) => {
    const detail = (event as CustomEvent<UserPreferences>).detail;
    listener(detail ?? readPreferences());
  };
  window.addEventListener(CHANGE_EVENT, changed);
  window.addEventListener("storage", refresh);
  colorQuery.addEventListener("change", refresh);
  motionQuery.addEventListener("change", refresh);
  return () => {
    window.removeEventListener(CHANGE_EVENT, changed);
    window.removeEventListener("storage", refresh);
    colorQuery.removeEventListener("change", refresh);
    motionQuery.removeEventListener("change", refresh);
  };
}

export function formatPreferenceTimestamp(value: string, preferences: UserPreferences): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  const timeZone = preferences.timezone_mode === "UTC"
    ? "UTC"
    : preferences.timezone_mode === "NAMED" && preferences.timezone
      ? preferences.timezone
      : undefined;
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      timeZone,
      timeZoneName: "short",
    }).format(date);
  } catch {
    // A malformed legacy preference or a browser Intl limitation must never
    // take down an operational console surface.
    return date.toISOString();
  }
}
