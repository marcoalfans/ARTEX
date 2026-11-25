"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

import en from "./en.json";
import id from "./id.json";

// ── Types ──────────────────────────────────────────────────────────────────────

export type Locale = "en" | "id";

type NestedRecord = { [key: string]: string | NestedRecord };

interface I18nContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: string) => string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const STORAGE_KEY = "artex-locale";

const messages: Record<Locale, NestedRecord> = { en, id };

/** Resolve a dotted key like "nav.dashboard" against a nested JSON object. */
function resolve(obj: NestedRecord, key: string): string | undefined {
  const parts = key.split(".");
  let current: NestedRecord | string = obj;
  for (const part of parts) {
    if (typeof current !== "object" || current === null) return undefined;
    current = current[part];
  }
  return typeof current === "string" ? current : undefined;
}

function readStoredLocale(): Locale {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "en" || stored === "id") return stored;
  } catch {
    // SSR or storage blocked
  }
  return "en";
}

// ── Context & Provider ─────────────────────────────────────────────────────────

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("en");

  // Hydrate from localStorage on mount
  useEffect(() => {
    setLocaleState(readStoredLocale());
  }, []);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // storage blocked
    }
    // Update the html lang attribute for accessibility
    document.documentElement.lang = next;
  }, []);

  const t = useCallback(
    (key: string): string => {
      // Try current locale first, fall back to English
      return resolve(messages[locale], key) ?? resolve(messages.en, key) ?? key;
    },
    [locale],
  );

  return <I18nContext.Provider value={{ locale, setLocale, t }}>{children}</I18nContext.Provider>;
}

// ── Hook ───────────────────────────────────────────────────────────────────────

export function useTranslation(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useTranslation must be used within an I18nProvider");
  }
  return ctx;
}
