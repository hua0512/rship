import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { DEFAULT_LOCALE, NON_DEFAULT_LOCALE_CODES } from './locales'
import type { Dictionary, Locale } from './types'

export type { Dictionary, Locale, SectionId } from './types'

const DICTIONARY_LOADERS: Record<Locale, () => Promise<Dictionary>> = {
  en: () => import('./en').then((m) => m.en),
  zh: () => import('./zh').then((m) => m.zh),
}

const loadedDictionaries = new Map<Locale, Dictionary>()
const pendingDictionaries = new Map<Locale, Promise<Dictionary>>()

export function getCachedDictionary(locale: Locale): Dictionary | null {
  return loadedDictionaries.get(locale) ?? null
}

export function getFallbackDictionary(): Dictionary | null {
  return (
    loadedDictionaries.get(DEFAULT_LOCALE) ??
    loadedDictionaries.values().next().value ??
    null
  )
}

export function loadDictionary(locale: Locale): Promise<Dictionary> {
  const cached = loadedDictionaries.get(locale)
  if (cached) return Promise.resolve(cached)

  const pending = pendingDictionaries.get(locale)
  if (pending) return pending

  const loader = DICTIONARY_LOADERS[locale] ?? DICTIONARY_LOADERS[DEFAULT_LOCALE]
  const promise = loader()
    .then((dict) => {
      loadedDictionaries.set(locale, dict)
      pendingDictionaries.delete(locale)
      return dict
    })
    .catch((err) => {
      pendingDictionaries.delete(locale)
      throw err
    })

  pendingDictionaries.set(locale, promise)
  return promise
}

export function detectLocaleFromPath(pathname: string): Locale {
  for (const code of NON_DEFAULT_LOCALE_CODES) {
    if (pathname === `/${code}` || pathname.startsWith(`/${code}/`)) {
      return code
    }
  }
  return DEFAULT_LOCALE
}

export function stripLocale(pathname: string): string {
  for (const code of NON_DEFAULT_LOCALE_CODES) {
    if (pathname === `/${code}` || pathname === `/${code}/`) {
      return '/'
    }
    if (pathname.startsWith(`/${code}/`)) {
      return pathname.slice(code.length + 1) || '/'
    }
  }
  return pathname || '/'
}

export function localizePath(path: string, locale: Locale): string {
  if (/^https?:\/\//i.test(path) || path.startsWith('#')) return path
  const clean = stripLocale(path.startsWith('/') ? path : `/${path}`)
  if (locale !== DEFAULT_LOCALE) {
    return clean === '/' ? `/${locale}/` : `/${locale}${clean}`
  }
  return clean
}

interface I18nContextValue {
  locale: Locale
  t: Dictionary
}

const I18nContext = createContext<I18nContextValue | null>(null)

export function I18nProvider({ locale, children }: { locale: Locale; children: ReactNode }) {
  const syncDict = getCachedDictionary(locale)
  const [loadedDict, setLoadedDict] = useState<Dictionary | null>(
    () => syncDict ?? getFallbackDictionary(),
  )

  useEffect(() => {
    if (syncDict) {
      setLoadedDict(syncDict)
      return
    }
    let cancelled = false
    void loadDictionary(locale)
      .then((dict) => {
        if (!cancelled) {
          setLoadedDict(dict)
        }
      })
      .catch(() => {
        // Keep currently loaded dictionary on transient network failure
      })
    return () => {
      cancelled = true
    }
  }, [locale, syncDict])

  const activeDict = syncDict ?? loadedDict ?? getFallbackDictionary()

  const value = useMemo<I18nContextValue | null>(
    () => (activeDict ? { locale, t: activeDict } : null),
    [locale, activeDict],
  )

  if (!value) return null

  return <I18nContext value={value}>{children}</I18nContext>
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext)
  if (!ctx) {
    throw new Error('useI18n must be used within an I18nProvider after dictionary preload')
  }
  return ctx
}
