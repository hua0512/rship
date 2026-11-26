import rawLocales from '../../locales.json'
import type { Locale } from './types'

export interface LocaleDefinition {
  code: Locale
  nativeName: string
  shortLabel: string
  langAttr: string
  default?: boolean
}

export const SUPPORTED_LOCALES = rawLocales as readonly LocaleDefinition[]

export const DEFAULT_LOCALE: Locale =
  (SUPPORTED_LOCALES.find((l) => l.default)?.code ?? 'en') as Locale

export const NON_DEFAULT_LOCALE_CODES: readonly Locale[] = SUPPORTED_LOCALES.filter(
  (l) => l.code !== DEFAULT_LOCALE,
).map((l) => l.code)

export function getLocaleDefinition(locale: Locale): LocaleDefinition {
  return SUPPORTED_LOCALES.find((l) => l.code === locale) ?? SUPPORTED_LOCALES[0]
}
