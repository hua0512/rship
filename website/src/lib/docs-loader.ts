import type { ComponentType } from 'react'
import type { DocHeading, DocMeta } from '../generated/docs-meta'
import { DEFAULT_LOCALE } from '../i18n/locales'
import type { Locale, SectionId } from '../i18n/types'
import { ALL_DOC_SLUGS, ALL_DOC_SLUG_SET, NAV_SECTIONS, slugToRoute } from './routes'

export type MdxComponent = ComponentType<{ components?: Record<string, ComponentType<any>> }>

interface MdxModule {
  default: MdxComponent
  frontmatter?: {
    title?: string
    description?: string
    section?: string
  }
}

const META_LOADERS: Record<Locale, () => Promise<Record<string, DocMeta>>> = {
  en: () => import('../generated/docs-meta-en').then((m) => m.DOCS_META),
  zh: () => import('../generated/docs-meta-zh').then((m) => m.DOCS_META),
}

const loadedMetaByLocale = new Map<Locale, Record<string, DocMeta>>()
const pendingMetaByLocale = new Map<Locale, Promise<Record<string, DocMeta>>>()

export function getCachedLocaleMetaMap(locale: Locale): Record<string, DocMeta> | null {
  return loadedMetaByLocale.get(locale) ?? null
}

export function loadLocaleMetaMap(locale: Locale): Promise<Record<string, DocMeta>> {
  const cached = loadedMetaByLocale.get(locale)
  if (cached) return Promise.resolve(cached)

  const pending = pendingMetaByLocale.get(locale)
  if (pending) return pending

  const loader = META_LOADERS[locale] ?? META_LOADERS[DEFAULT_LOCALE]
  const promise = loader()
    .then((meta) => {
      loadedMetaByLocale.set(locale, meta)
      pendingMetaByLocale.delete(locale)
      return meta
    })
    .catch((err) => {
      pendingMetaByLocale.delete(locale)
      throw err
    })

  pendingMetaByLocale.set(locale, promise)
  return promise
}

const rawMdxLoaders = import.meta.glob<MdxModule>('../../content/**/*.mdx')
const mdxLoaderRegistry: Record<string, () => Promise<MdxModule>> = {}

for (const [key, loader] of Object.entries(rawMdxLoaders)) {
  const normalized = key.replace(/\\/g, '/')
  const match = normalized.match(/\.\.\/\.\.\/content\/([a-z]{2}(?:-[A-Za-z]{2})?)\/(.+)\.mdx$/)
  if (!match) continue
  const locale = match[1]
  const rawSlug = match[2].replace(/\/index$/, '').replace(/^index$/, '')
  mdxLoaderRegistry[`${locale}:${rawSlug}`] = loader
}

const loadedMdxCache = new Map<string, MdxComponent>()
const pendingMdxLoads = new Map<string, Promise<MdxComponent | null>>()

export function getCachedMdxComponent(activeKey: string): MdxComponent | null {
  return loadedMdxCache.get(activeKey) ?? null
}

export function resolveActiveDocKey(slug: string, locale: Locale): string | null {
  if (!ALL_DOC_SLUG_SET.has(slug)) return null
  const localizedKey = `${locale}:${slug}`
  if (mdxLoaderRegistry[localizedKey]) return localizedKey
  const fallbackKey = `${DEFAULT_LOCALE}:${slug}`
  if (mdxLoaderRegistry[fallbackKey]) return fallbackKey
  return null
}

export function loadDocComponent(activeKey: string): Promise<MdxComponent | null> {
  const cached = loadedMdxCache.get(activeKey)
  if (cached) return Promise.resolve(cached)

  const pending = pendingMdxLoads.get(activeKey)
  if (pending) return pending

  const loader = mdxLoaderRegistry[activeKey]
  if (!loader) return Promise.resolve(null)

  const promise = loader()
    .then((mod) => {
      loadedMdxCache.set(activeKey, mod.default)
      pendingMdxLoads.delete(activeKey)
      return mod.default
    })
    .catch((err) => {
      pendingMdxLoads.delete(activeKey)
      throw err
    })

  pendingMdxLoads.set(activeKey, promise)
  return promise
}

export interface ResolvedDocMeta {
  slug: string
  activeKey: string
  routePath: string
  section: SectionId
  meta: DocMeta
  headings: DocHeading[]
  isFallback: boolean
  prevSlug: string | null
  nextSlug: string | null
  githubEditUrl: string
}

export function resolveDocMeta(slug: string, locale: Locale): ResolvedDocMeta | null {
  if (!ALL_DOC_SLUG_SET.has(slug)) {
    return null
  }

  const localeMap = loadedMetaByLocale.get(locale)
  const meta = localeMap?.[slug]
  const activeKey = resolveActiveDocKey(slug, locale)

  if (!meta || !activeKey) {
    return null
  }

  const idx = ALL_DOC_SLUGS.indexOf(slug)
  const prevSlug = idx > 0 ? ALL_DOC_SLUGS[idx - 1] : null
  const nextSlug = idx < ALL_DOC_SLUGS.length - 1 ? ALL_DOC_SLUGS[idx + 1] : null
  const sectionObj = NAV_SECTIONS.find((s) => s.slugs.includes(slug))

  return {
    slug,
    activeKey,
    routePath: slugToRoute(slug),
    section: sectionObj?.id ?? 'getting-started',
    meta,
    headings: meta.headings,
    isFallback: Boolean(meta.isFallback),
    prevSlug,
    nextSlug,
    githubEditUrl: `https://github.com/hua0512/rship/edit/main/website/${meta.sourcePath}`,
  }
}
