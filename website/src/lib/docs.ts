import type { DocMeta } from '../generated/docs-meta'
import type { Locale } from '../i18n/types'
import type { MdxComponent, ResolvedDocMeta } from './docs-loader'

export {
  ALL_DOC_SLUGS,
  ALL_DOC_SLUG_SET,
  DIR_SLUGS,
  LEGACY_ROUTE_REDIRECTS,
  NAV_SECTIONS,
  SLUG_TO_LABS,
  normalizeSlugFromPath,
  slugToRoute,
  type LabName,
  type NavSectionDef,
} from './routes'
export type { MdxComponent, ResolvedDocMeta } from './docs-loader'

type DocsLoaderModule = typeof import('./docs-loader')

let cachedLoader: DocsLoaderModule | null = null
let pendingLoader: Promise<DocsLoaderModule> | null = null

export function loadDocsLoader(): Promise<DocsLoaderModule> {
  if (cachedLoader) return Promise.resolve(cachedLoader)
  if (pendingLoader) return pendingLoader

  pendingLoader = import('./docs-loader')
    .then((mod) => {
      cachedLoader = mod
      pendingLoader = null
      return mod
    })
    .catch((err) => {
      pendingLoader = null
      throw err
    })

  return pendingLoader
}

export function getCachedDocMeta(slug: string, locale: Locale): ResolvedDocMeta | null {
  return cachedLoader ? cachedLoader.resolveDocMeta(slug, locale) : null
}

export function getCachedMdxComponent(activeKey: string): MdxComponent | null {
  return cachedLoader ? cachedLoader.getCachedMdxComponent(activeKey) : null
}

export function getCachedDocsMetaMap(locale: Locale): Record<string, DocMeta> | null {
  return cachedLoader ? cachedLoader.getCachedLocaleMetaMap(locale) : null
}

export async function loadDocForRoute(
  slug: string,
  locale: Locale,
): Promise<{ doc: ResolvedDocMeta; Component: MdxComponent } | null> {
  const loader = await loadDocsLoader()
  const activeKey = loader.resolveActiveDocKey(slug, locale)
  if (!activeKey) return null

  const [, Component] = await Promise.all([
    loader.loadLocaleMetaMap(locale),
    loader.loadDocComponent(activeKey),
  ])

  const doc = loader.resolveDocMeta(slug, locale)
  if (!doc || !Component) return null

  return { doc, Component }
}
