import type { ComponentType } from 'react'
import { preloadLabsForSlug } from '../components/labs/registry'
import { detectLocaleFromPath, loadDictionary, stripLocale } from '../i18n/context'
import {
  ALL_DOC_SLUG_SET,
  loadDocForRoute,
  normalizeSlugFromPath,
  type MdxComponent,
  type ResolvedDocMeta,
} from './docs'

export interface DocsLayoutProps {
  doc: ResolvedDocMeta
  DocComponent: MdxComponent
  sidebarOpen: boolean
  onCloseSidebar: () => void
}

type DocsLayoutComp = ComponentType<DocsLayoutProps>
type HomePageComp = ComponentType<Record<string, never>>

let cachedDocsLayout: DocsLayoutComp | null = null
let pendingDocsLayout: Promise<DocsLayoutComp> | null = null

let cachedHomePage: HomePageComp | null = null
let pendingHomePage: Promise<HomePageComp> | null = null

export function getCachedDocsLayout(): DocsLayoutComp | null {
  return cachedDocsLayout
}

export function loadDocsLayout(): Promise<DocsLayoutComp> {
  if (cachedDocsLayout) return Promise.resolve(cachedDocsLayout)
  if (pendingDocsLayout) return pendingDocsLayout

  pendingDocsLayout = import('../layouts/DocsLayout')
    .then((m) => {
      cachedDocsLayout = m.DocsLayout
      pendingDocsLayout = null
      return m.DocsLayout
    })
    .catch((err) => {
      pendingDocsLayout = null
      throw err
    })

  return pendingDocsLayout
}

export function getCachedHomePage(): HomePageComp | null {
  return cachedHomePage
}

export function loadHomePage(): Promise<HomePageComp> {
  if (cachedHomePage) return Promise.resolve(cachedHomePage)
  if (pendingHomePage) return pendingHomePage

  pendingHomePage = import('../pages/HomePage')
    .then((m) => {
      cachedHomePage = m.HomePage
      pendingHomePage = null
      return m.HomePage
    })
    .catch((err) => {
      pendingHomePage = null
      throw err
    })

  return pendingHomePage
}

export function preloadCommandPalette(): void {
  void import('../components/CommandPalette')
}

export async function preloadRoute(pathname: string): Promise<void> {
  const cleanHashless = pathname.split('#')[0] ?? '/'
  const locale = detectLocaleFromPath(cleanHashless)
  const cleanPath = stripLocale(cleanHashless)
  const slug = normalizeSlugFromPath(cleanPath)

  if (!slug) {
    await Promise.all([loadDictionary(locale), loadHomePage()])
    return
  }

  if (!ALL_DOC_SLUG_SET.has(slug)) {
    await loadDictionary(locale)
    return
  }

  await Promise.all([
    loadDictionary(locale),
    loadDocsLayout(),
    loadDocForRoute(slug, locale),
    preloadLabsForSlug(slug),
  ])
}
