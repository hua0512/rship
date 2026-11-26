import rawRoutes from '../../routes.json'
import type { SectionId } from '../i18n/types'

export type LabName =
  | 'VpsMemoryLab'
  | 'ProviderComposer'
  | 'ProviderMatrix'
  | 'Oae2Xray'
  | 'RcloneTranslator'
  | 'ArchitectureGraph'

export interface NavSectionDef {
  id: SectionId
  slugs: string[]
  collapsible?: boolean
  defaultOpen?: boolean
}

interface RouteConfig {
  navSections: NavSectionDef[]
  dirSlugs: string[]
  legacyRedirects: Record<string, string>
  slugLabs: Record<string, LabName[]>
}

const config = rawRoutes as RouteConfig

export const NAV_SECTIONS: NavSectionDef[] = config.navSections
export const ALL_DOC_SLUGS: string[] = NAV_SECTIONS.flatMap((s) => s.slugs)
export const ALL_DOC_SLUG_SET: ReadonlySet<string> = new Set(ALL_DOC_SLUGS)
export const LEGACY_ROUTE_REDIRECTS: Record<string, string> = config.legacyRedirects
export const DIR_SLUGS: ReadonlySet<string> = new Set(config.dirSlugs)
export const SLUG_TO_LABS: Record<string, LabName[]> = config.slugLabs

export function slugToRoute(slug: string): string {
  if (!slug) return '/'
  return DIR_SLUGS.has(slug) ? `/${slug}/` : `/${slug}`
}

export function normalizeSlugFromPath(pathWithoutLocale: string): string {
  const trimmed = pathWithoutLocale.replace(/^\/+|\/+$/g, '')
  if (!trimmed) return ''
  return trimmed.replace(/\/index$/, '')
}
