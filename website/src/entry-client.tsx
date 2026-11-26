import { StrictMode } from 'react'
import { createRoot, hydrateRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import { App } from './App'
import { detectLocaleFromPath, stripLocale } from './i18n/context'
import { DEFAULT_LOCALE } from './i18n/locales'
import { ALL_DOC_SLUG_SET, LEGACY_ROUTE_REDIRECTS, normalizeSlugFromPath } from './lib/routes'
import { preloadRoute } from './lib/preload'
import './styles/fonts.css'
import './styles/global.css'

const rawBase = import.meta.env.BASE_URL ?? '/'
const routerBase = rawBase.endsWith('/') ? rawBase : `${rawBase}/`
const baseNoTrail = routerBase === '/' ? '/' : routerBase.slice(0, -1)

function resolveAppPathname(): string {
  const path = window.location.pathname || '/'
  if (baseNoTrail !== '/' && (path === baseNoTrail || path.startsWith(`${baseNoTrail}/`))) {
    const stripped = path.slice(baseNoTrail.length)
    return stripped.startsWith('/') ? stripped : `/${stripped}`
  }
  return path
}

function canHydrateSsr(rootEl: HTMLElement, appPath: string): boolean {
  if (rootEl.innerHTML.trim().length === 0 || rootEl.innerHTML.includes('<!--app-html-->')) {
    return false
  }
  if (rootEl.dataset.ssr404 === '1') {
    const locale = detectLocaleFromPath(appPath)
    const slug = normalizeSlugFromPath(stripLocale(appPath))
    const isKnownRoute =
      slug === '' || ALL_DOC_SLUG_SET.has(slug) || Boolean(LEGACY_ROUTE_REDIRECTS[slug])
    return locale === DEFAULT_LOCALE && !isKnownRoute
  }
  return true
}

async function bootstrap() {
  if (baseNoTrail !== '/' && window.location.pathname === baseNoTrail) {
    window.history.replaceState(
      null,
      '',
      `${routerBase}${window.location.search}${window.location.hash}`,
    )
  }

  const appPath = resolveAppPathname()
  await preloadRoute(appPath)

  const rootEl = document.getElementById('root')!
  const tree = (
    <StrictMode>
      <BrowserRouter basename={routerBase}>
        <App />
      </BrowserRouter>
    </StrictMode>
  )

  if (canHydrateSsr(rootEl, appPath)) {
    hydrateRoot(rootEl, tree)
  } else {
    delete rootEl.dataset.ssr404
    createRoot(rootEl).render(tree)
  }
}

void bootstrap()
