import { lazy, Suspense, useCallback, useEffect, useState, type ComponentType } from 'react'
import { Link, Navigate, useLocation } from 'react-router'
import { preloadLabsForSlug } from './components/labs/registry'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Navbar } from './components/Navbar'
import {
  detectLocaleFromPath,
  getCachedDictionary,
  getFallbackDictionary,
  I18nProvider,
  localizePath,
  stripLocale,
  useI18n,
  type Locale,
} from './i18n/context'
import {
  ALL_DOC_SLUG_SET,
  getCachedDocMeta,
  getCachedMdxComponent,
  LEGACY_ROUTE_REDIRECTS,
  loadDocForRoute,
  normalizeSlugFromPath,
  type MdxComponent,
  type ResolvedDocMeta,
} from './lib/docs'
import {
  getCachedDocsLayout,
  getCachedHomePage,
  loadDocsLayout,
  loadHomePage,
  preloadRoute,
  type DocsLayoutProps,
} from './lib/preload'
import { ThemeProvider } from './lib/theme'

const LazyCommandPalette = lazy(() =>
  import('./components/CommandPalette').then((m) => ({ default: m.CommandPalette })),
)

export function resolvePageMeta(pathname: string) {
  const locale = detectLocaleFromPath(pathname)
  const dict = getCachedDictionary(locale) ?? getFallbackDictionary()
  const cleanPath = stripLocale(pathname)
  const slug = normalizeSlugFromPath(cleanPath)

  if (!dict) {
    return {
      lang: locale === 'zh' ? 'zh-CN' : locale,
      title: 'rship',
      description: '',
    }
  }

  if (!slug) {
    const joiner = /[，。！？、：；]$/.test(dict.home.titlePrimary) ? '' : ' '
    return {
      lang: dict.langAttr,
      title: `rship — ${dict.home.titlePrimary}${joiner}${dict.home.titleMuted}`,
      description: dict.home.lead,
    }
  }

  const doc = getCachedDocMeta(slug, locale)
  if (doc) {
    const title = dict.docs.pageTitles[doc.slug] ?? doc.meta.title
    return {
      lang: dict.langAttr,
      title: `${title} · rship`,
      description: doc.meta.description || dict.home.lead,
    }
  }

  if (ALL_DOC_SLUG_SET.has(slug)) {
    const title = dict.docs.pageTitles[slug] ?? slug
    return {
      lang: dict.langAttr,
      title: `${title} · rship`,
      description: dict.home.lead,
    }
  }

  return {
    lang: dict.langAttr,
    title: `${dict.docs.notFoundTitle} · rship`,
    description: dict.home.lead,
  }
}

function SkipToContentLink() {
  const { t } = useI18n()
  return (
    <a
      href="#main-content"
      className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-50 focus:rounded-md focus:bg-[var(--brand-bg)] focus:px-3.5 focus:py-2 focus:text-[13px] focus:font-semibold focus:text-white focus:shadow-lg focus:outline-none"
    >
      {t.nav.skipToContent}
    </a>
  )
}

function PageHeadSync({ pathname, docMeta }: { pathname: string; docMeta: ResolvedDocMeta | null }) {
  const { t } = useI18n()

  useEffect(() => {
    const meta = resolvePageMeta(pathname)
    document.title = meta.title
    document.documentElement.lang = meta.lang
  }, [pathname, t, docMeta])

  return null
}

function NotFoundView() {
  const { locale, t } = useI18n()
  const homeTo = localizePath('/', locale)
  const startTo = localizePath('/guide/getting-started', locale)

  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="mx-auto max-w-[600px] px-6 py-24 text-center outline-none"
    >
      <div className="mb-2 font-mono text-[12px] font-semibold text-[var(--brand)]">404</div>
      <h1 className="m-0 mb-3 text-[26px] font-semibold tracking-[-0.03em] text-[var(--fg)]">
        {t.docs.notFoundTitle}
      </h1>
      <p className="m-0 mb-7 text-[14px] leading-[1.6] text-[var(--muted)]">
        {t.docs.notFoundBody}
      </p>
      <div className="flex flex-wrap justify-center gap-3">
        <Link
          to={homeTo}
          onMouseEnter={() => void preloadRoute(homeTo)}
          onFocus={() => void preloadRoute(homeTo)}
          className="rounded-md bg-[var(--brand-bg)] px-4 py-2 text-[13px] font-semibold text-white no-underline transition-opacity hover:opacity-90"
        >
          {t.docs.backHome}
        </Link>
        <Link
          to={startTo}
          onMouseEnter={() => void preloadRoute(startTo)}
          onFocus={() => void preloadRoute(startTo)}
          className="rounded-md border border-[var(--border)] bg-[var(--surface)] px-4 py-2 text-[13px] font-medium text-[var(--fg)] no-underline hover:border-[var(--border-strong)]"
        >
          {t.docs.goQuickStart}
        </Link>
      </div>
    </main>
  )
}

function HomeSkeleton() {
  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="mx-auto max-w-[920px] px-4 pb-16 pt-14 outline-none sm:px-8 xl:max-w-[1120px] 2xl:max-w-[1280px]"
      aria-busy="true"
    >
      <div className="mb-4 h-3 w-48 rounded bg-[var(--chrome)]" />
      <div className="mb-3 h-10 w-2/3 rounded bg-[var(--chrome)]" />
      <div className="mb-8 h-4 w-1/2 rounded bg-[var(--chrome)]" />
      <div className="h-56 w-full rounded-[10px] border border-[var(--border)] bg-[var(--surface)]" />
    </main>
  )
}

function DocSkeleton() {
  return (
    <div className="mx-auto flex max-w-[1320px] items-start gap-8 px-4 pb-20 pt-8 sm:px-6 lg:px-8 xl:max-w-[1440px] 2xl:max-w-[1600px]">
      <div className="hidden w-[236px] shrink-0 lg:block" />
      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto min-w-0 max-w-[760px] flex-1 outline-none xl:max-w-[820px] 2xl:max-w-[900px]"
        aria-busy="true"
      >
        <div className="mb-3 h-3 w-28 rounded bg-[var(--chrome)]" />
        <div className="mb-4 h-8 w-2/3 rounded bg-[var(--chrome)]" />
        <div className="mb-8 h-4 w-5/6 rounded bg-[var(--chrome)]" />
        <div className="h-[1px] w-full bg-[var(--border)]" />
        <div className="mt-6 flex flex-col gap-3">
          <div className="h-4 w-full rounded bg-[var(--chrome)]" />
          <div className="h-4 w-11/12 rounded bg-[var(--chrome)]" />
          <div className="h-4 w-4/5 rounded bg-[var(--chrome)]" />
        </div>
      </main>
    </div>
  )
}

type DocsLayoutComp = ComponentType<DocsLayoutProps>
type HomePageComp = ComponentType<Record<string, never>>

function AppShell() {
  const location = useLocation()
  const locale = detectLocaleFromPath(location.pathname)
  const cleanPath = stripLocale(location.pathname)
  const slug = normalizeSlugFromPath(cleanPath)
  const isHome = slug === ''
  const redirectTarget = !isHome ? LEGACY_ROUTE_REDIRECTS[slug] : undefined
  const isDocRoute = !isHome && !redirectTarget && ALL_DOC_SLUG_SET.has(slug)

  const syncHome = isHome ? getCachedHomePage() : null
  const syncLayout = isDocRoute ? getCachedDocsLayout() : null
  const syncDocMeta = isDocRoute ? getCachedDocMeta(slug, locale) : null
  const syncDocComp = syncDocMeta ? getCachedMdxComponent(syncDocMeta.activeKey) : null

  const [searchOpen, setSearchOpen] = useState(false)
  const [searchMounted, setSearchMounted] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const [homeComp, setHomeComp] = useState<HomePageComp | null>(() => getCachedHomePage())
  const [layoutComp, setLayoutComp] = useState<DocsLayoutComp | null>(() => getCachedDocsLayout())
  const [loadedDoc, setLoadedDoc] = useState<{
    slug: string
    locale: Locale
    doc: ResolvedDocMeta
    Component: MdxComponent
  } | null>(() => {
    if (!syncDocMeta || !syncDocComp) return null
    return { slug, locale, doc: syncDocMeta, Component: syncDocComp }
  })
  const [loadFailed, setLoadFailed] = useState(false)

  const ActiveHomePage = syncHome ?? homeComp
  const ActiveDocsLayout = syncLayout ?? layoutComp
  const resolvedDoc =
    isDocRoute && syncDocMeta && syncDocComp
      ? { doc: syncDocMeta, Component: syncDocComp }
      : isDocRoute && loadedDoc && loadedDoc.slug === slug && loadedDoc.locale === locale
        ? { doc: loadedDoc.doc, Component: loadedDoc.Component }
        : null

  const openSearch = useCallback(() => {
    setSearchMounted(true)
    setSearchOpen(true)
  }, [])

  const closeSearch = useCallback(() => {
    setSearchOpen(false)
  }, [])

  const toggleSidebar = useCallback(() => {
    setSidebarOpen((v) => !v)
  }, [])

  const closeSidebar = useCallback(() => {
    setSidebarOpen(false)
  }, [])

  useEffect(() => {
    setSidebarOpen(false)
    setLoadFailed(false)
  }, [location.pathname])

  useEffect(() => {
    if (!isHome || ActiveHomePage) return
    let cancelled = false
    loadHomePage()
      .then((comp) => {
        if (!cancelled) setHomeComp(() => comp)
      })
      .catch(() => {
        if (!cancelled) setLoadFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [isHome, ActiveHomePage])

  useEffect(() => {
    if (!isDocRoute) return
    if (ActiveDocsLayout && resolvedDoc) {
      void preloadLabsForSlug(slug)
      return
    }

    let cancelled = false
    Promise.all([loadDocsLayout(), loadDocForRoute(slug, locale), preloadLabsForSlug(slug)])
      .then(([layout, result]) => {
        if (cancelled) return
        setLayoutComp(() => layout)
        if (result) {
          setLoadedDoc({ slug, locale, doc: result.doc, Component: result.Component })
        }
      })
      .catch(() => {
        if (!cancelled) setLoadFailed(true)
      })

    return () => {
      cancelled = true
    }
  }, [isDocRoute, slug, locale, ActiveDocsLayout, resolvedDoc])

  const contentReady = (isHome && Boolean(ActiveHomePage)) || Boolean(resolvedDoc)

  useEffect(() => {
    if (!contentReady) return
    if (location.hash) {
      const targetId = decodeURIComponent(location.hash.slice(1))
      const el = document.getElementById(targetId)
      if (el) {
        el.scrollIntoView()
        return
      }
    }
    window.scrollTo({ top: 0 })
  }, [location.pathname, location.hash, contentReady])

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setSearchMounted(true)
        setSearchOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  return (
    <I18nProvider locale={locale}>
      <PageHeadSync pathname={location.pathname} docMeta={resolvedDoc?.doc ?? null} />
      <div className="min-h-screen bg-[var(--bg)] text-[var(--fg)]">
        <SkipToContentLink />
        <Navbar
          onOpenSearch={openSearch}
          onToggleSidebar={toggleSidebar}
          sidebarOpen={sidebarOpen}
          showSidebarToggle={!isHome}
        />

        {redirectTarget ? (
          <Navigate to={localizePath(redirectTarget, locale)} replace />
        ) : loadFailed ? (
          <main
            id="main-content"
            tabIndex={-1}
            className="mx-auto max-w-[600px] px-6 py-20 text-center outline-none"
          >
            <p className="m-0 mb-4 text-[14px] text-[var(--muted)]">
              Failed to load page chunk.
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="cursor-pointer rounded-md border border-[var(--border)] bg-[var(--surface)] px-3.5 py-1.5 font-mono text-[12px] text-[var(--fg)]"
            >
              Reload
            </button>
          </main>
        ) : isHome ? (
          ActiveHomePage ? (
            <ErrorBoundary key={location.pathname}>
              <ActiveHomePage />
            </ErrorBoundary>
          ) : (
            <HomeSkeleton />
          )
        ) : !isDocRoute ? (
          <NotFoundView />
        ) : ActiveDocsLayout && resolvedDoc ? (
          <ErrorBoundary key={location.pathname}>
            <ActiveDocsLayout
              doc={resolvedDoc.doc}
              DocComponent={resolvedDoc.Component}
              sidebarOpen={sidebarOpen}
              onCloseSidebar={closeSidebar}
            />
          </ErrorBoundary>
        ) : (
          <DocSkeleton />
        )}

        {searchMounted && (
          <ErrorBoundary>
            <Suspense fallback={null}>
              <LazyCommandPalette open={searchOpen} onClose={closeSearch} />
            </Suspense>
          </ErrorBoundary>
        )}
      </div>
    </I18nProvider>
  )
}

export function App() {
  return (
    <ThemeProvider>
      <AppShell />
    </ThemeProvider>
  )
}
