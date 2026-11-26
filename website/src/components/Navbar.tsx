import { useEffect, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router'
import { Check, ChevronDown, Languages, Menu, Moon, Search, Sun, X } from 'lucide-react'
import { APP_VERSION } from '../generated/version'
import { localizePath, stripLocale, useI18n, type Locale } from '../i18n/context'
import { getLocaleDefinition, SUPPORTED_LOCALES } from '../i18n/locales'
import { preloadCommandPalette, preloadRoute } from '../lib/preload'
import { useTheme } from '../lib/theme'
import { Logo } from './Logo'

interface NavbarProps {
  onOpenSearch: () => void
  onToggleSidebar?: () => void
  sidebarOpen?: boolean
  showSidebarToggle?: boolean
}

function LanguageMenu({
  locale,
  cleanPath,
  onSelect,
}: {
  locale: Locale
  cleanPath: string
  onSelect: (targetLocale: Locale) => void
}) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  const activeLocale = getLocaleDefinition(locale)

  useEffect(() => {
    setOpen(false)
  }, [cleanPath, locale])

  useEffect(() => {
    if (!open) return

    const onPointerDown = (e: PointerEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        triggerRef.current?.focus()
      }
    }

    document.addEventListener('pointerdown', onPointerDown)
    window.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  return (
    <div ref={containerRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Language"
        className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md px-2 text-[12px] text-[var(--muted)] transition-colors hover:bg-[var(--chrome)]/75 hover:text-[var(--fg)]"
      >
        <Languages size={14} aria-hidden="true" />
        <span className="hidden font-mono text-[11px] font-medium sm:inline">
          {activeLocale.shortLabel}
        </span>
        <ChevronDown
          size={12}
          className={`text-[var(--subtle)] transition-transform duration-150 ${
            open ? 'rotate-180' : ''
          }`}
          aria-hidden="true"
        />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Select language"
          className="absolute right-0 top-full z-40 mt-1.5 min-w-[168px] overflow-hidden rounded-[8px] border border-[var(--border)] bg-[var(--surface)] p-1 shadow-lg"
        >
          {SUPPORTED_LOCALES.map((item) => {
            const isCurrent = item.code === locale
            const targetPath = localizePath(cleanPath, item.code)
            return (
              <button
                key={item.code}
                type="button"
                role="menuitemradio"
                aria-checked={isCurrent}
                onMouseEnter={() => void preloadRoute(targetPath)}
                onFocus={() => void preloadRoute(targetPath)}
                onClick={() => {
                  setOpen(false)
                  onSelect(item.code)
                }}
                className={`flex w-full cursor-pointer items-center justify-between gap-3 rounded-md px-2.5 py-1.5 text-left transition-colors ${
                  isCurrent ? 'bg-[var(--chrome)]/75' : 'hover:bg-[var(--chrome)]/50'
                }`}
              >
                <span
                  className={`text-[12.5px] ${
                    isCurrent ? 'font-medium text-[var(--fg)]' : 'text-[var(--muted)]'
                  }`}
                >
                  {item.nativeName}
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="font-mono text-[10.5px] text-[var(--subtle)]">{item.code}</span>
                  {isCurrent ? (
                    <Check size={13} className="text-[var(--brand)]" aria-hidden="true" />
                  ) : (
                    <span className="w-[13px]" aria-hidden="true" />
                  )}
                </span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

export function Navbar({
  onOpenSearch,
  onToggleSidebar,
  sidebarOpen = false,
  showSidebarToggle = false,
}: NavbarProps) {
  const { locale, t } = useI18n()
  const { toggleTheme } = useTheme()
  const location = useLocation()
  const navigate = useNavigate()

  const cleanPath = stripLocale(location.pathname)

  const navItems = [
    { label: t.nav.guide, to: '/guide/getting-started', match: '/guide/' },
    { label: t.nav.providers, to: '/providers/', match: '/providers' },
    { label: t.nav.sdk, to: '/sdk/embedding', match: '/sdk/' },
    { label: t.nav.benchmarks, to: '/benchmarks/', match: '/benchmarks' },
  ]

  const isNavActive = (match: string) => {
    if (match === '/sdk/') {
      return cleanPath.startsWith('/sdk/') || cleanPath.startsWith('/architecture')
    }
    return cleanPath.startsWith(match)
  }

  const switchLocale = (targetLocale: Locale) => {
    if (targetLocale === locale) return
    navigate(localizePath(cleanPath, targetLocale))
  }

  return (
    <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[var(--bg)]/88 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-[1320px] items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3">
          {showSidebarToggle && onToggleSidebar && (
            <button
              type="button"
              onClick={onToggleSidebar}
              aria-label={sidebarOpen ? t.nav.close : t.nav.menu}
              aria-expanded={sidebarOpen}
              className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md border border-[var(--border)] bg-[var(--surface)] text-[var(--fg)] lg:hidden"
            >
              {sidebarOpen ? <X size={15} /> : <Menu size={15} />}
            </button>
          )}

          <Link
            to={localizePath('/', locale)}
            onMouseEnter={() => void preloadRoute(localizePath('/', locale))}
            onFocus={() => void preloadRoute(localizePath('/', locale))}
            className="inline-flex items-center gap-2.5 text-[var(--fg)] no-underline"
          >
            <Logo size={22} />
            <span className="text-[15px] font-semibold tracking-[-0.03em]">rship</span>
            <span className="hidden rounded border border-[var(--border)] bg-[var(--chrome)] px-1.5 py-0.5 font-mono text-[10px] font-medium text-[var(--muted)] sm:inline-block">
              v{APP_VERSION}
            </span>
          </Link>
        </div>

        <nav className="hidden h-full items-stretch gap-6 md:flex" aria-label="Primary navigation">
          {navItems.map((item) => {
            const active = isNavActive(item.match)
            const target = localizePath(item.to, locale)
            return (
              <Link
                key={item.to}
                to={target}
                aria-current={active ? 'page' : undefined}
                onMouseEnter={() => void preloadRoute(target)}
                onFocus={() => void preloadRoute(target)}
                className={`relative inline-flex items-center text-[13px] font-medium no-underline transition-colors ${
                  active ? 'text-[var(--fg)]' : 'text-[var(--muted)] hover:text-[var(--fg)]'
                }`}
              >
                {item.label}
                {active && (
                  <span className="absolute inset-x-0 -bottom-[1px] h-[1.5px] bg-[var(--brand)]" />
                )}
              </Link>
            )
          })}
        </nav>

        <div className="flex items-center gap-1.5 sm:gap-2">
          <button
            type="button"
            onClick={onOpenSearch}
            onMouseEnter={preloadCommandPalette}
            onFocus={preloadCommandPalette}
            className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--surface)]/80 px-2.5 text-[12px] text-[var(--muted)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
            aria-label={t.nav.search}
          >
            <Search size={13} />
            <span className="hidden sm:inline">{t.nav.search}</span>
            <kbd className="font-mono text-[10.5px] text-[var(--subtle)]">⌘K</kbd>
          </button>

          <span className="mx-1 hidden h-4 w-[1px] bg-[var(--border)] sm:block" aria-hidden="true" />

          <LanguageMenu locale={locale} cleanPath={cleanPath} onSelect={switchLocale} />

          <button
            type="button"
            onClick={toggleTheme}
            aria-label={t.nav.toggleTheme}
            title={t.nav.toggleTheme}
            className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-[var(--muted)] transition-colors hover:bg-[var(--chrome)]/75 hover:text-[var(--fg)]"
          >
            <Moon size={15} className="theme-icon-light" aria-hidden="true" />
            <Sun size={15} className="theme-icon-dark" aria-hidden="true" />
          </button>

          <a
            href="https://github.com/hua0512/rship"
            target="_blank"
            rel="noreferrer"
            aria-label="GitHub repository"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-[var(--muted)] transition-colors hover:bg-[var(--chrome)]/75 hover:text-[var(--fg)]"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.76 2.68 1.25 3.33.96.1-.74.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.09-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.17 1.18a10.97 10.97 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.62 1.59.23 2.76.11 3.05.74.8 1.18 1.83 1.18 3.09 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.13 0 1.54-.01 2.78-.01 3.16 0 .31.21.68.8.56A11.51 11.51 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z" />
            </svg>
          </a>
        </div>
      </div>
    </header>
  )
}
