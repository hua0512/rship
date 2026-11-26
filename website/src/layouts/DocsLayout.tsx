import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { MDXProvider } from '@mdx-js/react'
import { ArrowLeft, ArrowRight, Check, ChevronRight, Copy, ExternalLink, Info } from 'lucide-react'
import { useCopyToClipboard } from '../hooks/useCopyToClipboard'
import { localizePath, useI18n, type SectionId } from '../i18n/context'
import { NAV_SECTIONS, slugToRoute } from '../lib/docs'
import { preloadRoute, type DocsLayoutProps } from '../lib/preload'
import { useMdxComponents } from '../components/mdx/MdxPrimitives'

const rawMarkdownCache = new Map<string, string>()

async function fetchRawMarkdown(rawMdPath: string): Promise<string | null> {
  const cached = rawMarkdownCache.get(rawMdPath)
  if (cached !== undefined) return cached

  try {
    const res = await fetch(`${import.meta.env.BASE_URL}raw/${rawMdPath}`)
    if (!res.ok) return null
    const text = await res.text()
    rawMarkdownCache.set(rawMdPath, text)
    return text
  } catch {
    return null
  }
}

export function DocsLayout({ doc, DocComponent, sidebarOpen, onCloseSidebar }: DocsLayoutProps) {
  const { locale, t } = useI18n()
  const mdxComponents = useMdxComponents()
  const { copied: copiedMd, copy, reset: resetCopyMd } = useCopyToClipboard(1500)
  const [activeHeading, setActiveHeading] = useState<string>(doc.headings[0]?.id ?? '')
  const [openSections, setOpenSections] = useState<Record<SectionId, boolean>>(() => {
    const initial = {} as Record<SectionId, boolean>
    for (const s of NAV_SECTIONS) {
      initial[s.id] = !s.collapsible || Boolean(s.defaultOpen) || s.id === doc.section
    }
    return initial
  })

  useEffect(() => {
    setActiveHeading(doc.headings[0]?.id ?? '')
    resetCopyMd()
  }, [doc.slug, doc.headings, resetCopyMd])

  useEffect(() => {
    setOpenSections((prev) => (prev[doc.section] ? prev : { ...prev, [doc.section]: true }))
  }, [doc.section])

  const toggleSection = (id: SectionId) => {
    setOpenSections((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  useEffect(() => {
    if (!sidebarOpen) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseSidebar()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [sidebarOpen, onCloseSidebar])

  useEffect(() => {
    if (typeof window === 'undefined' || !doc.headings.length) return
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveHeading(entry.target.id)
            break
          }
        }
      },
      { rootMargin: '-80px 0px -65% 0px', threshold: 0.1 },
    )

    for (const h of doc.headings) {
      const el = document.getElementById(h.id)
      if (el) observer.observe(el)
    }

    return () => observer.disconnect()
  }, [doc.slug, doc.headings])

  const copyMarkdown = async () => {
    const md = await fetchRawMarkdown(doc.meta.rawMdPath)
    if (md) {
      await copy(md)
    }
  }

  const pageTitle = t.docs.pageTitles[doc.slug] ?? doc.meta.title
  const sectionLabel = t.docs.sections[doc.section]
  const llmsUrl = `${import.meta.env.BASE_URL}llms.txt`
  const privacyTo = localizePath('/privacy', locale)
  const prevTo = doc.prevSlug ? localizePath(slugToRoute(doc.prevSlug), locale) : null
  const nextTo = doc.nextSlug ? localizePath(slugToRoute(doc.nextSlug), locale) : null

  const sidebarContent = (
    <nav className="flex flex-col gap-5 py-2" aria-label="Documentation sidebar">
      {NAV_SECTIONS.map((section) => {
        const isCollapsible = Boolean(section.collapsible)
        const isOpen = !isCollapsible || Boolean(openSections[section.id])

        return (
          <div key={section.id}>
            {isCollapsible ? (
              <button
                type="button"
                aria-expanded={isOpen}
                aria-controls={`sidebar-sec-${section.id}`}
                onClick={() => toggleSection(section.id)}
                className="flex w-full cursor-pointer items-center justify-between gap-2 py-1 text-left text-[12px] font-semibold tracking-[-0.01em] text-[var(--fg)] transition-colors hover:text-[var(--brand)]"
              >
                <span>{t.docs.sections[section.id]}</span>
                <span className="inline-flex items-center gap-1.5">
                  {!isOpen && (
                    <span className="font-mono text-[10.5px] font-normal text-[var(--subtle)]">
                      {section.slugs.length}
                    </span>
                  )}
                  <ChevronRight
                    size={13}
                    className={`text-[var(--subtle)] transition-transform duration-150 ${
                      isOpen ? 'rotate-90 text-[var(--muted)]' : ''
                    }`}
                  />
                </span>
              </button>
            ) : (
              <div className="mb-1.5 text-[12px] font-semibold tracking-[-0.01em] text-[var(--fg)]">
                {t.docs.sections[section.id]}
              </div>
            )}

            {isOpen && (
              <ul
                id={`sidebar-sec-${section.id}`}
                className="m-0 mt-1 flex list-none flex-col border-l border-[var(--border)] p-0"
              >
                {section.slugs.map((slug) => {
                  const isActive = slug === doc.slug
                  const route = slugToRoute(slug)
                  const localizedTo = localizePath(route, locale)
                  const label = t.docs.sidebarTitles?.[slug] ?? t.docs.pageTitles[slug] ?? slug
                  return (
                    <li key={slug}>
                      <Link
                        to={localizedTo}
                        aria-current={isActive ? 'page' : undefined}
                        onMouseEnter={() => void preloadRoute(localizedTo)}
                        onFocus={() => void preloadRoute(localizedTo)}
                        onClick={onCloseSidebar}
                        className={`-ml-[1px] block border-l-[1.5px] py-1.5 pl-3.5 pr-2 text-[13px] no-underline transition-colors ${
                          isActive
                            ? 'border-[var(--brand)] font-medium text-[var(--brand)]'
                            : 'border-transparent text-[var(--muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg)]'
                        }`}
                      >
                        {label}
                      </Link>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        )
      })}
    </nav>
  )

  return (
    <div className="mx-auto flex max-w-[1320px] items-start gap-8 px-4 pb-20 pt-6 sm:px-6 lg:px-8">
      {/* Desktop Sticky Left Sidebar */}
      <aside className="sticky top-[74px] hidden max-h-[calc(100vh-92px)] w-[236px] shrink-0 overflow-y-auto pr-3 lg:block">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer Sidebar */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 flex bg-black/50 backdrop-blur-xs lg:hidden"
          onClick={(e) => {
            if (e.target === e.currentTarget) onCloseSidebar()
          }}
        >
          <aside className="h-full w-[272px] overflow-y-auto border-r border-[var(--border)] bg-[var(--bg)] p-4 shadow-xl">
            {sidebarContent}
          </aside>
        </div>
      )}

      {/* Main Center Prose Column */}
      <main id="main-content" tabIndex={-1} className="min-w-0 max-w-[760px] flex-1 outline-none">
        <header className="mb-7 border-b border-[var(--border)] pb-5">
          <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.08em] text-[var(--brand)]">
              {sectionLabel}
            </span>
            <button
              type="button"
              onClick={() => void copyMarkdown()}
              className="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 font-mono text-[11px] font-medium text-[var(--muted)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
            >
              {copiedMd ? <Check size={12} className="text-[var(--ok)]" /> : <Copy size={12} />}
              <span>{copiedMd ? t.docs.copiedMarkdown : t.docs.copyMarkdown}</span>
            </button>
          </div>

          <h1 className="m-0 mb-2 text-[28px] leading-[1.15] font-semibold tracking-[-0.035em] text-[var(--fg)] sm:text-[32px]">
            {pageTitle}
          </h1>

          {doc.meta.description && (
            <p className="m-0 text-[15px] leading-[1.6] text-[var(--muted)]">
              {doc.meta.description}
            </p>
          )}
        </header>

        {doc.isFallback && (
          <div className="mb-6 flex items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--chrome)] px-3.5 py-2 text-[12.5px] text-[var(--muted)]">
            <Info size={14} className="shrink-0 text-[var(--info)]" />
            <span>{t.docs.fallbackNotice}</span>
          </div>
        )}

        <article className="mdx-prose">
          <MDXProvider components={mdxComponents}>
            <DocComponent />
          </MDXProvider>
        </article>

        {/* Footer: GitHub Edit + Prev/Next Pagination */}
        <footer className="mt-12 border-t border-[var(--border)] pt-6">
          <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
            <a
              href={doc.githubEditUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 font-mono text-[11.5px] text-[var(--muted)] no-underline hover:text-[var(--brand)]"
            >
              <span>{t.docs.editOnGitHub}</span>
              <ExternalLink size={12} />
            </a>

            <Link
              to={privacyTo}
              onMouseEnter={() => void preloadRoute(privacyTo)}
              onFocus={() => void preloadRoute(privacyTo)}
              className="font-mono text-[11.5px] text-[var(--muted)] no-underline hover:text-[var(--fg)]"
            >
              {t.home.linkPrivacy}
            </Link>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {doc.prevSlug && prevTo ? (
              <Link
                to={prevTo}
                onMouseEnter={() => void preloadRoute(prevTo)}
                onFocus={() => void preloadRoute(prevTo)}
                className="group flex flex-col gap-1 rounded-[8px] border border-[var(--border)] bg-[var(--surface)] px-4 py-3 no-underline transition-colors hover:border-[var(--brand-line)]"
              >
                <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-[var(--muted)]">
                  <ArrowLeft size={11} />
                  {t.docs.previous}
                </span>
                <span className="text-[13.5px] font-medium text-[var(--fg)] group-hover:text-[var(--brand)]">
                  {t.docs.pageTitles[doc.prevSlug] ?? doc.prevSlug}
                </span>
              </Link>
            ) : (
              <div />
            )}

            {doc.nextSlug && nextTo ? (
              <Link
                to={nextTo}
                onMouseEnter={() => void preloadRoute(nextTo)}
                onFocus={() => void preloadRoute(nextTo)}
                className="group flex flex-col items-end gap-1 rounded-[8px] border border-[var(--border)] bg-[var(--surface)] px-4 py-3 text-right no-underline transition-colors hover:border-[var(--brand-line)]"
              >
                <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-[var(--muted)]">
                  {t.docs.next}
                  <ArrowRight size={11} />
                </span>
                <span className="text-[13.5px] font-medium text-[var(--fg)] group-hover:text-[var(--brand)]">
                  {t.docs.pageTitles[doc.nextSlug] ?? doc.nextSlug}
                </span>
              </Link>
            ) : (
              <div />
            )}
          </div>
        </footer>
      </main>

      {/* Right Sticky TOC */}
      <aside className="sticky top-[74px] hidden max-h-[calc(100vh-92px)] w-[210px] shrink-0 overflow-y-auto xl:block">
        {doc.headings.length > 0 && (
          <div>
            <div className="mb-2.5 text-[12px] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {t.docs.onThisPage}
            </div>
            <ul className="m-0 flex list-none flex-col gap-1.5 border-l border-[var(--border)] p-0">
              {doc.headings.map((h) => {
                const isActive = activeHeading === h.id
                return (
                  <li key={h.id}>
                    <a
                      href={`#${h.id}`}
                      aria-current={isActive ? 'location' : undefined}
                      className={`-ml-[1px] block border-l-[1.5px] py-0.5 text-[12px] leading-[1.45] no-underline transition-colors ${
                        h.level === 3 ? 'pl-5' : 'pl-3'
                      } ${
                        isActive
                          ? 'border-[var(--brand)] font-medium text-[var(--fg)]'
                          : 'border-transparent text-[var(--muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg)]'
                      }`}
                    >
                      {h.text}
                    </a>
                  </li>
                )
              })}
            </ul>
          </div>
        )}

        <div className="mt-6 border-t border-[var(--border)] pt-3">
          <a
            href={llmsUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 font-mono text-[11px] text-[var(--muted)] no-underline hover:text-[var(--brand)]"
          >
            <span>{t.docs.llmsContext}</span>
            <ExternalLink size={11} />
          </a>
        </div>
      </aside>
    </div>
  )
}
