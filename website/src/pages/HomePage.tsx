import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ArrowRight, Check, Copy } from 'lucide-react'
import { APP_VERSION } from '../generated/version'
import { useCopyToClipboard } from '../hooks/useCopyToClipboard'
import { localizePath, useI18n } from '../i18n/context'
import { preloadRoute } from '../lib/preload'
import { HeroTerminal } from '../components/HeroTerminal'

const INSTALL_CMD_UNIX = 'curl -fsSL https://hua0512.github.io/rship/install.sh | sh'
const INSTALL_CMD_WIN = 'irm https://hua0512.github.io/rship/install.ps1 | iex'

export function HomePage() {
  const { locale, t } = useI18n()
  const { copied, copy, reset } = useCopyToClipboard()
  const [installPlatform, setInstallPlatform] = useState<'unix' | 'win'>('unix')

  useEffect(() => {
    if (typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent)) {
      setInstallPlatform('win')
    }
  }, [])

  const startTo = localizePath('/guide/getting-started', locale)
  const migrateTo = localizePath('/guide/migration', locale)
  const privacyTo = localizePath('/privacy', locale)
  const benchmarksTo = localizePath('/benchmarks/', locale)
  const sdkTo = localizePath('/sdk/embedding', locale)
  const installCmd = installPlatform === 'win' ? INSTALL_CMD_WIN : INSTALL_CMD_UNIX

  const selectPlatform = (next: 'unix' | 'win') => {
    setInstallPlatform(next)
    reset()
  }

  return (
    <div className="mx-auto max-w-[920px] px-4 pb-16 pt-4 sm:px-8 xl:max-w-[1120px] 2xl:max-w-[1280px]">
      <main id="main-content" tabIndex={-1} className="outline-none">
      {/* Spacious, Confident Hero */}
      <section className="grid grid-cols-1 items-center gap-8 py-10 sm:py-12 md:grid-cols-[minmax(0,1fr)_172px]">
        <div className="min-w-0">
          <div className="mb-4 inline-flex items-center gap-2 font-mono text-[10.5px] font-medium uppercase tracking-[0.08em] text-[var(--muted)]">
            <span className="h-1.5 w-1.5 rounded-full bg-[var(--brand)]" />
            {t.home.overline}
          </div>

          <h1 className="m-0 mb-4 text-[34px] leading-[1.06] font-semibold tracking-[-0.045em] text-[var(--fg)] sm:text-[42px] xl:text-[46px] 2xl:text-[50px]">
            {t.home.titlePrimary}
            <span className="block font-medium text-[var(--muted)]">{t.home.titleMuted}</span>
          </h1>

          <p className="m-0 mb-7 max-w-[460px] text-[14.5px] leading-[1.65] text-[var(--muted)] xl:text-[15px] 2xl:max-w-[520px] 2xl:text-[15.5px]">
            {t.home.lead}
          </p>

          <div className="flex flex-wrap items-center gap-2.5">
            <Link
              to={startTo}
              onMouseEnter={() => void preloadRoute(startTo)}
              onFocus={() => void preloadRoute(startTo)}
              className="inline-flex h-[38px] shrink-0 items-center gap-1.5 rounded-[7px] bg-[var(--brand-bg)] px-4.5 text-[13px] font-semibold tracking-[-0.01em] text-white no-underline transition-opacity hover:opacity-90"
            >
              {t.home.ctaGetStarted}
              <ArrowRight size={14} />
            </Link>

            <div className="inline-flex h-[38px] max-w-full min-w-0 items-center overflow-hidden rounded-[7px] border border-[var(--border)] bg-[var(--surface)] transition-colors hover:border-[var(--border-strong)]">
              <div
                className="flex h-full shrink-0 items-center border-r border-[var(--border)] bg-[var(--chrome)]/55 p-0.5 font-mono text-[10px]"
                role="group"
                aria-label="Installer OS"
              >
                <button
                  type="button"
                  aria-pressed={installPlatform === 'unix'}
                  onClick={() => selectPlatform('unix')}
                  className={`h-full cursor-pointer rounded-[4px] px-2 transition-colors ${
                    installPlatform === 'unix'
                      ? 'bg-[var(--surface)] font-semibold text-[var(--fg)]'
                      : 'text-[var(--muted)] hover:text-[var(--fg)]'
                  }`}
                >
                  {t.home.installLabelUnix}
                </button>
                <button
                  type="button"
                  aria-pressed={installPlatform === 'win'}
                  onClick={() => selectPlatform('win')}
                  className={`h-full cursor-pointer rounded-[4px] px-2 transition-colors ${
                    installPlatform === 'win'
                      ? 'bg-[var(--surface)] font-semibold text-[var(--fg)]'
                      : 'text-[var(--muted)] hover:text-[var(--fg)]'
                  }`}
                >
                  {t.home.installLabelWindows}
                </button>
              </div>

              <button
                type="button"
                onClick={() => void copy(installCmd)}
                className="flex h-full min-w-0 cursor-pointer items-center gap-2 px-3 font-mono text-[11.5px] text-[var(--muted)]"
                aria-label={`${t.home.ctaCopy}: ${installCmd}`}
              >
                <span className="shrink-0 text-[var(--brand)]">
                  {installPlatform === 'win' ? '>' : '$'}
                </span>
                <span className="truncate text-[var(--fg)]">{installCmd}</span>
                <span className="inline-flex shrink-0 items-center text-[var(--muted)]">
                  {copied ? <Check size={13} className="text-[var(--ok)]" /> : <Copy size={13} />}
                </span>
              </button>
            </div>
          </div>

          <div className="mt-3 text-[12.5px] text-[var(--muted)] 2xl:text-[13.5px]">
            {t.home.migrateHintPrefix}{' '}
            <Link
              to={migrateTo}
              onMouseEnter={() => void preloadRoute(migrateTo)}
              onFocus={() => void preloadRoute(migrateTo)}
              className="font-medium text-[var(--fg)] no-underline underline-offset-4 hover:text-[var(--brand)] hover:underline"
            >
              {t.home.migrateHintLink} →
            </Link>
          </div>
        </div>

        {/* Quiet architectural wireframe hull schematic */}
        <div className="hidden justify-end select-none md:flex" aria-hidden="true">
          <svg width="168" height="146" viewBox="0 0 172 152" fill="none">
            <line
              x1="8"
              y1="24"
              x2="164"
              y2="24"
              stroke="currentColor"
              strokeOpacity="0.10"
              strokeDasharray="2 4"
            />
            <line
              x1="8"
              y1="76"
              x2="164"
              y2="76"
              stroke="currentColor"
              strokeOpacity="0.10"
              strokeDasharray="2 4"
            />
            <line
              x1="8"
              y1="128"
              x2="164"
              y2="128"
              stroke="currentColor"
              strokeOpacity="0.10"
              strokeDasharray="2 4"
            />
            <line x1="36" y1="8" x2="36" y2="144" stroke="currentColor" strokeOpacity="0.08" />
            <line x1="136" y1="8" x2="136" y2="144" stroke="currentColor" strokeOpacity="0.08" />
            <path
              d="M62 32H112L103 52H53L62 32Z"
              stroke="currentColor"
              strokeOpacity="0.30"
              strokeWidth="1.2"
            />
            <path
              d="M44 60H77L69 78H36L44 60Z"
              stroke="currentColor"
              strokeOpacity="0.20"
              strokeWidth="1.2"
            />
            <path
              d="M88 60H130L122 78H80L88 60Z"
              stroke="currentColor"
              strokeOpacity="0.36"
              strokeWidth="1.2"
            />
            <path
              d="M24 88H148L130 122H42L24 88Z"
              stroke="#FF5E1A"
              strokeWidth="1.5"
              fill="rgba(255,94,26,0.06)"
            />
            <circle cx="148" cy="88" r="2.5" fill="#FF5E1A" />
          </svg>
        </div>
      </section>

      {/* Single Quiet Terminal Centerpiece */}
      <div className="mb-9">
        <HeroTerminal />
      </div>

      {/* Quiet 4-Column Hairline Capability Grid */}
      <section className="grid grid-cols-1 border-y border-[var(--border)] sm:grid-cols-2 lg:grid-cols-4">
        {t.home.capabilities.map((cap, idx) => {
          const capTo = localizePath(cap.to, locale)
          return (
            <Link
              key={cap.index}
              to={capTo}
              onMouseEnter={() => void preloadRoute(capTo)}
              onFocus={() => void preloadRoute(capTo)}
              className={`group flex flex-col gap-1.5 border-b border-[var(--border)] py-5 no-underline transition-colors sm:pr-5 lg:border-b-0 ${
                idx < 3 ? 'lg:mr-5 lg:border-r' : ''
              } ${idx % 2 === 0 ? 'sm:mr-5 sm:border-r lg:mr-5' : 'sm:border-r-0 lg:border-r'} ${
                idx === 3 ? 'border-b-0 lg:border-r-0' : ''
              } ${idx === 2 ? 'sm:border-b-0' : ''}`}
            >
              <span className="font-mono text-[10px] font-semibold text-[var(--brand)] 2xl:text-[11px]">
                {cap.index}
              </span>
              <span className="text-[13.5px] font-semibold tracking-[-0.015em] text-[var(--fg)] group-hover:text-[var(--brand)] 2xl:text-[14.5px]">
                {cap.title}
              </span>
              <span className="text-[12.5px] leading-[1.55] text-[var(--muted)] 2xl:text-[13.5px]">
                {cap.desc}
              </span>
            </Link>
          )
        })}
      </section>
      </main>

      {/* Understated Ecosystem Footer */}
      <footer className="flex flex-col gap-3 pt-5">
        <div className="font-mono text-[11px] leading-[1.6] text-[var(--subtle)] 2xl:text-[12px]">
          <strong className="font-medium text-[var(--muted)]">{t.home.backendsLabel}</strong>{' '}
          {t.home.backendsList}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-[var(--subtle)] 2xl:text-[12px]">
            <span>
              {t.home.licenseNote} · v{APP_VERSION}
            </span>
            <span>·</span>
            <Link
              to={privacyTo}
              onMouseEnter={() => void preloadRoute(privacyTo)}
              onFocus={() => void preloadRoute(privacyTo)}
              className="text-[var(--muted)] no-underline hover:text-[var(--fg)]"
            >
              {t.home.linkPrivacy}
            </Link>
            <span>·</span>
            <a
              href="https://github.com/hua0512/rship/releases"
              target="_blank"
              rel="noreferrer"
              className="text-[var(--muted)] no-underline hover:text-[var(--fg)]"
            >
              {t.home.linkReleases}
            </a>
            <span>·</span>
            <a
              href="https://github.com/hua0512/rship/issues"
              target="_blank"
              rel="noreferrer"
              className="text-[var(--muted)] no-underline hover:text-[var(--fg)]"
            >
              {t.home.linkIssues}
            </a>
          </div>

          <div className="flex items-center gap-5 font-mono text-[11px] 2xl:text-[12px]">
            <Link
              to={benchmarksTo}
              onMouseEnter={() => void preloadRoute(benchmarksTo)}
              onFocus={() => void preloadRoute(benchmarksTo)}
              className="border-b border-[var(--border-strong)] pb-0.5 font-medium text-[var(--fg)] no-underline transition-colors hover:border-[var(--brand)] hover:text-[var(--brand)]"
            >
              {t.home.linkBenchmarks} →
            </Link>
            <Link
              to={sdkTo}
              onMouseEnter={() => void preloadRoute(sdkTo)}
              onFocus={() => void preloadRoute(sdkTo)}
              className="border-b border-[var(--border-strong)] pb-0.5 font-medium text-[var(--fg)] no-underline transition-colors hover:border-[var(--brand)] hover:text-[var(--brand)]"
            >
              {t.home.linkSdk} →
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
