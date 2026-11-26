import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { CornerDownLeft, FileText, Flag, HardDrive, Search } from 'lucide-react'
import type { SearchDocItem } from '../generated/docs-meta'
import { localizePath, useI18n } from '../i18n/context'
import { ALL_DOC_SLUGS, getCachedDocsMetaMap, slugToRoute } from '../lib/docs'
import { preloadRoute } from '../lib/preload'

interface CommandEntry {
  id: string
  group: 'pages' | 'flags' | 'providers'
  title: string
  subtitle: string
  to: string
  titleLower: string
  altTitleLower: string
  subtitleLower: string
  headingsLower: string
  keywordsLower: string
  bodyLower: string
  fullTextLower: string
}

interface StaticCommandDef {
  id: string
  title: string
  subtitle: string
  keywords: string
  to: string
}

let cachedSearchIndex: SearchDocItem[] | null = null
let pendingSearchFetch: Promise<SearchDocItem[]> | null = null

function loadSearchIndex(): Promise<SearchDocItem[]> {
  if (cachedSearchIndex) return Promise.resolve(cachedSearchIndex)
  if (pendingSearchFetch) return pendingSearchFetch

  pendingSearchFetch = fetch(`${import.meta.env.BASE_URL}search-index.json`)
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<SearchDocItem[]>
    })
    .then((items) => {
      cachedSearchIndex = items
      pendingSearchFetch = null
      return items
    })
    .catch(() => {
      pendingSearchFetch = null
      return []
    })

  return pendingSearchFetch
}

const CLI_FLAG_ENTRIES: StaticCommandDef[] = [
  {
    id: 'flag-adaptive',
    title: '--adaptive',
    subtitle: 'Falcon dual-lane small/large concurrency controller',
    keywords: 'falcon adaptive concurrency dual lane small large',
    to: '/guide/cli-reference#key-transfer-flags',
  },
  {
    id: 'flag-bwlimit',
    title: '--bwlimit <RATE>',
    subtitle: 'Sustained bandwidth cap (e.g. 20M, 500K, 1G)',
    keywords: 'bwlimit bandwidth rate limit throttle',
    to: '/guide/cli-reference#key-transfer-flags',
  },
  {
    id: 'flag-max-buffer-mem',
    title: '--max-buffer-mem <SIZE>',
    subtitle: 'Hard cap on BufferPool byte semaphore (<= 64 MiB RSS)',
    keywords: 'bufferpool memory rss max-buffer-mem 16M 8M',
    to: '/guide/cli-reference#key-transfer-flags',
  },
  {
    id: 'flag-max-delete',
    title: '--max-delete <N>',
    subtitle: 'Circuit breaker aborting sync/delete if deletions exceed N',
    keywords: 'max-delete sync safety circuit breaker',
    to: '/guide/cli-reference#key-transfer-flags',
  },
  {
    id: 'flag-conflict-strategy',
    title: 'rship bisync --conflict-strategy',
    subtitle: 'Three-Tree two-way sync conflict policy (keep-both | abort | prefer-a | prefer-b)',
    keywords: 'bisync resync conflict strategy keep-both three-tree',
    to: '/guide/bisync',
  },
  {
    id: 'flag-no-lock',
    title: '--no-lock / ProcessLock',
    subtitle: 'Exclusive destination lock management & state directory recovery',
    keywords: 'no-lock processlock state config.toml troubleshooting gc',
    to: '/guide/troubleshooting',
  },
  {
    id: 'flag-import-rclone',
    title: 'rship config import-rclone',
    subtitle: 'Import 8 cloud providers & obscured secrets from rclone.conf',
    keywords: 'import-rclone migrate rclone.conf config',
    to: '/guide/migration',
  },
  {
    id: 'flag-drive-stop',
    title: '--drive-stop-on-upload-limit',
    subtitle: 'Fast-fail with QuotaExceeded on Google Drive 750 GiB/day cap',
    keywords: 'google drive quota 750gb userRateLimitExceeded failover',
    to: '/guide/cli-reference#global-flags',
  },
]

const PROVIDER_ENTRIES: StaticCommandDef[] = [
  {
    id: 'prov-gdrive',
    title: 'Google Drive v3',
    subtitle: 'OAuth2 PKCE, Service Accounts, Shared Drives, changes.list',
    keywords: 'gdrive google drive oauth pkce service account',
    to: '/providers/gdrive',
  },
  {
    id: 'prov-s3',
    title: 'S3-Compatible (AWS, Cloudflare R2, MinIO, B2, OSS)',
    subtitle: '12 presets, SigV4, CRC64NVME / CRC32C, parallel multipart',
    keywords: 's3 r2 cloudflare aws minio backblaze b2 oss wasabi hetzner',
    to: '/providers/s3',
  },
  {
    id: 'prov-sftp',
    title: 'SSH / SFTP (russh)',
    subtitle: 'Pooled sessions, offset crash-resume, known_hosts',
    keywords: 'sftp ssh russh vps',
    to: '/providers/sftp',
  },
  {
    id: 'prov-webdav',
    title: 'WebDAV (Nextcloud, OwnCloud, Alist, Synology)',
    subtitle: 'Chunked Upload v2, COPY, PROPFIND quota',
    keywords: 'webdav nextcloud owncloud alist synology nas',
    to: '/providers/webdav',
  },
  {
    id: 'prov-gcs',
    title: 'Google Cloud Storage (GCS)',
    subtitle: 'RS256 JWT, OAuth2 PKCE, public buckets, 256 KiB resumable',
    keywords: 'gcs google cloud storage gcp bucket fake-gcs-server',
    to: '/providers/gcs',
  },
  {
    id: 'prov-azureblob',
    title: 'Azure Blob Storage',
    subtitle: 'SharedKey, SAS URL, Azurite emulator, Put Block resume',
    keywords: 'azure blob storage sas azurite sharedkey',
    to: '/providers/azureblob',
  },
  {
    id: 'prov-dropbox',
    title: 'Dropbox API v2',
    subtitle: '4 MiB upload sessions, dropbox_content_hash, copy_v2',
    keywords: 'dropbox dbx oauth pkce content hash',
    to: '/providers/dropbox',
  },
  {
    id: 'prov-onedrive',
    title: 'OneDrive & SharePoint',
    subtitle: 'Microsoft Graph v1.0, 320 KiB sessions, async copy',
    keywords: 'onedrive sharepoint microsoft graph entra',
    to: '/providers/onedrive',
  },
  {
    id: 'prov-crypt',
    title: 'STREAM OAE2 Encrypted Vault',
    subtitle: '64 KiB XChaCha20-Poly1305 seekable range reads + SIV names',
    keywords: 'crypt encryption xchacha20 poly1305 argon2id vault',
    to: '/guide/encryption',
  },
]

function makeStaticEntry(def: StaticCommandDef, group: 'flags' | 'providers'): CommandEntry {
  const titleLower = def.title.toLowerCase()
  const subtitleLower = def.subtitle.toLowerCase()
  const keywordsLower = def.keywords.toLowerCase()
  return {
    id: def.id,
    group,
    title: def.title,
    subtitle: def.subtitle,
    to: def.to,
    titleLower,
    altTitleLower: '',
    subtitleLower,
    headingsLower: '',
    keywordsLower,
    bodyLower: '',
    fullTextLower: `${titleLower} ${subtitleLower} ${keywordsLower}`,
  }
}

const STATIC_ENTRIES: CommandEntry[] = [
  ...CLI_FLAG_ENTRIES.map((e) => makeStaticEntry(e, 'flags')),
  ...PROVIDER_ENTRIES.map((e) => makeStaticEntry(e, 'providers')),
]

function hasWordStartMatch(haystack: string, term: string): boolean {
  let idx = haystack.indexOf(term)
  while (idx !== -1) {
    if (idx === 0) return true
    const prev = haystack[idx - 1]
    if (prev === ' ' || prev === '-' || prev === '/' || prev === '(' || prev === '_') {
      return true
    }
    idx = haystack.indexOf(term, idx + 1)
  }
  return false
}

function scoreEntry(entry: CommandEntry, fullQuery: string, terms: string[]): number {
  for (const term of terms) {
    if (!entry.fullTextLower.includes(term)) return 0
  }

  let score = 0

  if (entry.titleLower === fullQuery) {
    score += 140
  } else if (entry.titleLower.startsWith(fullQuery)) {
    score += 90
  } else if (entry.titleLower.includes(fullQuery)) {
    score += 55
  } else if (entry.altTitleLower && entry.altTitleLower.includes(fullQuery)) {
    score += 35
  }

  if (fullQuery.startsWith('-') && entry.group === 'flags') {
    score += 12
  }

  for (const term of terms) {
    if (entry.titleLower.includes(term)) {
      score += hasWordStartMatch(entry.titleLower, term) ? 34 : 22
    } else if (entry.altTitleLower && entry.altTitleLower.includes(term)) {
      score += 16
    }

    if (entry.headingsLower && entry.headingsLower.includes(term)) {
      score += 14
    }
    if (entry.subtitleLower && entry.subtitleLower.includes(term)) {
      score += 10
    }
    if (entry.keywordsLower && entry.keywordsLower.includes(term)) {
      score += 8
    }
    if (entry.bodyLower && entry.bodyLower.includes(term)) {
      score += 3
    }
  }

  return score
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

function GroupIcon({ g }: { g: CommandEntry['group'] }) {
  if (g === 'flags') return <Flag size={13} className="shrink-0 text-[var(--brand)]" />
  if (g === 'providers') return <HardDrive size={13} className="shrink-0 text-[var(--info)]" />
  return <FileText size={13} className="shrink-0 text-[var(--muted)]" />
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const { locale, t } = useI18n()
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const deferredQuery = useDeferredValue(query)
  const [activeIdx, setActiveIdx] = useState(0)
  const [searchDocs, setSearchDocs] = useState<SearchDocItem[]>(() => cachedSearchIndex ?? [])
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open || searchDocs.length > 0) return
    let cancelled = false
    void loadSearchIndex().then((items) => {
      if (!cancelled && items.length > 0) {
        setSearchDocs(items)
      }
    })
    return () => {
      cancelled = true
    }
  }, [open, searchDocs.length])

  const entries = useMemo<CommandEntry[]>(() => {
    const cachedMeta = getCachedDocsMetaMap(locale)
    const docItems: CommandEntry[] = ALL_DOC_SLUGS.map((slug) => {
      const searchDoc =
        searchDocs.find((d) => d.locale === locale && d.slug === slug) ??
        searchDocs.find((d) => d.locale === 'en' && d.slug === slug)
      const metaDoc = cachedMeta?.[slug]

      const titleFallback = searchDoc?.title ?? metaDoc?.title ?? slug
      const localizedTitle = t.docs.pageTitles[slug] ?? titleFallback
      const sectionKey = (searchDoc?.section ?? metaDoc?.section ?? '') as keyof typeof t.docs.sections
      const sectionTitle = sectionKey ? t.docs.sections[sectionKey] ?? sectionKey : ''
      const description = searchDoc?.description ?? metaDoc?.description ?? ''
      const headingTexts = searchDoc?.headings ?? metaDoc?.headings.map((h) => h.text) ?? []

      const titleLower = localizedTitle.toLowerCase()
      const altTitleLower = titleFallback !== localizedTitle ? titleFallback.toLowerCase() : ''
      const subtitle = sectionTitle || description
      const subtitleLower = `${subtitle} ${description}`.toLowerCase()
      const headingsLower = headingTexts.join(' ').toLowerCase()
      const keywordsLower = slug.replace(/\//g, ' ').toLowerCase()
      const bodyLower = (searchDoc?.body ?? '').toLowerCase()

      return {
        id: `doc-${slug}`,
        group: 'pages',
        title: localizedTitle,
        subtitle,
        to: slugToRoute(slug),
        titleLower,
        altTitleLower,
        subtitleLower,
        headingsLower,
        keywordsLower,
        bodyLower,
        fullTextLower: `${titleLower} ${altTitleLower} ${subtitleLower} ${headingsLower} ${keywordsLower} ${bodyLower}`,
      }
    })

    return [...docItems, ...STATIC_ENTRIES]
  }, [locale, t, searchDocs])

  const filtered = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase()
    if (!q) {
      return entries.slice(0, 12)
    }
    const terms = q.split(/\s+/).filter(Boolean)
    const scored: Array<{ item: CommandEntry; score: number; idx: number }> = []
    for (let idx = 0; idx < entries.length; idx++) {
      const item = entries[idx]
      const score = scoreEntry(item, q, terms)
      if (score > 0) {
        scored.push({ item, score, idx })
      }
    }
    scored.sort((a, b) => b.score - a.score || a.idx - b.idx)
    return scored.slice(0, 14).map((s) => s.item)
  }, [entries, deferredQuery])

  useEffect(() => {
    if (!open) return
    setQuery('')
    setActiveIdx(0)
    const timer = window.setTimeout(() => inputRef.current?.focus(), 16)
    return () => window.clearTimeout(timer)
  }, [open])

  useEffect(() => {
    setActiveIdx(0)
  }, [deferredQuery])

  if (!open) return null

  const choose = (entry: CommandEntry) => {
    const [rawPath, hash] = entry.to.split('#')
    const target = localizePath(rawPath, locale) + (hash ? `#${hash}` : '')
    navigate(target)
    onClose()
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIdx((i) => (filtered.length ? (i + 1) % filtered.length : 0))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIdx((i) => (filtered.length ? (i - 1 + filtered.length) % filtered.length : 0))
    } else if (e.key === 'Enter' && filtered[activeIdx]) {
      e.preventDefault()
      choose(filtered[activeIdx])
    } else if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    }
  }

  const groupLabel = (g: CommandEntry['group']) => {
    if (g === 'flags') return t.cmdk.groupFlags
    if (g === 'providers') return t.cmdk.groupProviders
    return t.cmdk.groupPages
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/55 px-4 pt-16 backdrop-blur-xs"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
      role="dialog"
      aria-modal="true"
      aria-label={t.nav.search}
    >
      <div
        className="w-full max-w-[540px] overflow-hidden rounded-[10px] border border-[var(--border-strong)] bg-[var(--surface)] shadow-2xl"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2.5 border-b border-[var(--border)] px-3.5 py-2.5">
          <Search size={15} className="shrink-0 text-[var(--muted)]" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t.cmdk.placeholder}
            className="w-full bg-transparent text-[13.5px] text-[var(--fg)] outline-none placeholder:text-[var(--subtle)]"
          />
          <kbd className="rounded border border-[var(--border)] bg-[var(--chrome)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">
            ESC
          </kbd>
        </div>

        <div className="max-h-[340px] overflow-y-auto p-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-10 text-center text-[13px] text-[var(--muted)]">
              {t.cmdk.empty}
            </div>
          ) : (
            filtered.map((item, idx) => {
              const active = idx === activeIdx
              const [rawPath] = item.to.split('#')
              const localizedPath = localizePath(rawPath, locale)
              return (
                <button
                  key={item.id}
                  type="button"
                  onMouseEnter={() => {
                    setActiveIdx(idx)
                    void preloadRoute(localizedPath)
                  }}
                  onFocus={() => void preloadRoute(localizedPath)}
                  onClick={() => choose(item)}
                  className={`flex w-full cursor-pointer items-center justify-between gap-3 rounded-md px-3 py-2 text-left transition-colors ${
                    active ? 'bg-[var(--chrome)]' : 'hover:bg-[var(--chrome)]/60'
                  }`}
                >
                  <div className="flex min-w-0 items-center gap-2.5">
                    <GroupIcon g={item.group} />
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-medium text-[var(--fg)]">
                        {item.title}
                      </div>
                      <div className="truncate font-mono text-[11px] text-[var(--muted)]">
                        {item.subtitle}
                      </div>
                    </div>
                  </div>
                  <span className="shrink-0 rounded border border-[var(--border)] bg-[var(--bg)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">
                    {groupLabel(item.group)}
                  </span>
                </button>
              )
            })
          )}
        </div>

        <div className="flex items-center justify-between border-t border-[var(--border)] bg-[var(--chrome)] px-3.5 py-2 font-mono text-[10.5px] text-[var(--muted)]">
          <span className="inline-flex items-center gap-1.5">
            <CornerDownLeft size={11} />
            {t.cmdk.hintSelect}
          </span>
          <span>ESC · {t.cmdk.hintClose}</span>
        </div>
      </div>
    </div>
  )
}
