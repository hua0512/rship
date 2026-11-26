import { useDeferredValue, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ArrowRight, Check, Copy, Search } from 'lucide-react'
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard'
import { localizePath, useI18n, type Locale } from '../../i18n/context'
import { preloadRoute } from '../../lib/preload'

interface MatrixCopy {
  filterAll: string
  filterSsc: string
  filterRclone: string
  filterOauth: string
  filterZeroHttp: string
  searchPlaceholder: string
  tableHeader: string
  resumeLabel: string
  guideLink: string
  copyCli: string
  copied: string
  countSuffix: string
  empty: string
  providers: Record<
    string,
    {
      name: string
      summary: string
      resume: string
    }
  >
}

const COPY: Record<Locale, MatrixCopy> = {
  en: {
    filterAll: 'All',
    filterSsc: 'Server-Side Copy',
    filterRclone: 'rclone.conf Import',
    filterOauth: 'OAuth2 PKCE',
    filterZeroHttp: 'Zero-HTTP',
    searchPlaceholder: 'Filter providers (R2, Nextcloud, SFTP, OAE2)...',
    tableHeader: 'Storage Drivers',
    resumeLabel: 'Crash-Resume',
    guideLink: 'Guide',
    copyCli: 'Copy CLI',
    copied: 'Copied',
    countSuffix: 'providers',
    empty: 'No providers match the current filter. Clear the query or switch back to All.',
    providers: {
      local: {
        name: 'Local Filesystem',
        summary:
          'OS-native CopyFileExW / copy_file_range / fclonefileat fast paths, atomic staging, symlink-escape guards, and native disk quota.',
        resume: '32 MiB CRC32C parallel parts manifest',
      },
      gdrive: {
        name: 'Google Drive v3',
        summary:
          'Desktop PKCE loopback & RS256 JWT + Shared Drives, 8-way BFS + incremental changes.list sync, zero-reupload dedupe, and files.copy.',
        resume: '256 MiB 308 resumable + SQLite inventory cache',
      },
      s3: {
        name: 'S3-Compatible (12 Presets)',
        summary:
          'Built-in capability matrix for AWS, R2, MinIO, OSS, B2, Wasabi, DO Spaces, Tencent COS, Tigris, Scaleway, Hetzner, and generic S3.',
        resume: 'Paginated ListParts parallel multipart',
      },
      dropbox: {
        name: 'Dropbox API v2',
        summary:
          'Strict 4 MiB-aligned upload sessions, native dropbox_content_hash block tree, files/copy_v2 server-side copy, and batch delete.',
        resume: '4 MiB upload_session + incorrect_offset recovery',
      },
      gcs: {
        name: 'Google Cloud Storage',
        summary:
          'GCS JSON API v1 supporting RS256 JWT, PKCE, and anonymous public buckets with rewrite server-side copy and MD5/CRC32C verification.',
        resume: '256 KiB aligned 308 resumable uploads',
      },
      azureblob: {
        name: 'Azure Blob Storage',
        summary:
          'Azure REST API 2023-11-03 with SharedKey HMAC-SHA256, SAS tokens, Azurite emulator support, x-ms-copy-source, and Content-MD5.',
        resume: 'Put Block / Get Block List parallel resume',
      },
      onedrive: {
        name: 'OneDrive & SharePoint',
        summary:
          'Microsoft Graph API v1.0 for personal OneDrive, Business, and SharePoint document libraries with async copy monitor polling.',
        resume: '320 KiB upload sessions (nextExpectedRanges)',
      },
      webdav: {
        name: 'WebDAV',
        summary:
          'Vendor profiles for Nextcloud, OwnCloud, Alist, Synology NAS, InfiniCloud, and generic WebDAV with COPY and PROPFIND quota.',
        resume: 'Nextcloud / OwnCloud Chunked Upload v2',
      },
      sftp: {
        name: 'SSH / SFTP',
        summary:
          'Built on russh + russh-sftp with bounded lazy session pooling, known_hosts verification, and statvfs.',
        resume: '.rship.part.* offset resume + posix-rename',
      },
      crypt: {
        name: 'STREAM OAE2 Crypt Overlay',
        summary:
          'Hardware-accelerated aws-lc-rs AVX2/NEON overlay with Argon2id + HKDF, zeroize key hygiene, and SIV base32 filename encryption.',
        resume: 'Inherits target backend resume + 4-part local',
      },
    },
  },
  zh: {
    filterAll: '全部',
    filterSsc: '服务端直拷',
    filterRclone: '支持 rclone 导入',
    filterOauth: 'OAuth2 PKCE',
    filterZeroHttp: '非 HTTP 协议',
    searchPlaceholder: '搜索存储后端 (R2, Nextcloud, SFTP, OAE2)...',
    tableHeader: '内置存储驱动',
    resumeLabel: '断点续传',
    guideLink: '配置指南',
    copyCli: '复制命令',
    copied: '已复制',
    countSuffix: '个后端',
    empty: '没有符合当前筛选条件的存储后端，请清空搜索词或切回「全部」。',
    providers: {
      local: {
        name: '本地文件系统 (Local)',
        summary:
          '原生调用 CopyFileExW / copy_file_range / fclonefileat 零拷贝路径，支持原子暂存提交、符号链接逃逸防护与磁盘配额查询。',
        resume: '32 MiB CRC32C 并行分片断点清单',
      },
      gdrive: {
        name: 'Google Drive v3',
        summary:
          '支持桌面 PKCE 回环、RS256 JWT 与共享云端硬盘，内置 8 路 BFS、changes.list 增量同步、零重传去重与 files.copy 服务端拷贝。',
        resume: '256 MiB 308 断点续传 + SQLite 目录缓存',
      },
      s3: {
        name: 'S3 兼容存储（12 个预设）',
        summary:
          '内置 AWS、Cloudflare R2、MinIO、阿里云 OSS、B2、Wasabi、DO Spaces、腾讯云 COS、Tigris、Scaleway、Hetzner 与通用 S3 能力矩阵。',
        resume: '分页 ListParts 并行分片续传',
      },
      dropbox: {
        name: 'Dropbox API v2',
        summary:
          '严格按 4 MiB 对齐上传会话并原生计算 dropbox_content_hash 块树，支持 files/copy_v2 服务端拷贝与批量删除。',
        resume: '4 MiB upload_session + incorrect_offset 自动纠偏',
      },
      gcs: {
        name: 'Google Cloud Storage (GCS)',
        summary:
          '基于 GCS JSON API v1，支持 RS256 JWT、PKCE 与匿名公开存储桶，内置 rewrite 服务端拷贝及 MD5 / CRC32C 校验。',
        resume: '256 KiB 对齐 308 断点续传',
      },
      azureblob: {
        name: 'Azure Blob Storage',
        summary:
          '基于 Azure REST API 2023-11-03，支持 SharedKey HMAC-SHA256、SAS 令牌、Azurite 模拟器、x-ms-copy-source 与 Content-MD5。',
        resume: 'Put Block / Get Block List 并行块续传',
      },
      onedrive: {
        name: 'OneDrive 与 SharePoint',
        summary:
          '基于 Microsoft Graph API v1.0，覆盖个人版、企业版及 SharePoint 文档库，支持异步服务端拷贝轮询监控。',
        resume: '320 KiB 上传会话（nextExpectedRanges 续传）',
      },
      webdav: {
        name: 'WebDAV 与 NAS',
        summary:
          '内置 Nextcloud、OwnCloud、Alist、群晖 Synology、InfiniCloud 与通用 WebDAV 适配配置，支持服务端 COPY 与 PROPFIND 配额查询。',
        resume: 'Nextcloud / OwnCloud Chunked Upload v2',
      },
      sftp: {
        name: 'SSH / SFTP',
        summary:
          '基于 russh + russh-sftp 构建，支持有界懒加载会话池、known_hosts 校验与 statvfs 配额查询。',
        resume: '.rship.part.* 偏移断点续传 + posix-rename 原子提交',
      },
      crypt: {
        name: 'STREAM OAE2 客户端加密层',
        summary:
          '基于 aws-lc-rs AVX2/NEON 硬件加速，提供 Argon2id + HKDF 密钥派生、zeroize 自动擦除与 SIV base32 文件名加密。',
        resume: '继承底层后端续传 + 本地 4 路并行加密读写',
      },
    },
  },
}

interface ProviderItem {
  id: string
  feature: string
  docPath: string
  metaTags: string[]
  ssc: boolean
  rclone: boolean
  oauth: boolean
  zeroHttp: boolean
  authCmd: string
}

const PROVIDERS: ProviderItem[] = [
  {
    id: 'local',
    feature: 'local',
    docPath: '/guide/getting-started',
    metaTags: ['Zero-HTTP', 'OS Fast Copy', 'OSDI-2014 Atomic'],
    ssc: true,
    rclone: false,
    oauth: false,
    zeroHttp: true,
    authCmd: 'rship copy ./src ./dst --transfers 16',
  },
  {
    id: 'gdrive',
    feature: 'gdrive',
    docPath: '/providers/gdrive',
    metaTags: ['OAuth2 PKCE', 'Service Account', 'changes.list'],
    ssc: true,
    rclone: true,
    oauth: true,
    zeroHttp: false,
    authCmd: 'rship auth gdrive gdrive --client-id <ID> --client-secret <SECRET>',
  },
  {
    id: 's3',
    feature: 's3',
    docPath: '/providers/s3',
    metaTags: ['AWS / R2 / MinIO / B2 / OSS', 'SigV4', 'CRC64NVME'],
    ssc: true,
    rclone: true,
    oauth: false,
    zeroHttp: false,
    authCmd: 'rship auth s3 r2 --provider r2 --bucket backups --region auto --endpoint <URL>',
  },
  {
    id: 'dropbox',
    feature: 'dropbox',
    docPath: '/providers/dropbox',
    metaTags: ['OAuth2 PKCE', '4 MiB Block Hash'],
    ssc: true,
    rclone: true,
    oauth: true,
    zeroHttp: false,
    authCmd: 'rship auth dropbox dbx --client-id <APP_KEY>',
  },
  {
    id: 'gcs',
    feature: 'gcs',
    docPath: '/providers/gcs',
    metaTags: ['Service Account JWT', 'OAuth2 PKCE', 'Public Buckets'],
    ssc: true,
    rclone: true,
    oauth: true,
    zeroHttp: false,
    authCmd: 'rship auth gcs gcs --bucket my-archive --service-account-file ./sa.json',
  },
  {
    id: 'azureblob',
    feature: 'azureblob',
    docPath: '/providers/azureblob',
    metaTags: ['SharedKey', 'SAS URL', 'Azurite'],
    ssc: true,
    rclone: true,
    oauth: false,
    zeroHttp: false,
    authCmd: 'rship auth azureblob az --account myacct --container backups --key <KEY>',
  },
  {
    id: 'onedrive',
    feature: 'onedrive',
    docPath: '/providers/onedrive',
    metaTags: ['Microsoft Graph', 'OAuth2 PKCE'],
    ssc: true,
    rclone: true,
    oauth: true,
    zeroHttp: false,
    authCmd: 'rship auth onedrive od --client-id <AZURE_CLIENT_ID>',
  },
  {
    id: 'webdav',
    feature: 'webdav',
    docPath: '/providers/webdav',
    metaTags: ['Nextcloud', 'OwnCloud', 'Alist / Synology'],
    ssc: true,
    rclone: true,
    oauth: false,
    zeroHttp: false,
    authCmd:
      'rship auth webdav nc --vendor nextcloud --url https://cloud.example.com/remote.php/dav/files/alice --username alice',
  },
  {
    id: 'sftp',
    feature: 'sftp',
    docPath: '/providers/sftp',
    metaTags: ['Zero-HTTP', 'russh', 'known_hosts'],
    ssc: false,
    rclone: true,
    oauth: false,
    zeroHttp: true,
    authCmd: 'rship auth sftp vps --host 10.0.0.5 --user deploy --key-file ~/.ssh/id_ed25519',
  },
  {
    id: 'crypt',
    feature: 'crypt',
    docPath: '/guide/encryption',
    metaTags: ['XChaCha20-Poly1305', 'Seekable 64 KiB', 'Zero Unsafe'],
    ssc: false,
    rclone: false,
    oauth: false,
    zeroHttp: true,
    authCmd: 'rship auth crypt vault --target r2:encrypted --password "strong-passphrase"',
  },
]

type FilterKind = 'all' | 'ssc' | 'rclone' | 'oauth' | 'zeroHttp'

export function ProviderMatrix() {
  const { locale } = useI18n()
  const copyText = COPY[locale] ?? COPY.en
  const [filter, setFilter] = useState<FilterKind>('all')
  const [query, setQuery] = useState('')
  const deferredQuery = useDeferredValue(query)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const { copied, copy } = useCopyToClipboard()

  const filtered = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase()
    return PROVIDERS.filter((p) => {
      if (filter === 'oauth' && !p.oauth) return false
      if (filter === 'ssc' && !p.ssc) return false
      if (filter === 'rclone' && !p.rclone) return false
      if (filter === 'zeroHttp' && !p.zeroHttp) return false
      if (!q) return true
      const copyItem = copyText.providers[p.id]
      return (
        (copyItem?.name ?? '').toLowerCase().includes(q) ||
        (copyItem?.summary ?? '').toLowerCase().includes(q) ||
        p.metaTags.some((tag) => tag.toLowerCase().includes(q)) ||
        p.feature.includes(q)
      )
    })
  }, [filter, deferredQuery, copyText])

  const copyAuth = async (p: ProviderItem) => {
    const ok = await copy(p.authCmd)
    setCopiedId(ok ? p.id : null)
  }

  const filters: Array<{ id: FilterKind; label: string }> = [
    { id: 'all', label: copyText.filterAll },
    { id: 'ssc', label: copyText.filterSsc },
    { id: 'rclone', label: copyText.filterRclone },
    { id: 'oauth', label: copyText.filterOauth },
    { id: 'zeroHttp', label: copyText.filterZeroHttp },
  ]

  return (
    <div className="not-prose my-5 flex flex-col gap-3">
      {/* Compact Controls */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter storage providers">
          {filters.map((f) => {
            const active = filter === f.id
            return (
              <button
                key={f.id}
                type="button"
                aria-pressed={active}
                onClick={() => setFilter(f.id)}
                className={`cursor-pointer rounded-md border px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                  active
                    ? 'border-[var(--brand-line)] bg-[var(--brand-soft)] text-[var(--brand)]'
                    : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg)]'
                }`}
              >
                {f.label}
              </button>
            )
          })}
        </div>

        <div className="flex w-full items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1.5 sm:w-[250px]">
          <Search size={13} className="shrink-0 text-[var(--muted)]" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={copyText.searchPlaceholder}
            aria-label={copyText.searchPlaceholder}
            className="w-full bg-transparent text-[12.5px] text-[var(--fg)] outline-none placeholder:text-[var(--subtle)]"
          />
        </div>
      </div>

      {/* Unified Swiss Hairline Ledger */}
      {filtered.length === 0 ? (
        <div className="rounded-[9px] border border-dashed border-[var(--border-strong)] px-4 py-8 text-center text-[13px] text-[var(--muted)]">
          {copyText.empty}
        </div>
      ) : (
        <div className="overflow-hidden rounded-[9px] border border-[var(--border)] bg-[var(--surface)]">
          <div className="flex items-center justify-between border-b border-[var(--border)] bg-[var(--chrome)] px-4 py-2 font-mono text-[10.5px] text-[var(--muted)]">
            <span className="uppercase tracking-[0.06em]">{copyText.tableHeader}</span>
            <span className="tabular-nums">
              {filtered.length} {copyText.countSuffix}
            </span>
          </div>

          <div className="divide-y divide-[var(--border)]">
            {filtered.map((p) => {
              const isRowCopied = copied && copiedId === p.id
              const guideTo = localizePath(p.docPath, locale)
              const copyItem = copyText.providers[p.id]
              const displayName = copyItem?.name ?? p.id

              return (
                <div
                  key={p.id}
                  className="flex flex-col gap-3 px-4 py-3.5 transition-colors hover:bg-[var(--chrome)]/45 sm:flex-row sm:items-center sm:justify-between sm:gap-5"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
                      <Link
                        to={guideTo}
                        onMouseEnter={() => void preloadRoute(guideTo)}
                        onFocus={() => void preloadRoute(guideTo)}
                        className="text-[14px] font-semibold tracking-[-0.015em] text-[var(--fg)] no-underline transition-colors hover:text-[var(--brand)]"
                      >
                        {displayName}
                      </Link>
                      <span className="rounded border border-[var(--border)] bg-[var(--chrome)] px-1.5 py-0.5 font-mono text-[10px] font-medium text-[var(--brand)]">
                        {p.feature}
                      </span>
                      <span className="font-mono text-[10.5px] text-[var(--subtle)]">
                        {p.metaTags.join(' · ')}
                      </span>
                    </div>

                    <p className="m-0 mt-1 text-[12.5px] leading-[1.55] text-[var(--muted)]">
                      {copyItem?.summary ?? ''}
                    </p>

                    <div className="mt-1.5 font-mono text-[11px] text-[var(--subtle)]">
                      <span className="text-[var(--muted)]">{copyText.resumeLabel}:</span>{' '}
                      {copyItem?.resume ?? ''}
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-2 self-start sm:self-center">
                    <button
                      type="button"
                      onClick={() => void copyAuth(p)}
                      title={p.authCmd}
                      aria-label={`Copy ${displayName} CLI command`}
                      className="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--bg)] px-2.5 font-mono text-[11px] font-medium text-[var(--muted)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
                    >
                      {isRowCopied ? (
                        <Check size={11} className="text-[var(--ok)]" />
                      ) : (
                        <Copy size={11} />
                      )}
                      <span>{isRowCopied ? copyText.copied : copyText.copyCli}</span>
                    </button>

                    <Link
                      to={guideTo}
                      onMouseEnter={() => void preloadRoute(guideTo)}
                      onFocus={() => void preloadRoute(guideTo)}
                      className="inline-flex h-7 items-center gap-1 rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 font-mono text-[11px] font-medium text-[var(--fg)] no-underline transition-colors hover:border-[var(--brand-line)] hover:text-[var(--brand)]"
                    >
                      <span>{copyText.guideLink}</span>
                      <ArrowRight size={11} />
                    </Link>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
