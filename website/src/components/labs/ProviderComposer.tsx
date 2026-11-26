import { useState } from 'react'
import { Check, Copy, KeyRound, Lock, PackageOpen } from 'lucide-react'
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard'
import { useI18n, type Locale } from '../../i18n/context'

interface ComposerCopy {
  title: string
  subtitle: string
  badgeLocal: string
  optCrypt: string
  optKeyring: string
  optRclone: string
  copyScript: string
  copied: string
  cImport: string
  cConnectPrefix: string
  cCrypt: string
  cKeyring: string
  cSync: string
}

const COPY: Record<Locale, ComposerCopy> = {
  en: {
    title: 'Cloud Recipe Composer',
    subtitle: 'Select a backend and stack security layers — generated 100% locally in your browser.',
    badgeLocal: 'Zero bytes leave browser',
    optCrypt: 'Wrap in STREAM OAE2 Vault',
    optKeyring: 'Lock secrets in OS Keyring',
    optRclone: 'Migrate from rclone.conf',
    copyScript: 'Copy Script',
    copied: 'Copied',
    cImport: '# 1. Import existing remotes from rclone.conf (preview with --dry-run)',
    cConnectPrefix: '# 1. Authorize',
    cCrypt: '# 2. Wrap remote in a seekable STREAM OAE2 encrypted vault',
    cKeyring: '# Move inline secrets into your OS Keyring',
    cSync: '# Run adaptive crash-resumable sync (<= 64 MiB RSS)',
  },
  zh: {
    title: '存储后端配置生成器',
    subtitle: '选择目标云并叠加加密 Vault 或系统密钥环 — 全程在浏览器本地生成，零数据上传。',
    badgeLocal: '100% 浏览器本地生成',
    optCrypt: '叠加 STREAM OAE2 加密层',
    optKeyring: '迁移密钥至系统 Keyring',
    optRclone: '直接从 rclone.conf 导入',
    copyScript: '复制脚本',
    copied: '已复制',
    cImport: '# 1. 从 rclone.conf 导入现有配置（可先加 --dry-run 预览）',
    cConnectPrefix: '# 1. 配置连接',
    cCrypt: '# 2. 在目标后端之上叠加可 Seek 的 STREAM OAE2 加密保险库',
    cKeyring: '# 将明文凭据锁入操作系统密钥环',
    cSync: '# 执行自适应断点续传同步（<= 64 MiB RSS）',
  },
}

interface ProviderPreset {
  id: string
  name: string
  sub: string
  meta: string
  cmd: string
  target: string
}

const PRESETS: ProviderPreset[] = [
  {
    id: 'r2',
    name: 'Cloudflare R2',
    sub: 'S3 · SigV4',
    meta: 'S3 Preset · CRC32C · Parallel Multipart',
    cmd: 'rship auth s3 r2 --provider r2 --bucket backups --region auto --endpoint https://<ACCOUNT_ID>.r2.cloudflarestorage.com',
    target: 'r2:backups',
  },
  {
    id: 'gdrive',
    name: 'Google Drive',
    sub: 'OAuth2 PKCE',
    meta: 'Drive v3 · 256 MiB 308 Resumable · changes.list',
    cmd: 'rship auth gdrive gdrive --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET>',
    target: 'gdrive:backups',
  },
  {
    id: 'sftp',
    name: 'SSH / SFTP',
    sub: 'russh',
    meta: 'Pooled Sessions · Offset Crash-Resume · known_hosts',
    cmd: 'rship auth sftp vps --host 10.0.0.5 --user deploy --key-file ~/.ssh/id_ed25519',
    target: 'vps:/srv/backups',
  },
  {
    id: 'webdav',
    name: 'WebDAV / NAS',
    sub: 'Nextcloud',
    meta: 'Chunked Upload v2 · Server-Side COPY',
    cmd: 'rship auth webdav nc --vendor nextcloud --url https://cloud.example.com/remote.php/dav/files/alice --username alice',
    target: 'nc:backups',
  },
  {
    id: 'dropbox',
    name: 'Dropbox v2',
    sub: '4 MiB Block Hash',
    meta: '4 MiB Upload Session · Native Content Hash',
    cmd: 'rship auth dropbox dbx --client-id <APP_KEY>',
    target: 'dbx:backups',
  },
  {
    id: 'gcs',
    name: 'Google Cloud Storage',
    sub: 'JWT / PKCE',
    meta: 'JSON API v1 · 256 KiB 308 Resumable · Rewrite Copy',
    cmd: 'rship auth gcs gcs --bucket my-archive --service-account-file ./sa.json',
    target: 'gcs:my-archive',
  },
  {
    id: 'azure',
    name: 'Azure Blob',
    sub: 'SharedKey / SAS',
    meta: 'REST 2023-11-03 · Put Block Parallel Resume',
    cmd: 'rship auth azureblob az --account myacct --container backups --key <KEY>',
    target: 'az:backups',
  },
  {
    id: 'onedrive',
    name: 'OneDrive / SharePoint',
    sub: 'Microsoft Graph',
    meta: '320 KiB Upload Sessions · Async Server Copy',
    cmd: 'rship auth onedrive od --client-id <AZURE_CLIENT_ID>',
    target: 'od:backups',
  },
]

export function ProviderComposer() {
  const { locale } = useI18n()
  const copyText = COPY[locale] ?? COPY.en
  const [selectedId, setSelectedId] = useState('r2')
  const [withCrypt, setWithCrypt] = useState(true)
  const [withKeyring, setWithKeyring] = useState(true)
  const [fromRclone, setFromRclone] = useState(false)
  const { copied, copy } = useCopyToClipboard()

  const active = PRESETS.find((p) => p.id === selectedId) ?? PRESETS[0]

  const scriptLines: string[] = []
  if (fromRclone) {
    scriptLines.push(copyText.cImport)
    scriptLines.push('rship config import-rclone ~/.config/rclone/rclone.conf')
  } else {
    scriptLines.push(`${copyText.cConnectPrefix} ${active.name}`)
    scriptLines.push(active.cmd)
  }

  let dest = active.target
  if (withCrypt) {
    scriptLines.push('')
    scriptLines.push(copyText.cCrypt)
    scriptLines.push(
      `rship auth crypt vault --target ${active.target}/vault --password "strong-passphrase"`,
    )
    dest = 'vault:2026'
  }

  if (withKeyring) {
    scriptLines.push('')
    scriptLines.push(copyText.cKeyring)
    scriptLines.push('rship auth keyring-migrate')
  }

  scriptLines.push('')
  scriptLines.push(copyText.cSync)
  scriptLines.push(`rship sync ./data ${dest} --adaptive --max-delete 100`)

  const plainScript = scriptLines.join('\n')

  return (
    <div className="not-prose my-5 overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] bg-[var(--chrome)] px-4 py-3">
        <div>
          <div className="text-[13.5px] font-semibold text-[var(--fg)]">{copyText.title}</div>
          <div className="text-[12px] text-[var(--muted)]">{copyText.subtitle}</div>
        </div>
        <span className="rounded border border-[var(--ok)]/35 bg-[var(--ok-soft)] px-2 py-0.5 font-mono text-[10.5px] font-medium text-[var(--ok)]">
          {copyText.badgeLocal}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[205px_minmax(0,1fr)]">
        {/* Left Master List */}
        <div
          className="flex flex-row overflow-x-auto border-b border-[var(--border)] bg-[var(--bg)] md:flex-col md:border-b-0 md:border-r"
          role="group"
          aria-label="Backend presets"
        >
          {PRESETS.map((p) => {
            const isActive = p.id === selectedId
            return (
              <button
                key={p.id}
                type="button"
                aria-pressed={isActive}
                onClick={() => setSelectedId(p.id)}
                className={`flex shrink-0 cursor-pointer flex-col gap-0.5 border-r border-[var(--border)] px-3.5 py-2.5 text-left transition-colors md:border-b md:border-r-0 md:last:border-b-0 ${
                  isActive
                    ? 'bg-[var(--surface)] text-[var(--fg)]'
                    : 'bg-transparent text-[var(--muted)] hover:bg-[var(--chrome)]/60 hover:text-[var(--fg)]'
                }`}
              >
                <span className="flex items-center justify-between gap-2 text-[12.5px] font-semibold text-[var(--fg)]">
                  <span>{p.name}</span>
                  {isActive && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--brand)]" />}
                </span>
                <span className="font-mono text-[10.5px] text-[var(--muted)]">{p.sub}</span>
              </button>
            )
          })}
        </div>

        {/* Right Detail Panel */}
        <div className="flex min-w-0 flex-col gap-3.5 bg-[var(--code-bg)] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[11px] text-[var(--muted)]">{active.meta}</span>
            <button
              type="button"
              onClick={() => void copy(plainScript)}
              className="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 font-mono text-[11px] font-medium text-[var(--fg)] hover:border-[var(--border-strong)]"
            >
              {copied ? <Check size={12} className="text-[var(--ok)]" /> : <Copy size={12} />}
              {copied ? copyText.copied : copyText.copyScript}
            </button>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              aria-pressed={withCrypt}
              onClick={() => setWithCrypt((v) => !v)}
              className={`inline-flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1.5 text-[12px] font-medium transition-colors ${
                withCrypt
                  ? 'border-[var(--brand-line)] bg-[var(--brand-soft)] text-[var(--fg)]'
                  : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]'
              }`}
            >
              <Lock size={12} className={withCrypt ? 'text-[var(--brand)]' : ''} />
              {copyText.optCrypt}
            </button>

            <button
              type="button"
              aria-pressed={withKeyring}
              onClick={() => setWithKeyring((v) => !v)}
              className={`inline-flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1.5 text-[12px] font-medium transition-colors ${
                withKeyring
                  ? 'border-[var(--brand-line)] bg-[var(--brand-soft)] text-[var(--fg)]'
                  : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]'
              }`}
            >
              <KeyRound size={12} className={withKeyring ? 'text-[var(--brand)]' : ''} />
              {copyText.optKeyring}
            </button>

            <button
              type="button"
              aria-pressed={fromRclone}
              onClick={() => setFromRclone((v) => !v)}
              className={`inline-flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1.5 text-[12px] font-medium transition-colors ${
                fromRclone
                  ? 'border-[var(--brand-line)] bg-[var(--brand-soft)] text-[var(--fg)]'
                  : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)]'
              }`}
            >
              <PackageOpen size={12} className={fromRclone ? 'text-[var(--brand)]' : ''} />
              {copyText.optRclone}
            </button>
          </div>

          <pre className="m-0 overflow-x-auto rounded-[7px] border border-[var(--border)] bg-[var(--surface)] p-3.5 font-mono text-[11.5px] leading-[1.7] text-[var(--fg)]">
            {scriptLines.map((line, i) => {
              if (line.startsWith('#')) {
                return (
                  <div key={i} className="text-[var(--muted)]">
                    {line}
                  </div>
                )
              }
              if (line.startsWith('rship ')) {
                return (
                  <div key={i}>
                    <span className="font-semibold text-[var(--brand)]">rship</span>
                    {line.slice(5)}
                  </div>
                )
              }
              return <div key={i}>{line || '\u00A0'}</div>
            })}
          </pre>
        </div>
      </div>
    </div>
  )
}
