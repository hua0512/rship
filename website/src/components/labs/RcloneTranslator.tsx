import { useId, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard'
import { useI18n, type Locale } from '../../i18n/context'

interface TranslatorCopy {
  labelRclone: string
  labelRship: string
  safetyNoteLabel: string
  copy: string
  copied: string
  scenarios: Record<
    string,
    {
      label: string
      upgrade: string
    }
  >
}

const COPY: Record<Locale, TranslatorCopy> = {
  en: {
    labelRclone: 'rclone',
    labelRship: 'rship',
    safetyNoteLabel: 'Engine Upgrade',
    copy: 'Copy',
    copied: 'Copied',
    scenarios: {
      import: {
        label: 'Config Import',
        upgrade:
          'Imports 8 cloud backends directly, decrypts AES-256-CTR obscured passwords, writes 0600 permissions, and optionally locks tokens in OS Keyring.',
      },
      copy: {
        label: 'Cloud Copy',
        upgrade:
          'Falcon dual-lane scheduler separates small files ([S]) from multi-part streams ([L]) under a strict <= 64 MiB BufferPool with SQLite WAL resume.',
      },
      sync: {
        label: 'Safe Mirror Sync',
        upgrade:
          'Observation Completeness Gate strictly aborts ALL destination deletions if any remote listing page fails, preventing accidental wipes on flaky networks.',
      },
      bisync: {
        label: 'Two-Way Bisync',
        upgrade:
          'Three-Tree bisync defaults to keep-both conflict preservation with explicit NFC/case collision detection — zero silent overwrites.',
      },
      crypt: {
        label: 'Encrypted Vault',
        upgrade:
          'STREAM OAE2 (64 KiB XChaCha20-Poly1305) hits 1,214 MiB/s local throughput at 52.9 MiB RSS (4.07× faster than rclone) and supports byte-range HTTP reads without downloading the full archive.',
      },
    },
  },
  zh: {
    labelRclone: 'rclone',
    labelRship: 'rship',
    safetyNoteLabel: '内核级增强',
    copy: '复制',
    copied: '已复制',
    scenarios: {
      import: {
        label: '导入配置',
        upgrade:
          '直接解析 8 大云盘配置，自动解密 AES-256-CTR 混淆密码并以 0600 权限落盘，还可选迁移进操作系统密钥环。',
      },
      copy: {
        label: '并发拷贝',
        upgrade:
          'Falcon 双通道自适应区分小文件与大文件流，硬上限 <= 64 MiB 内存池，并默认启用 SQLite WAL 崩溃断点续传。',
      },
      sync: {
        label: '安全镜像同步',
        upgrade:
          'Observation Completeness Gate 会在任何一次远端目录遍历失败时自动熔断所有删除操作，彻底杜绝网络抖动导致的误删。',
      },
      bisync: {
        label: '双向同步',
        upgrade:
          '三树模型双向同步默认采用 keep-both 零丢失策略，并显式捕获 NFC/大小写路径冲突，绝不静默覆盖任何文件。',
      },
      crypt: {
        label: '流式加密保险库',
        upgrade:
          '基于 STREAM OAE2（64 KiB XChaCha20-Poly1305），本地吞吐达 1,214 MiB/s 且峰值仅 52.9 MiB RSS（比 rclone 快 4.07×），并支持按字节偏移拉取密文片段，无需下载整包。',
      },
    },
  },
}

interface Scenario {
  id: string
  rcloneCmd: string
  rshipCmd: string
}

const SCENARIOS: Scenario[] = [
  {
    id: 'import',
    rcloneCmd: 'rclone config show ~/.config/rclone/rclone.conf',
    rshipCmd:
      'rship config import-rclone --dry-run\nrship config import-rclone ~/.config/rclone/rclone.conf\nrship auth keyring-migrate',
  },
  {
    id: 'copy',
    rcloneCmd: 'rclone copy ./photos gdrive:backups/photos --transfers 8 --bwlimit 20M -P',
    rshipCmd: 'rship copy ./photos gdrive:backups/photos --adaptive --bwlimit 20M',
  },
  {
    id: 'sync',
    rcloneCmd: 'rclone sync ./workspace r2:workspace --exclude ".git/" --max-delete 100',
    rshipCmd: "rship sync ./workspace r2:workspace --exclude '.git/' --max-delete 100",
  },
  {
    id: 'bisync',
    rcloneCmd: 'rclone bisync ./notes gdrive:notes --conflict-resolve newer',
    rshipCmd: 'rship bisync ./notes gdrive:notes --conflict-strategy keep-both',
  },
  {
    id: 'crypt',
    rcloneCmd: 'rclone copy ./secrets vault:2026',
    rshipCmd:
      'rship copy ./secrets vault:2026\nrship cat vault:2026/archive.tar --offset 1048576 --count 4096 | xxd',
  },
]

export function RcloneTranslator() {
  const { locale } = useI18n()
  const copyText = COPY[locale] ?? COPY.en
  const baseId = useId()
  const [activeId, setActiveId] = useState('copy')
  const { copied, copy, reset } = useCopyToClipboard()

  const item = SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0]
  const activeCopy = copyText.scenarios[item.id]

  return (
    <div className="not-prose my-5 overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
      <div
        className="flex flex-wrap gap-1.5 border-b border-[var(--border)] bg-[var(--chrome)] px-4 py-2.5"
        role="tablist"
        aria-label="rclone command scenarios"
      >
        {SCENARIOS.map((s) => {
          const active = s.id === activeId
          const label = copyText.scenarios[s.id]?.label ?? s.id
          return (
            <button
              key={s.id}
              id={`${baseId}-tab-${s.id}`}
              type="button"
              role="tab"
              aria-selected={active}
              aria-controls={`${baseId}-panel`}
              onClick={() => {
                setActiveId(s.id)
                reset()
              }}
              className={`cursor-pointer rounded-md border px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                active
                  ? 'border-[var(--brand-line)] bg-[var(--surface)] text-[var(--brand)]'
                  : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
              }`}
            >
              {label}
            </button>
          )
        })}
      </div>

      <div
        id={`${baseId}-panel`}
        role="tabpanel"
        aria-labelledby={`${baseId}-tab-${activeId}`}
        className="grid grid-cols-1 divide-y divide-[var(--border)] md:grid-cols-2 md:divide-x md:divide-y-0"
      >
        <div className="p-4">
          <div className="mb-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--muted)]">
            {copyText.labelRclone}
          </div>
          <pre className="m-0 overflow-x-auto rounded-md border border-[var(--border)] bg-[var(--code-bg)] p-3 font-mono text-[11.5px] leading-[1.65] text-[var(--muted)]">
            {item.rcloneCmd}
          </pre>
        </div>

        <div className="p-4">
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--brand)]">
              {copyText.labelRship}
            </span>
            <button
              type="button"
              onClick={() => void copy(item.rshipCmd)}
              className="inline-flex h-6 cursor-pointer items-center gap-1 rounded border border-[var(--border)] bg-[var(--chrome)] px-2 font-mono text-[10.5px] text-[var(--fg)]"
            >
              {copied ? <Check size={11} className="text-[var(--ok)]" /> : <Copy size={11} />}
              <span>{copied ? copyText.copied : copyText.copy}</span>
            </button>
          </div>
          <pre className="m-0 overflow-x-auto rounded-md border border-[var(--brand-line)] bg-[var(--code-bg)] p-3 font-mono text-[11.5px] leading-[1.65] text-[var(--fg)]">
            {item.rshipCmd}
          </pre>
        </div>
      </div>

      <div className="border-t border-[var(--border)] bg-[var(--chrome)] px-4 py-2.5 text-[12.5px] leading-[1.55] text-[var(--muted)]">
        <strong className="mr-2 font-mono text-[10.5px] uppercase tracking-[0.05em] text-[var(--fg)]">
          {copyText.safetyNoteLabel}:
        </strong>
        {activeCopy?.upgrade ?? ''}
      </div>
    </div>
  )
}
