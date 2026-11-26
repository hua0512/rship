import { useState } from 'react'
import { ExternalLink } from 'lucide-react'
import { useI18n, type Locale } from '../../i18n/context'

interface ArchCopy {
  diagramLabel: string
  invariantsLabel: string
  keyTypesLabel: string
  viewCrateOnGitHub: string
  crates: Record<
    string,
    {
      layer: string
      summary: string
      invariants: string[]
    }
  >
}

const COPY: Record<Locale, ArchCopy> = {
  en: {
    diagramLabel: '7-Crate Dependency Topology',
    invariantsLabel: 'Key Responsibilities & Invariants',
    keyTypesLabel: 'Core Modules & Types',
    viewCrateOnGitHub: 'Open crate on GitHub',
    crates: {
      'rship-cli': {
        layer: 'Binary & Interactive TUI',
        summary:
          'Modular CLI binary, borderless live TUI dashboard, OS Keyring migration, credential export/import bundles, and ProviderAdapter auth/GC dispatch.',
        invariants: [
          'Delegates backend creation to rship::factory',
          'Honors NO_COLOR, CLICOLOR_FORCE, TERM=dumb, and --json / --json-progress',
        ],
      },
      rship: {
        layer: 'Ergonomic Rust SDK Facade',
        summary:
          'Top-level library API for Tokio services with zero anyhow in public signatures, lean default = ["local"] features, and shared config/factory.',
        invariants: [
          'Shares one HttpTransport, BufferPool, and StateActor across all workers',
          'Supports ephemeral zero-disk execution via RshipClient::ephemeral()',
        ],
      },
      'rship-backends': {
        layer: '9 Storage Drivers (Feature-Gated)',
        summary:
          'Unified StorageBackend implementations for local, gdrive, s3 (12 presets), dropbox, gcs, azureblob, onedrive, webdav, and sftp.',
        invariants: [
          'Heavy dependencies (russh, rsa, quick-xml) compile only when enabled',
          'Verified by rship_core::conformance::run_backend_conformance()',
        ],
      },
      'rship-crypto': {
        layer: 'STREAM OAE2 Overlay (#![forbid(unsafe_code)])',
        summary:
          'Zero-unsafe, hardware-accelerated (aws-lc-rs AVX2/NEON) 64 KiB seekable XChaCha20-Poly1305 overlay with Argon2id + HKDF and SIV base32 filenames.',
        invariants: [
          'Zeroizes key material automatically on drop',
          'Supports HTTP Range random-access decryption without full-file download',
        ],
      },
      'rship-state': {
        layer: 'Bundled SQLite WAL Persistence',
        summary:
          'Dedicated StateActor persisting transfer intents and resumable upload offsets in WAL mode, plus ephemeral SqliteSyncIndex for 1M-row diffs.',
        invariants: [
          'PRAGMA mmap_size = 0 and bounded page caches (-4096 / -8192)',
          'Cross-platform advisory ProcessLock prevents concurrent state corruption',
        ],
      },
      'rship-transport': {
        layer: 'Split H2/H1 HTTP & OAuth2 Plane',
        summary:
          'Separates HTTP/2 Control Plane from HTTP/1.1 Data Plane to prevent h2 buffer bloat, paired with CUBIC adaptive rate limiting and OAuth2 PKCE.',
        invariants: [
          'Data plane enforces .http1_only() + byte-progress idle stall watchdog',
          'Supports --proxy, --ca-cert, and --tpslimit uniformly',
        ],
      },
      'rship-core': {
        layer: 'Zero-I/O Engine & Conformance Core',
        summary:
          'Pure engine kernel containing BufferPool byte semaphore, Falcon dual-lane scheduler, Three-Tree bisync planner, FilterSet, and ChaosBackend DST.',
        invariants: [
          'Anti-deadlock rule: tasks hold at most one PooledSlice at a time',
          'Observation Completeness Gate blocks deletions on partial listing errors',
        ],
      },
    },
  },
  zh: {
    diagramLabel: '7-Crate 工作区依赖拓扑',
    invariantsLabel: '核心职责与工程不变量',
    keyTypesLabel: '关键模块与类型',
    viewCrateOnGitHub: '在 GitHub 查看源码目录',
    crates: {
      'rship-cli': {
        layer: '单二进制 CLI 与实时 TUI',
        summary:
          '单二进制 CLI 入口、实时 TUI 看板、系统密钥环迁移、无头凭据包导出/导入以及 ProviderAdapter 鉴权与 GC 调度。',
        invariants: [
          '所有后端实例化统一委托给 rship::factory',
          '严格遵循 NO_COLOR / TERM=dumb 与 --json / --json-progress 机器可读契约',
        ],
      },
      rship: {
        layer: 'Rust SDK 高层门面',
        summary:
          '面向 Tokio 服务的顶层 Rust SDK 门面 crate：公开 API 零 anyhow，默认仅开启 local 特性，共享配置与工厂实例。',
        invariants: [
          '跨全部并发任务共享单个 HttpTransport、BufferPool 与 WAL StateActor',
          '支持 RshipClient::ephemeral() 全内存零落盘模式',
        ],
      },
      'rship-backends': {
        layer: '9 大存储驱动（Feature 按需裁剪）',
        summary: '按 Cargo feature 按需编译的 9 大存储驱动，共用流式请求/校验与 XML/JWT 辅助层。',
        invariants: [
          '重量级依赖（russh、rsa、quick-xml）仅在启用对应 feature 时参与编译',
          '每个后端均须通过统一一致性测试套件 run_backend_conformance()',
        ],
      },
      'rship-crypto': {
        layer: 'STREAM OAE2 加密叠加层 (#![forbid(unsafe_code)])',
        summary:
          '零 unsafe 代码、基于 aws-lc-rs 硬件加速的 64 KiB 可随机 Seek XChaCha20-Poly1305 加密叠加层，附带 Argon2id 与 SIV 文件名加密。',
        invariants: [
          '通过 zeroize 在析构时自动擦除内存中的密钥材料',
          '支持按字节范围随机解密，无需整文件下载',
        ],
      },
      'rship-state': {
        layer: '内置 SQLite WAL 状态引擎',
        summary:
          '内置 SQLite WAL StateActor 持久化传输意图与分片偏移，并提供面向百万级文件差异比对的临时 SqliteSyncIndex。',
        invariants: [
          '强制 PRAGMA mmap_size = 0 与受控页缓存（-4096 / -8192）',
          '跨平台 ProcessLock 文件锁防止多进程并发写入损坏',
        ],
      },
      'rship-transport': {
        layer: 'H2/H1 分离传输与 OAuth2 引擎',
        summary:
          '控制面 HTTP/2 与数据面 HTTP/1.1 分离传输避免 h2 缓冲区膨胀，内置 CUBIC 自适应限流、字节停滞看门狗与 OAuth2 PKCE 引擎。',
        invariants: [
          '数据面默认 .http1_only() 并配备字节进度停滞看门狗',
          '统一支持 --proxy、--ca-cert 与 --tpslimit 全局速率上限',
        ],
      },
      'rship-core': {
        layer: '零 I/O 内核与一致性测试核心',
        summary:
          '零网络/磁盘耦合的纯内核引擎：包含 BufferPool 字节信号量、Falcon 双通道调度、三树双向同步规划器与 ChaosBackend 确定性测试。',
        invariants: [
          '防死锁不变量：单个任务同一时间最多持有 1 个 PooledSlice 租约',
          'Observation Completeness Gate 在不完整遍历下严格禁止执行任何删除',
        ],
      },
    },
  },
}

interface CrateNode {
  id: string
  name: string
  types: string[]
}

const CRATES: CrateNode[] = [
  { id: 'rship-cli', name: 'rship-cli', types: ['ProviderAdapter', 'tui.rs', 'ops/*', 'ui.rs'] },
  {
    id: 'rship',
    name: 'rship',
    types: ['RshipClient', 'ClientBuilder', 'TransferBuilder', 'BisyncBuilder', 'FailoverPool'],
  },
  {
    id: 'rship-backends',
    name: 'rship-backends',
    types: ['LocalBackend', 'GDriveBackend', 'S3Backend', 'SftpBackend', 'WebDavBackend'],
  },
  {
    id: 'rship-crypto',
    name: 'rship-crypto',
    types: ['CryptBackend', 'StreamEncryptor', 'StreamDecryptor', 'SivNameCipher'],
  },
  {
    id: 'rship-state',
    name: 'rship-state',
    types: ['StateActor', 'SqliteSyncIndex', 'DeltaInventoryStore', 'ProcessLock'],
  },
  {
    id: 'rship-transport',
    name: 'rship-transport',
    types: ['HttpTransport', 'ScopedLimiter', 'PkceSession', 'OAuth2TokenManager'],
  },
  {
    id: 'rship-core',
    name: 'rship-core',
    types: ['StorageBackend', 'BufferPool', 'PooledSlice', 'FalconController', 'FilterSet'],
  },
]

export function ArchitectureGraph() {
  const { locale } = useI18n()
  const copyText = COPY[locale] ?? COPY.en
  const [selectedId, setSelectedId] = useState('rship-core')

  const active = CRATES.find((c) => c.id === selectedId) ?? CRATES[0]
  const activeCopy = copyText.crates[active.id]

  const cratePill = (id: string) => {
    const c = CRATES.find((x) => x.id === id)!
    const copy = copyText.crates[id]
    const isSelected = selectedId === id
    return (
      <button
        key={id}
        type="button"
        aria-pressed={isSelected}
        onClick={() => setSelectedId(id)}
        className={`w-full cursor-pointer rounded-md border px-3 py-2 text-left transition-colors ${
          isSelected
            ? 'border-[var(--brand)] bg-[var(--brand-soft)]'
            : 'border-[var(--border)] bg-[var(--surface)] hover:border-[var(--border-strong)]'
        }`}
      >
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono text-[12px] font-semibold text-[var(--fg)]">{c.name}</span>
          {isSelected && <span className="h-1.5 w-1.5 rounded-full bg-[var(--brand)]" />}
        </div>
        <div className="mt-0.5 truncate font-mono text-[10px] text-[var(--muted)]">
          {copy?.layer ?? c.name}
        </div>
      </button>
    )
  }

  return (
    <div className="not-prose my-5 overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
      <div className="border-b border-[var(--border)] bg-[var(--chrome)] px-4 py-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--muted)]">
        {copyText.diagramLabel}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
        {/* Interactive Topology Layers */}
        <div
          className="flex flex-col gap-2.5 border-b border-[var(--border)] bg-[var(--bg)] p-4 lg:border-b-0 lg:border-r"
          role="group"
          aria-label="Workspace crates"
        >
          {cratePill('rship-cli')}
          <div className="mx-auto h-3 w-[1px] bg-[var(--border-strong)]" />
          {cratePill('rship')}
          <div className="mx-auto h-3 w-[1px] bg-[var(--border-strong)]" />
          <div className="grid grid-cols-2 gap-2">
            {['rship-backends', 'rship-crypto', 'rship-state', 'rship-transport'].map((id) =>
              cratePill(id),
            )}
          </div>
          <div className="mx-auto h-3 w-[1px] bg-[var(--border-strong)]" />
          {cratePill('rship-core')}
        </div>

        {/* Selected Crate Detail Drawer */}
        <div className="flex flex-col gap-3.5 p-4">
          <div className="flex items-start justify-between gap-2 border-b border-[var(--border)] pb-3">
            <div>
              <div className="font-mono text-[15px] font-bold text-[var(--fg)]">{active.name}</div>
              <div className="font-mono text-[11px] text-[var(--brand)]">
                {activeCopy?.layer ?? ''}
              </div>
            </div>
            <a
              href={`https://github.com/hua0512/rship/tree/main/crates/${active.id}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 rounded border border-[var(--border)] bg-[var(--chrome)] px-2 py-1 font-mono text-[10.5px] text-[var(--fg)] no-underline hover:border-[var(--brand)]"
            >
              <span>{copyText.viewCrateOnGitHub}</span>
              <ExternalLink size={11} />
            </a>
          </div>

          <p className="m-0 text-[13px] leading-[1.6] text-[var(--muted)]">
            {activeCopy?.summary ?? ''}
          </p>

          <div>
            <div className="mb-1.5 font-mono text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--fg)]">
              {copyText.invariantsLabel}
            </div>
            <ul className="m-0 flex flex-col gap-1.5 pl-4 text-[12.5px] text-[var(--muted)]">
              {(activeCopy?.invariants ?? []).map((inv) => (
                <li key={inv}>{inv}</li>
              ))}
            </ul>
          </div>

          <div className="mt-auto pt-1">
            <div className="mb-1.5 font-mono text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--fg)]">
              {copyText.keyTypesLabel}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {active.types.map((sym) => (
                <code
                  key={sym}
                  className="rounded border border-[var(--border)] bg-[var(--chrome)] px-2 py-0.5 font-mono text-[11px] text-[var(--fg)]"
                >
                  {sym}
                </code>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
