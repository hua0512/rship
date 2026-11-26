import { useState } from 'react'
import { useI18n, type Locale } from '../../i18n/context'

interface VpsLabCopy {
  rship: string
  rclone: string
  title: string
  subtitle: string
  ramBudgetLabel: string
  catGdrive: string
  catLocal: string
  metricRss: string
  metricSpeed: string
  legendRss: string
  legendSpeed: string
  oomBadge: string
  footSyncDiff: string
  footCrashResume: string
}

const COPY: Record<Locale, VpsLabCopy> = {
  en: {
    rship: 'rship 0.1.0',
    rclone: 'rclone (1G: v1.60.1 · NVMe: v1.76.0)',
    title: 'VPS Memory Cliff Simulator',
    subtitle: 'Pick your container RAM ceiling to see which engine triggers the Linux OOM Killer.',
    ramBudgetLabel: 'VPS RAM Limit',
    catGdrive: '1G Live Google Drive',
    catLocal: 'Local NVMe',
    metricRss: 'Peak RSS',
    metricSpeed: 'Throughput',
    legendRss: 'Lower bar = less RAM · Dashed line marks VPS OOM threshold',
    legendSpeed: 'Higher bar = faster completion · MD5 bit-exact verified',
    oomBadge: 'OOM @',
    footSyncDiff: '1,000,000-row SQLite SyncIndex diff (release): 1.55 s · 25.2 MiB RSS (~39% of 64 MiB cap; 16.6 MiB w/ system allocator)',
    footCrashResume: 'Default build uses tuned mimalloc v3 (no_thp + bounded 2..=8 Tokio workers) — every workload stays under 64 MiB RSS.',
  },
  zh: {
    rship: 'rship 0.1.0',
    rclone: 'rclone (1G: v1.60.1 · NVMe: v1.76.0)',
    title: 'VPS 内存悬崖模拟器',
    subtitle: '选择服务器内存上限，直观对比 rship 与 rclone 何时会触发 OOM Killer。',
    ramBudgetLabel: 'VPS 内存上限',
    catGdrive: '1G Google Drive 实测',
    catLocal: '本地 NVMe',
    metricRss: '峰值内存 (RSS)',
    metricSpeed: '吞吐速度',
    legendRss: '越短越省内存 · 红色竖线代表 VPS OOM 临界线',
    legendSpeed: '越长速度越快 · 全程 MD5 逐比特校验',
    oomBadge: '触发 OOM @',
    footSyncDiff: '1,000,000 行 SQLite SyncIndex 差异对比（Release）：1.55 秒 · 25.2 MiB RSS（占 64 MiB 上限 39%，系统分配器 16.6 MiB）',
    footCrashResume: '默认采用调优后的 mimalloc v3（no_thp + 2..=8 有界 Tokio 工作线程），全部云端与本地负载均严格低于 64 MiB RSS。',
  },
}

interface BenchRow {
  workload: string
  category: 'gdrive' | 'local'
  rshipRss: number
  rcloneRss: number
  rshipPerf: string
  rclonePerf: string
  rssGain: string
  speedGain: string
  rshipSpeedPct: number
  rcloneSpeedPct: number
}

const BENCH_ROWS: BenchRow[] = [
  {
    workload: 'GDrive 4×64 MiB Parallel Upload (--transfers 4)',
    category: 'gdrive',
    rshipRss: 54.8,
    rcloneRss: 374.5,
    rshipPerf: 'Up to 32.1 MiB/s',
    rclonePerf: '28.9 MiB/s (64M)',
    rssGain: '6.8× less RAM',
    speedGain: '1.11× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 90,
  },
  {
    workload: 'GDrive 128 MiB Single Upload',
    category: 'gdrive',
    rshipRss: 29.4,
    rcloneRss: 132.5,
    rshipPerf: 'Up to 27.6 MiB/s',
    rclonePerf: '23.2 MiB/s (64M)',
    rssGain: '4.5× less RAM',
    speedGain: '1.19× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 84,
  },
  {
    workload: 'GDrive 64 MiB Crypt Upload (STREAM OAE2)',
    category: 'gdrive',
    rshipRss: 47.1,
    rcloneRss: 147.9,
    rshipPerf: '11.2–12.1 MiB/s',
    rclonePerf: '7.6–8.3 MiB/s (64M)',
    rssGain: '3.1× less RAM',
    speedGain: 'Up to 1.58× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 68,
  },
  {
    workload: 'GDrive 64 MiB Crypt Download (4-Part OAE2)',
    category: 'gdrive',
    rshipRss: 45.5,
    rcloneRss: 70.8,
    rshipPerf: '13.0–26.2 MiB/s',
    rclonePerf: '9.5–13.4 MiB/s',
    rssGain: '1.6× less RAM',
    speedGain: 'Up to 1.95× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 58,
  },
  {
    workload: 'GDrive 128 MiB 4-Stream Download',
    category: 'gdrive',
    rshipRss: 31.6,
    rcloneRss: 55.6,
    rshipPerf: 'Up to 77.1 MiB/s',
    rclonePerf: '14.5–21.1 MiB/s (4-stream)',
    rssGain: '1.8× less RAM',
    speedGain: 'Up to 3.66× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 27,
  },
  {
    workload: 'GDrive Warm Sync (changes.list)',
    category: 'gdrive',
    rshipRss: 31.1,
    rcloneRss: 52.7,
    rshipPerf: '285–304 ms',
    rclonePerf: '1,239–1,305 ms',
    rssGain: '1.7× less RAM',
    speedGain: '4.1–4.6× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 23,
  },
  {
    workload: '1 GiB Local Copy (NVMe)',
    category: 'local',
    rshipRss: 17.5,
    rcloneRss: 64.7,
    rshipPerf: '905 ms (1,131 MiB/s)',
    rclonePerf: '1,323 ms (774 MiB/s)',
    rssGain: '3.7× less RAM',
    speedGain: '1.46× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 68,
  },
  {
    workload: '1 GiB OAE2 Crypt Write (Local NVMe)',
    category: 'local',
    rshipRss: 52.9,
    rcloneRss: 79.7,
    rshipPerf: '844 ms (1,214 MiB/s)',
    rclonePerf: '3,436 ms (298 MiB/s)',
    rssGain: '1.5× less RAM',
    speedGain: '4.07× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 25,
  },
  {
    workload: '5,000-File Warm Sync',
    category: 'local',
    rshipRss: 26.3,
    rcloneRss: 65.8,
    rshipPerf: '27.6 ms',
    rclonePerf: '132.0 ms',
    rssGain: '2.5× less RAM',
    speedGain: '4.78× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 21,
  },
  {
    workload: '5,000-File Warm Bisync (--transfers 16)',
    category: 'local',
    rshipRss: 25.3,
    rcloneRss: 58.9,
    rshipPerf: '42.5 ms',
    rclonePerf: '206.9 ms',
    rssGain: '2.3× less RAM',
    speedGain: '4.87× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 21,
  },
  {
    workload: '5,000-File Read-Only ls -r (Lazy Zero-DB)',
    category: 'local',
    rshipRss: 15.5,
    rcloneRss: 51.1,
    rshipPerf: '23.7 ms',
    rclonePerf: '103.4 ms',
    rssGain: '3.3× less RAM',
    speedGain: '4.36× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 23,
  },
  {
    workload: '1 GiB Hardware CRC-32C Hashsum',
    category: 'local',
    rshipRss: 14.6,
    rcloneRss: 46.7,
    rshipPerf: '230 ms (4.3 GiB/s)',
    rclonePerf: '306 ms (3.3 GiB/s)',
    rssGain: '3.2× less RAM',
    speedGain: '1.33× faster',
    rshipSpeedPct: 100,
    rcloneSpeedPct: 75,
  },
]

const RAM_LIMITS = [128, 256, 512] as const

export function VpsMemoryLab() {
  const { locale } = useI18n()
  const copy = COPY[locale] ?? COPY.en
  const [category, setCategory] = useState<'gdrive' | 'local'>('gdrive')
  const [metric, setMetric] = useState<'rss' | 'speed'>('rss')
  const [vpsRam, setVpsRam] = useState<128 | 256 | 512>(256)

  const visible = BENCH_ROWS.filter((r) => r.category === category)
  const scaleMax = Math.max(390, vpsRam * 1.15)
  const cliffPct = Math.min(97, (vpsRam / scaleMax) * 100).toFixed(1)

  return (
    <div className="not-prose my-5 overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] bg-[var(--chrome)] px-4 py-3">
        <div>
          <div className="text-[13.5px] font-semibold text-[var(--fg)]">{copy.title}</div>
          <div className="text-[12px] text-[var(--muted)]">{copy.subtitle}</div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {metric === 'rss' && (
            <div
              className="inline-flex items-center overflow-hidden rounded-md border border-[var(--border)] bg-[var(--surface)]"
              role="group"
              aria-label={copy.ramBudgetLabel}
            >
              <span className="border-r border-[var(--border)] px-2.5 py-1 font-mono text-[10.5px] text-[var(--muted)]">
                {copy.ramBudgetLabel}
              </span>
              {RAM_LIMITS.map((ram) => (
                <button
                  key={ram}
                  type="button"
                  aria-pressed={vpsRam === ram}
                  onClick={() => setVpsRam(ram)}
                  className={`cursor-pointer border-r border-[var(--border)] px-2.5 py-1 font-mono text-[11px] last:border-r-0 ${
                    vpsRam === ram
                      ? 'bg-[var(--brand-soft)] font-semibold text-[var(--brand)]'
                      : 'text-[var(--muted)] hover:text-[var(--fg)]'
                  }`}
                >
                  {ram}M
                </button>
              ))}
            </div>
          )}

          <div
            className="inline-flex divide-x divide-[var(--border)] overflow-hidden rounded-md border border-[var(--border)] bg-[var(--surface)]"
            role="group"
            aria-label="Workload category"
          >
            <button
              type="button"
              aria-pressed={category === 'gdrive'}
              onClick={() => setCategory('gdrive')}
              className={`cursor-pointer px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                category === 'gdrive'
                  ? 'bg-[var(--chrome)] font-semibold text-[var(--fg)]'
                  : 'text-[var(--muted)] hover:text-[var(--fg)]'
              }`}
            >
              {copy.catGdrive}
            </button>
            <button
              type="button"
              aria-pressed={category === 'local'}
              onClick={() => setCategory('local')}
              className={`cursor-pointer px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                category === 'local'
                  ? 'bg-[var(--chrome)] font-semibold text-[var(--fg)]'
                  : 'text-[var(--muted)] hover:text-[var(--fg)]'
              }`}
            >
              {copy.catLocal}
            </button>
          </div>

          <div
            className="inline-flex divide-x divide-[var(--border)] overflow-hidden rounded-md border border-[var(--border)] bg-[var(--surface)]"
            role="group"
            aria-label="Comparison metric"
          >
            <button
              type="button"
              aria-pressed={metric === 'rss'}
              onClick={() => setMetric('rss')}
              className={`cursor-pointer px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                metric === 'rss'
                  ? 'bg-[var(--chrome)] font-semibold text-[var(--fg)]'
                  : 'text-[var(--muted)] hover:text-[var(--fg)]'
              }`}
            >
              {copy.metricRss}
            </button>
            <button
              type="button"
              aria-pressed={metric === 'speed'}
              onClick={() => setMetric('speed')}
              className={`cursor-pointer px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                metric === 'speed'
                  ? 'bg-[var(--chrome)] font-semibold text-[var(--fg)]'
                  : 'text-[var(--muted)] hover:text-[var(--fg)]'
              }`}
            >
              {copy.metricSpeed}
            </button>
          </div>
        </div>
      </div>

      {/* Legend strip */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] px-4 py-2 font-mono text-[11px] text-[var(--muted)]">
        <div className="flex items-center gap-4">
          <span className="inline-flex items-center gap-1.5 font-medium text-[var(--fg)]">
            <span className="h-2 w-2 rounded-[2px] bg-[var(--brand)]" />
            {copy.rship}
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-[2px] bg-[var(--subtle)]" />
            {copy.rclone}
          </span>
        </div>
        <span>{metric === 'rss' ? copy.legendRss : copy.legendSpeed}</span>
      </div>

      {/* Rows */}
      <div className="divide-y divide-[var(--border)] px-4">
        {visible.map((row) => {
          const isOom = metric === 'rss' && row.rcloneRss > vpsRam
          const isRshipOom = metric === 'rss' && row.rshipRss > vpsRam
          const rshipW =
            metric === 'rss'
              ? `${Math.min(100, Math.max(3, (row.rshipRss / scaleMax) * 100)).toFixed(1)}%`
              : `${row.rshipSpeedPct}%`
          const rcloneW =
            metric === 'rss'
              ? `${Math.min(100, (row.rcloneRss / scaleMax) * 100).toFixed(1)}%`
              : `${row.rcloneSpeedPct}%`

          return (
            <div key={row.workload} className="py-3">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <span className="text-[13px] font-medium text-[var(--fg)]">{row.workload}</span>
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="rounded border border-[var(--border)] bg-[var(--chrome)] px-2 py-0.5 text-[var(--fg)]">
                    {metric === 'rss' ? row.rssGain : row.speedGain}
                  </span>
                  {isOom && (
                    <span className="rounded border border-[var(--err)]/40 bg-[var(--err-soft)] px-2 py-0.5 font-semibold text-[var(--err)]">
                      rclone {copy.oomBadge} {vpsRam} MiB
                    </span>
                  )}
                  {isRshipOom && (
                    <span className="rounded border border-[var(--err)]/40 bg-[var(--err-soft)] px-2 py-0.5 font-semibold text-[var(--err)]">
                      rship (mimalloc) {copy.oomBadge} {vpsRam} MiB
                    </span>
                  )}
                </div>
              </div>

              <div className="flex flex-col gap-1.5 font-mono text-[11px] tabular-nums">
                <div className="grid grid-cols-[52px_1fr_auto] items-center gap-3">
                  <span className="font-semibold text-[var(--fg)]">rship</span>
                  <div className="relative h-2 overflow-hidden rounded-[2px] bg-[var(--chrome)]">
                    <div
                      className={`h-full rounded-[2px] transition-all duration-300 ${
                        isRshipOom ? 'bg-[var(--err)] opacity-85' : 'bg-[var(--brand)]'
                      }`}
                      style={{ width: rshipW }}
                    />
                    {metric === 'rss' && (
                      <div
                        className="pointer-events-none absolute inset-y-0 w-[1.5px] bg-[var(--err)]/85"
                        style={{ left: `${cliffPct}%` }}
                      />
                    )}
                  </div>
                  <span
                    className={`min-w-[82px] text-right font-semibold ${
                      isRshipOom ? 'text-[var(--err)]' : 'text-[var(--fg)]'
                    }`}
                  >
                    {metric === 'rss' ? `${row.rshipRss.toFixed(1)} MiB` : row.rshipPerf}
                  </span>
                </div>

                <div className="grid grid-cols-[52px_1fr_auto] items-center gap-3">
                  <span className="text-[var(--muted)]">rclone</span>
                  <div className="relative h-2 overflow-hidden rounded-[2px] bg-[var(--chrome)]">
                    <div
                      className={`h-full rounded-[2px] transition-all duration-300 ${
                        isOom ? 'bg-[var(--err)] opacity-85' : 'bg-[var(--subtle)] opacity-60'
                      }`}
                      style={{ width: rcloneW }}
                    />
                    {metric === 'rss' && (
                      <div
                        className="pointer-events-none absolute inset-y-0 w-[1.5px] bg-[var(--err)]/85"
                        style={{ left: `${cliffPct}%` }}
                      />
                    )}
                  </div>
                  <span
                    className={`min-w-[82px] text-right ${
                      isOom ? 'font-semibold text-[var(--err)]' : 'text-[var(--muted)]'
                    }`}
                  >
                    {metric === 'rss' ? `${row.rcloneRss.toFixed(1)} MiB` : row.rclonePerf}
                  </span>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Footer notes */}
      <div className="flex flex-col gap-1 border-t border-[var(--border)] bg-[var(--chrome)] px-4 py-2.5 font-mono text-[11px] text-[var(--muted)]">
        <div>{copy.footSyncDiff}</div>
        <div>{copy.footCrashResume}</div>
      </div>
    </div>
  )
}
