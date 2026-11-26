import { useId, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard'
import { useI18n, type Locale } from '../../i18n/context'

interface XrayCopy {
  title: string
  subtitle: string
  fetchedLabel: string
  skippedLabel: string
  offsetLabel: string
  countLabel: string
  blocksUnit: string
  copy: string
  copied: string
}

const COPY: Record<Locale, XrayCopy> = {
  en: {
    title: '10 GiB Encrypted Archive · 64 KiB AEAD Segments',
    subtitle: 'Drag the byte offset and block count sliders to inspect exact HTTP Range requests.',
    fetchedLabel: 'fetched',
    skippedLabel: 'bandwidth skipped',
    offsetLabel: '--offset',
    countLabel: '--count',
    blocksUnit: 'blocks',
    copy: 'Copy',
    copied: 'Copied',
  },
  zh: {
    title: '10 GiB 加密对象 · 64 KiB AEAD 分块透视',
    subtitle: '拖动偏移量与读取块数滑块，实时查看 HTTP Range 精确拉取的数据块范围。',
    fetchedLabel: '实际拉取',
    skippedLabel: '节省流量',
    offsetLabel: '--offset',
    countLabel: '--count',
    blocksUnit: '块',
    copy: '复制',
    copied: '已复制',
  },
}

const TOTAL_SEGMENTS = 32
const TOTAL_ARCHIVE_BYTES = 10 * 1024 * 1024 * 1024 // 10 GiB
const BLOCK_BYTES = 64 * 1024 // 64 KiB AEAD block
const SEGMENT_OFFSET_STEP = Math.floor(TOTAL_ARCHIVE_BYTES / TOTAL_SEGMENTS)

export function Oae2Xray() {
  const { locale } = useI18n()
  const copyText = COPY[locale] ?? COPY.en
  const offsetId = useId()
  const countId = useId()
  const [offsetIdx, setOffsetIdx] = useState(10)
  const [blockCount, setBlockCount] = useState(3)
  const { copied, copy } = useCopyToClipboard()

  const byteOffset = offsetIdx * SEGMENT_OFFSET_STEP
  const byteCount = blockCount * BLOCK_BYTES
  const fetchedKiB = blockCount * 64
  const skippedPct = (100 - (byteCount / TOTAL_ARCHIVE_BYTES) * 100).toFixed(4)
  const approxGiB = ((offsetIdx * 10) / TOTAL_SEGMENTS).toFixed(1)

  const cmd = `rship cat vault:backups/archive.tar --offset ${byteOffset} --count ${byteCount}`

  return (
    <div className="not-prose my-5 overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] bg-[var(--chrome)] px-4 py-3">
        <div>
          <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.05em] text-[var(--fg)]">
            {copyText.title}
          </div>
          <div className="text-[12px] text-[var(--muted)]">{copyText.subtitle}</div>
        </div>
        <span className="font-mono text-[11px] font-semibold text-[var(--brand)] tabular-nums">
          {fetchedKiB} KiB {copyText.fetchedLabel} · {skippedPct}% {copyText.skippedLabel}
        </span>
      </div>

      <div className="p-4">
        <div
          className="mb-4 grid grid-cols-16 gap-1 sm:grid-cols-32"
          role="img"
          aria-label="64 KiB STREAM OAE2 encrypted blocks"
        >
          {Array.from({ length: TOTAL_SEGMENTS }, (_, idx) => {
            const hit = idx >= offsetIdx && idx < offsetIdx + blockCount
            return (
              <div
                key={idx}
                className={`h-6 rounded-[2px] transition-colors ${
                  hit ? 'bg-[var(--brand)]' : 'border border-[var(--border)] bg-[var(--chrome)]'
                }`}
              />
            )
          })}
        </div>

        <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label
              htmlFor={offsetId}
              className="mb-1.5 flex items-center justify-between font-mono text-[11px] text-[var(--muted)]"
            >
              <span>{copyText.offsetLabel}</span>
              <span className="font-semibold text-[var(--fg)] tabular-nums">
                #{offsetIdx} (~{approxGiB} GiB)
              </span>
            </label>
            <input
              id={offsetId}
              type="range"
              min={0}
              max={TOTAL_SEGMENTS - 1}
              value={offsetIdx}
              onChange={(e) => {
                const next = Number(e.target.value)
                setOffsetIdx(Math.min(next, TOTAL_SEGMENTS - blockCount))
              }}
              className="w-full cursor-pointer accent-[var(--brand)]"
            />
          </div>

          <div>
            <label
              htmlFor={countId}
              className="mb-1.5 flex items-center justify-between font-mono text-[11px] text-[var(--muted)]"
            >
              <span>{copyText.countLabel}</span>
              <span className="font-semibold text-[var(--fg)] tabular-nums">
                {blockCount} {copyText.blocksUnit} ({fetchedKiB} KiB)
              </span>
            </label>
            <input
              id={countId}
              type="range"
              min={1}
              max={8}
              value={blockCount}
              onChange={(e) => {
                const next = Number(e.target.value)
                setBlockCount(next)
                if (offsetIdx + next > TOTAL_SEGMENTS) {
                  setOffsetIdx(TOTAL_SEGMENTS - next)
                }
              }}
              className="w-full cursor-pointer accent-[var(--brand)]"
            />
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 rounded-md border border-[var(--border)] bg-[var(--code-bg)] px-3 py-2">
          <code className="overflow-x-auto whitespace-nowrap font-mono text-[11.5px] text-[var(--fg)]">
            <span className="font-semibold text-[var(--brand)]">$</span> {cmd}
          </code>
          <button
            type="button"
            onClick={() => void copy(cmd)}
            className="inline-flex h-6 shrink-0 cursor-pointer items-center gap-1 rounded border border-[var(--border)] bg-[var(--surface)] px-2 font-mono text-[10.5px] text-[var(--muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
          >
            {copied ? <Check size={11} className="text-[var(--ok)]" /> : <Copy size={11} />}
            <span>{copied ? copyText.copied : copyText.copy}</span>
          </button>
        </div>
      </div>
    </div>
  )
}
