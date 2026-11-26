import { useEffect, useReducer, useState } from 'react'
import { useI18n } from '../i18n/context'

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

type SimState = 'running' | 'killed' | 'done'
type EventKind = 'none' | 'killed' | 'resumed' | 'done'

interface TerminalState {
  simState: SimState
  pct: number
  frame: number
  eventKind: EventKind
  killedAtPct: number
}

type TerminalAction = { type: 'TICK' } | { type: 'TOGGLE' }

function terminalReducer(state: TerminalState, action: TerminalAction): TerminalState {
  if (action.type === 'TICK') {
    if (state.simState !== 'running') return state
    const nextPct = Math.min(100, state.pct + 1.1)
    const nextFrame = (state.frame + 1) % SPINNER_FRAMES.length
    if (nextPct >= 100) {
      return {
        ...state,
        pct: 100,
        frame: nextFrame,
        simState: 'done',
        eventKind: 'done',
      }
    }
    return {
      ...state,
      pct: nextPct,
      frame: nextFrame,
    }
  }

  if (state.simState === 'running') {
    return {
      ...state,
      killedAtPct: state.pct,
      simState: 'killed',
      eventKind: 'killed',
    }
  }

  if (state.simState === 'killed') {
    return {
      ...state,
      simState: 'running',
      eventKind: 'resumed',
    }
  }

  return {
    ...state,
    pct: 24,
    simState: 'running',
    eventKind: 'none',
  }
}

export function HeroTerminal() {
  const { t } = useI18n()
  const [state, dispatch] = useReducer(terminalReducer, {
    simState: 'running',
    pct: 62,
    frame: 0,
    eventKind: 'none',
    killedAtPct: 62,
  })
  const [reducedMotion, setReducedMotion] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const media = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReducedMotion(media.matches)
    const onChange = (e: MediaQueryListEvent) => setReducedMotion(e.matches)
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  useEffect(() => {
    if (state.simState !== 'running' || reducedMotion) return

    let timer: number | null = null

    const start = () => {
      if (timer !== null || document.hidden) return
      timer = window.setInterval(() => dispatch({ type: 'TICK' }), 420)
    }

    const stop = () => {
      if (timer !== null) {
        window.clearInterval(timer)
        timer = null
      }
    }

    const onVisibility = () => {
      if (document.hidden) stop()
      else start()
    }

    start()
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [state.simState, reducedMotion])

  const { simState, pct, frame, eventKind, killedAtPct } = state
  const slot0 = pct >= 99.5 ? 100 : Math.min(100, Math.round(pct * 1.18))
  const slot1 = pct >= 99.5 ? 100 : Math.min(100, Math.round(pct * 0.92))
  const volumeTransferred = ((18.4 * pct) / 100).toFixed(1)

  const barColor =
    simState === 'killed'
      ? 'bg-[var(--err)]'
      : simState === 'done'
        ? 'bg-[var(--ok)]'
        : 'bg-[var(--brand)]'

  const slotColor = (value: number) =>
    simState === 'killed'
      ? 'bg-[var(--err)]'
      : value >= 100
        ? 'bg-[var(--ok)]'
        : 'bg-[var(--brand)]'

  const btnLabel =
    simState === 'running'
      ? t.home.terminal.btnKill
      : simState === 'killed'
        ? t.home.terminal.btnResume
        : t.home.terminal.btnReplay

  const btnClass =
    simState === 'killed'
      ? 'border-[var(--brand-line)] bg-[var(--brand-soft)] text-[var(--brand)]'
      : simState === 'done'
        ? 'border-[var(--ok)]/40 text-[var(--ok)]'
        : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] hover:border-[var(--err)] hover:text-[var(--err)]'

  return (
    <section className="overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
      <div className="flex h-10 items-center justify-between gap-2.5 border-b border-[var(--border)] bg-[var(--chrome)] px-4">
        <span className="inline-flex items-center gap-2 font-mono text-[11px] text-[var(--muted)]">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              simState === 'killed' ? 'bg-[var(--err)]' : 'bg-[var(--ok)]'
            }`}
          />
          <span>{t.home.terminal.title}</span>
        </span>

        <button
          type="button"
          onClick={() => dispatch({ type: 'TOGGLE' })}
          className={`inline-flex h-[26px] cursor-pointer items-center rounded-[5px] border px-2.5 font-mono text-[10.5px] font-medium transition-colors ${btnClass}`}
        >
          {btnLabel}
        </button>
      </div>

      <div className="overflow-x-auto px-5 py-4 font-mono text-[12px] leading-[1.75] tabular-nums">
        <div className="min-w-[500px]">
          <div className="mb-3 text-[var(--fg)]">
            <span className="mr-2 font-semibold text-[var(--brand)]">$</span>
            rship copy ./photos gdrive:backups/photos --adaptive
          </div>

          <div className="mb-1 flex items-center gap-3 whitespace-nowrap">
            <span
              className="w-3 font-semibold"
              style={{
                color:
                  simState === 'killed'
                    ? 'var(--err)'
                    : simState === 'done'
                      ? 'var(--ok)'
                      : 'var(--brand)',
              }}
            >
              {simState === 'killed'
                ? '✕'
                : simState === 'done'
                  ? '✓'
                  : SPINNER_FRAMES[frame]}
            </span>
            <span className="font-semibold text-[var(--fg)]">copy</span>
            <div className="h-[3px] flex-1 overflow-hidden rounded-full bg-[var(--border)]">
              <div
                className={`h-full transition-all duration-200 ${barColor}`}
                style={{ width: `${pct.toFixed(1)}%` }}
              />
            </div>
            <span className="w-11 text-right font-semibold text-[var(--fg)]">
              {pct.toFixed(1)}%
            </span>
            <span className="text-[var(--muted)]">{volumeTransferred} / 18.4 GiB</span>
            <span className="text-[var(--fg)]">
              {simState === 'killed' ? '0.0 MiB/s' : '32.4 MiB/s'}
            </span>
          </div>

          <div className="mb-3.5 pl-4 text-[11px] text-[var(--muted)]">
            {t.home.terminal.statsSummary}
          </div>

          <div className="flex flex-col gap-1.5 pl-4 text-[11.5px]">
            <div className="grid grid-cols-[26px_minmax(0,1fr)_100px_38px] items-center gap-3">
              <span className="text-[var(--brand)]">[L]</span>
              <span className="truncate text-[var(--fg)]">photos/RAW_8842.dng</span>
              <div className="h-[3px] overflow-hidden rounded-full bg-[var(--border)]">
                <div
                  className={`h-full transition-all duration-200 ${slotColor(slot0)}`}
                  style={{ width: `${slot0}%` }}
                />
              </div>
              <span className="text-right text-[var(--muted)]">{slot0}%</span>
            </div>

            <div className="grid grid-cols-[26px_minmax(0,1fr)_100px_38px] items-center gap-3">
              <span className="text-[var(--brand)]">[L]</span>
              <span className="truncate text-[var(--fg)]">
                photos/archive_2026_backup.tar.zst
              </span>
              <div className="h-[3px] overflow-hidden rounded-full bg-[var(--border)]">
                <div
                  className={`h-full transition-all duration-200 ${slotColor(slot1)}`}
                  style={{ width: `${slot1}%` }}
                />
              </div>
              <span className="text-right text-[var(--muted)]">{slot1}%</span>
            </div>

            <div className="grid grid-cols-[26px_minmax(0,1fr)_100px_38px] items-center gap-3">
              <span className="text-[var(--muted)]">[S]</span>
              <span className="truncate text-[var(--fg)]">photos/meta/exif_0412.json</span>
              <div className="h-[3px] overflow-hidden rounded-full bg-[var(--border)]">
                <div className="h-full w-full bg-[var(--ok)]" />
              </div>
              <span className="text-right text-[var(--muted)]">100%</span>
            </div>
          </div>

          {eventKind !== 'none' && (
            <div
              className={`mt-3.5 border-t border-dashed border-[var(--border)] pt-3 text-[11px] ${
                eventKind === 'killed' ? 'text-[var(--err)]' : 'text-[var(--ok)]'
              }`}
            >
              {eventKind === 'killed' &&
                `✕ ${t.home.terminal.killedEventPrefix} ${killedAtPct.toFixed(1)}% ${t.home.terminal.killedEventSuffix}`}
              {eventKind === 'resumed' && t.home.terminal.resumedEvent}
              {eventKind === 'done' && `✓ ${t.home.terminal.doneEvent}`}
            </div>
          )}
        </div>
      </div>
    </section>
  )
}
