import {
  Children,
  createContext,
  isValidElement,
  Suspense,
  useContext,
  useId,
  useMemo,
  useRef,
  useState,
  type ComponentPropsWithoutRef,
  type ReactNode,
} from 'react'
import { Link } from 'react-router'
import { AlertTriangle, Check, Copy, Info, Terminal } from 'lucide-react'
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard'
import { localizePath, useI18n } from '../../i18n/context'
import { preloadRoute } from '../../lib/preload'
import { ErrorBoundary } from '../ErrorBoundary'
import { getCachedLab, getLazyLab, type LabName } from '../labs/registry'

function LabLoadingPlaceholder() {
  return (
    <div
      className="not-prose my-5 h-36 rounded-[10px] border border-[var(--border)] bg-[var(--surface)] p-4"
      aria-busy="true"
    >
      <div className="mb-3 h-4 w-44 rounded bg-[var(--chrome)]" />
      <div className="h-16 w-full rounded bg-[var(--chrome)]" />
    </div>
  )
}

function createLabSlot(name: LabName) {
  const LazyLab = getLazyLab(name)

  return function LabSlot() {
    const Cached = getCachedLab(name)
    if (Cached) {
      return (
        <ErrorBoundary>
          <Cached />
        </ErrorBoundary>
      )
    }
    return (
      <ErrorBoundary>
        <Suspense fallback={<LabLoadingPlaceholder />}>
          <LazyLab />
        </Suspense>
      </ErrorBoundary>
    )
  }
}

const VpsMemoryLabSlot = createLabSlot('VpsMemoryLab')
const ProviderComposerSlot = createLabSlot('ProviderComposer')
const ProviderMatrixSlot = createLabSlot('ProviderMatrix')
const Oae2XraySlot = createLabSlot('Oae2Xray')
const RcloneTranslatorSlot = createLabSlot('RcloneTranslator')
const ArchitectureGraphSlot = createLabSlot('ArchitectureGraph')

interface CalloutProps {
  type?: 'tip' | 'warning' | 'info'
  title?: string
  children: ReactNode
}

export function Callout({ type = 'tip', title, children }: CalloutProps) {
  const styles = {
    tip: {
      iconColor: 'text-[var(--brand)]',
      Icon: Terminal,
    },
    warning: {
      iconColor: 'text-[var(--warn)]',
      Icon: AlertTriangle,
    },
    info: {
      iconColor: 'text-[var(--info)]',
      Icon: Info,
    },
  }[type]

  const Icon = styles.Icon

  return (
    <aside className="my-5 rounded-[8px] border border-[var(--border)] bg-[var(--chrome)]/55 px-4 py-3.5 text-[13.5px] leading-[1.6]">
      {title && (
        <div className="mb-1.5 flex items-center gap-2 text-[12.5px] font-semibold tracking-[-0.01em] text-[var(--fg)]">
          <Icon size={14} className={styles.iconColor} />
          <span>{title}</span>
        </div>
      )}
      <div className="[&>p]:my-1.5 [&>p:first-child]:mt-0 [&>p:last-child]:mb-0 [&_.mdx-code-shell]:my-2.5">
        {children}
      </div>
    </aside>
  )
}

const InsideCodeTabsContext = createContext(false)

interface CodeTabItem {
  label: string
  lang?: string
  code: string
}

export function CodeTab({ children }: { label: string; children: ReactNode }) {
  return <>{children}</>
}

export function CodeTabs({
  children,
  tabs,
}: {
  children?: ReactNode
  tabs?: CodeTabItem[]
}) {
  const { t } = useI18n()
  const baseId = useId()
  const panelRef = useRef<HTMLDivElement>(null)
  const [activeIdx, setActiveIdx] = useState(0)
  const { copied, copy, reset } = useCopyToClipboard()

  const childItems = Children.toArray(children).flatMap((child) => {
    if (isValidElement<{ label?: string; children?: ReactNode }>(child)) {
      const label = child.props?.label
      if (typeof label === 'string' && label.length > 0) {
        return [{ label, node: child.props.children, rawCode: '' }]
      }
    }
    return []
  })

  const items =
    childItems.length > 0
      ? childItems
      : (tabs ?? []).map((item) => ({
          label: item.label,
          rawCode: item.code,
          node: (
            <pre className="m-0 overflow-x-auto bg-transparent p-4 font-mono text-[12.5px] leading-[1.68] text-[var(--fg)]">
              <code>{item.code}</code>
            </pre>
          ),
        }))

  const safeIdx = activeIdx < items.length ? activeIdx : 0
  const current = items[safeIdx]
  if (!current) return null

  const copyTab = () => {
    const domText = panelRef.current?.querySelector('pre')?.textContent
    const text = domText?.trimEnd() || current.rawCode
    if (!text) return
    void copy(text)
  }

  return (
    <div className="not-prose my-4 overflow-hidden rounded-[9px] border border-[var(--border)] bg-[var(--code-bg)]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] bg-[var(--chrome)] px-3">
        <div className="flex items-stretch overflow-x-auto" role="tablist">
          {items.map((tab, idx) => {
            const active = idx === safeIdx
            const tabId = `${baseId}-tab-${idx}`
            return (
              <button
                key={tab.label}
                id={tabId}
                type="button"
                role="tab"
                aria-selected={active}
                aria-controls={`${baseId}-panel`}
                onClick={() => {
                  setActiveIdx(idx)
                  reset()
                }}
                className={`relative cursor-pointer whitespace-nowrap px-3 py-2 font-mono text-[11px] font-medium transition-colors ${
                  active ? 'text-[var(--fg)]' : 'text-[var(--muted)] hover:text-[var(--fg)]'
                }`}
              >
                {tab.label}
                {active && (
                  <span className="absolute inset-x-1 bottom-0 h-[1.5px] bg-[var(--brand)]" />
                )}
              </button>
            )
          })}
        </div>

        <button
          type="button"
          onClick={copyTab}
          className="inline-flex h-6 shrink-0 cursor-pointer items-center gap-1 rounded border border-[var(--border)] bg-[var(--surface)] px-2 font-mono text-[10.5px] text-[var(--muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
        >
          {copied ? <Check size={11} className="text-[var(--ok)]" /> : <Copy size={11} />}
          <span>{copied ? t.docs.copiedCode : t.docs.copyCode}</span>
        </button>
      </div>

      <div
        ref={panelRef}
        id={`${baseId}-panel`}
        role="tabpanel"
        aria-labelledby={`${baseId}-tab-${safeIdx}`}
        className="mdx-code-tabs-panel"
      >
        <InsideCodeTabsContext value={true}>{current.node}</InsideCodeTabsContext>
      </div>
    </div>
  )
}

function MdxPre(props: ComponentPropsWithoutRef<'pre'> & { 'data-language'?: string }) {
  const insideCodeTabs = useContext(InsideCodeTabsContext)
  const { t } = useI18n()
  const preRef = useRef<HTMLPreElement>(null)
  const { copied, copy } = useCopyToClipboard()

  if (insideCodeTabs) {
    return (
      <pre
        {...props}
        className={`${props.className ?? ''} m-0 overflow-x-auto bg-transparent p-4 font-mono text-[12.5px] leading-[1.68]`.trim()}
      />
    )
  }

  let lang = props['data-language'] ?? ''
  if (!lang && props.children && typeof props.children === 'object' && 'props' in props.children) {
    const childClass = String(
      (props.children as { props?: { className?: string } }).props?.className ?? '',
    )
    const match = childClass.match(/language-([\w-]+)/)
    if (match) lang = match[1]
  }
  if (!lang) lang = 'text'

  const copyCode = () => {
    const raw = preRef.current?.textContent ?? ''
    if (!raw) return
    void copy(raw.trimEnd())
  }

  return (
    <div className="mdx-code-shell not-prose">
      <div className="mdx-code-bar">
        <span className="mdx-code-lang">{lang}</span>
        <button
          type="button"
          onClick={copyCode}
          className="inline-flex h-6 cursor-pointer items-center gap-1 rounded border border-[var(--border)] bg-[var(--surface)] px-2 font-mono text-[10.5px] text-[var(--muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
        >
          {copied ? <Check size={11} className="text-[var(--ok)]" /> : <Copy size={11} />}
          <span>{copied ? t.docs.copiedCode : t.docs.copyCode}</span>
        </button>
      </div>
      <pre ref={preRef} {...props} />
    </div>
  )
}

function MdxTable(props: ComponentPropsWithoutRef<'table'>) {
  return (
    <div className="mdx-table-wrap">
      <table {...props} />
    </div>
  )
}

function MdxAnchor({ href = '', children, ...rest }: ComponentPropsWithoutRef<'a'>) {
  const { locale } = useI18n()
  if (href.startsWith('/') && !href.startsWith('//')) {
    const localizedTo = localizePath(href, locale)
    return (
      <Link
        to={localizedTo}
        onMouseEnter={() => void preloadRoute(localizedTo)}
        onFocus={() => void preloadRoute(localizedTo)}
        {...rest}
      >
        {children}
      </Link>
    )
  }
  if (href.startsWith('#')) {
    return (
      <a href={href} {...rest}>
        {children}
      </a>
    )
  }
  return (
    <a href={href} target="_blank" rel="noreferrer" {...rest}>
      {children}
    </a>
  )
}

function MdxH2({ id, children, ...rest }: ComponentPropsWithoutRef<'h2'>) {
  return (
    <h2 id={id} {...rest}>
      <span className="mdx-heading-anchor">
        <span>{children}</span>
        {id && (
          <a href={`#${id}`} className="mdx-anchor-hash" aria-label="Section link">
            #
          </a>
        )}
      </span>
    </h2>
  )
}

function MdxH3({ id, children, ...rest }: ComponentPropsWithoutRef<'h3'>) {
  return (
    <h3 id={id} {...rest}>
      <span className="mdx-heading-anchor">
        <span>{children}</span>
        {id && (
          <a href={`#${id}`} className="mdx-anchor-hash" aria-label="Section link">
            #
          </a>
        )}
      </span>
    </h3>
  )
}

export function useMdxComponents() {
  return useMemo(
    () => ({
      pre: MdxPre,
      table: MdxTable,
      a: MdxAnchor,
      h2: MdxH2,
      h3: MdxH3,
      Callout,
      CodeTab,
      CodeTabs,
      VpsMemoryLab: VpsMemoryLabSlot,
      ProviderComposer: ProviderComposerSlot,
      ProviderMatrix: ProviderMatrixSlot,
      Oae2Xray: Oae2XraySlot,
      RcloneTranslator: RcloneTranslatorSlot,
      ArchitectureGraph: ArchitectureGraphSlot,
    }),
    [],
  )
}
