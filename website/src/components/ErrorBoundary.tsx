import { Component, type ErrorInfo, type ReactNode } from 'react'

interface ErrorBoundaryProps {
  children: ReactNode
  fallbackTitle?: string
  retryLabel?: string
}

interface ErrorBoundaryState {
  hasError: boolean
  message: string
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false, message: '' }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      message: error?.message || 'Unexpected rendering error.',
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (import.meta.env.DEV) {
      console.error('[ErrorBoundary]', error, info)
    }
  }

  private handleReset = () => {
    this.setState({ hasError: false, message: '' })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          role="alert"
          className="not-prose my-6 rounded-[9px] border border-[var(--border-strong)] bg-[var(--surface)] p-5"
        >
          <div className="mb-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[var(--err)]">
            {this.props.fallbackTitle ?? 'View failed to load'}
          </div>
          <p className="m-0 mb-3 text-[13px] leading-[1.55] text-[var(--muted)]">
            {this.state.message}
          </p>
          <button
            type="button"
            onClick={this.handleReset}
            className="inline-flex h-7 cursor-pointer items-center rounded-md border border-[var(--border)] bg-[var(--chrome)] px-2.5 font-mono text-[11px] font-medium text-[var(--fg)] hover:border-[var(--border-strong)]"
          >
            {this.props.retryLabel ?? 'Retry'}
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
