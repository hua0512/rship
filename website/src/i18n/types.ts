export type Locale = 'en' | 'zh'

export type SectionId =
  | 'getting-started'
  | 'core'
  | 'providers'
  | 'sdk'
  | 'performance'

export interface Dictionary {
  locale: Locale
  langAttr: string
  nav: {
    guide: string
    providers: string
    sdk: string
    benchmarks: string
    search: string
    light: string
    dark: string
    toggleTheme: string
    menu: string
    close: string
    skipToContent: string
  }
  home: {
    overline: string
    titlePrimary: string
    titleMuted: string
    lead: string
    ctaGetStarted: string
    ctaCopied: string
    ctaCopy: string
    installLabelUnix: string
    installLabelWindows: string
    migrateHintPrefix: string
    migrateHintLink: string
    terminal: {
      title: string
      btnKill: string
      btnResume: string
      btnReplay: string
      killedEventPrefix: string
      killedEventSuffix: string
      resumedEvent: string
      doneEvent: string
      statsSummary: string
    }
    capabilities: Array<{
      index: string
      title: string
      desc: string
      to: string
    }>
    backendsLabel: string
    backendsList: string
    licenseNote: string
    linkPrivacy: string
    linkReleases: string
    linkIssues: string
    linkBenchmarks: string
    linkSdk: string
  }
  docs: {
    sections: Record<SectionId, string>
    pageTitles: Record<string, string>
    sidebarTitles?: Record<string, string>
    onThisPage: string
    copyMarkdown: string
    copiedMarkdown: string
    editOnGitHub: string
    previous: string
    next: string
    llmsContext: string
    fallbackNotice: string
    copyCode: string
    copiedCode: string
    notFoundTitle: string
    notFoundBody: string
    backHome: string
    goQuickStart: string
  }
  cmdk: {
    placeholder: string
    empty: string
    groupPages: string
    groupFlags: string
    groupProviders: string
    hintSelect: string
    hintClose: string
  }
}
