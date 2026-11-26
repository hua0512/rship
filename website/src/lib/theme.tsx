import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type ThemeMode = 'light' | 'dark'

interface ThemeContextValue {
  theme: ThemeMode
  setTheme: (mode: ThemeMode) => void
  toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'light',
  setTheme: () => {},
  toggleTheme: () => {},
})

function hasSavedThemeOverride(): boolean {
  if (typeof window === 'undefined') return false
  try {
    const saved = window.localStorage.getItem('rship-theme')
    return saved === 'dark' || saved === 'light'
  } catch {
    return false
  }
}

function readInitialTheme(): ThemeMode {
  if (typeof document !== 'undefined') {
    const attr = document.documentElement.dataset.theme
    if (attr === 'dark' || attr === 'light') return attr
  }
  if (typeof window !== 'undefined') {
    try {
      const saved = window.localStorage.getItem('rship-theme')
      if (saved === 'dark' || saved === 'light') return saved
      if (window.matchMedia?.('(prefers-color-scheme: dark)').matches) return 'dark'
    } catch {
      // ignore storage restrictions
    }
  }
  return 'light'
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeMode>(readInitialTheme)

  const setTheme = useCallback((mode: ThemeMode) => {
    setThemeState(mode)
    if (typeof document !== 'undefined') {
      document.documentElement.dataset.theme = mode
    }
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem('rship-theme', mode)
      } catch {
        // ignore storage errors
      }
    }
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }, [setTheme, theme])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => {
      if (!hasSavedThemeOverride()) {
        setThemeState(e.matches ? 'dark' : 'light')
      }
    }
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, setTheme, toggleTheme }),
    [theme, setTheme, toggleTheme],
  )

  return <ThemeContext value={value}>{children}</ThemeContext>
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext)
}
