import { StrictMode } from 'react'
import { renderToString } from 'react-dom/server'
import { StaticRouter } from 'react-router'
import { App, resolvePageMeta } from './App'
import { preloadRoute } from './lib/preload'
import './styles/global.css'

export async function render(url: string, basename: string) {
  await preloadRoute(url)

  const routerBase = basename.endsWith('/') ? basename : `${basename}/`
  const basePrefix = routerBase === '/' ? '' : routerBase.slice(0, -1)
  const normalizedUrl = url.startsWith('/') ? url : `/${url}`
  const fullLocation = `${basePrefix}${normalizedUrl}`

  const html = renderToString(
    <StrictMode>
      <StaticRouter location={fullLocation} basename={routerBase}>
        <App />
      </StaticRouter>
    </StrictMode>,
  )

  const meta = resolvePageMeta(normalizedUrl)

  return {
    html,
    ...meta,
  }
}
