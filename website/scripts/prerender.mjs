import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const websiteRoot = path.resolve(here, '..')
const distDir = path.join(websiteRoot, 'dist')
const distSsrDir = path.join(websiteRoot, 'dist-ssr')

const rawBase = process.env.DOCS_BASE ?? '/'
const base = `/${rawBase.replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/')
const siteUrl = (process.env.DOCS_SITE_URL ?? 'https://hua0512.github.io/rship/').replace(/\/?$/, '/')

const routeConfig = JSON.parse(fs.readFileSync(path.join(websiteRoot, 'routes.json'), 'utf8'))
const dirSlugs = new Set(routeConfig.dirSlugs)
const allDocSlugs = routeConfig.navSections.flatMap((section) => section.slugs)
const allDocSlugSet = new Set(allDocSlugs)
const slugLabs = routeConfig.slugLabs ?? {}

function slugToRoutePath(slug) {
  if (!slug) return '/'
  return dirSlugs.has(slug) ? `/${slug}/` : `/${slug}`
}

const CANONICAL_ROUTES = ['/', ...allDocSlugs.map(slugToRoutePath)]

const LEGACY_REDIRECTS = Object.entries(routeConfig.legacyRedirects ?? {}).map(([slug, to]) => ({
  from: `/${slug}`,
  to,
}))

const localeDefs = JSON.parse(fs.readFileSync(path.join(websiteRoot, 'locales.json'), 'utf8'))
const defaultLocale = localeDefs.find((l) => l.default)?.code ?? 'en'
const nonDefaultLocales = localeDefs.filter((l) => l.code !== defaultLocale).map((l) => l.code)

function getHreflang(def) {
  return def.langAttr ?? (def.code === 'zh' ? 'zh-CN' : def.code)
}

function buildLocalizedRoute(code, canonicalRoute) {
  if (code === defaultLocale) return canonicalRoute
  return canonicalRoute === '/' ? `/${code}/` : `/${code}${canonicalRoute}`
}

function hasLocalizedContent(code, canonicalRoute) {
  if (code === defaultLocale || canonicalRoute === '/') return true
  const slug = canonicalRoute.replace(/^\/+|\/+$/g, '').replace(/\/index$/, '')
  if (!slug) return true
  return (
    fs.existsSync(path.join(websiteRoot, 'content', code, `${slug}.mdx`)) ||
    fs.existsSync(path.join(websiteRoot, 'content', code, slug, 'index.mdx'))
  )
}

const ROUTE_ENTRIES = [
  ...CANONICAL_ROUTES.map((canonicalRoute) => ({
    locale: defaultLocale,
    canonicalRoute,
    route: canonicalRoute,
  })),
  ...nonDefaultLocales.flatMap((code) =>
    CANONICAL_ROUTES.map((canonicalRoute) => ({
      locale: code,
      canonicalRoute,
      route: buildLocalizedRoute(code, canonicalRoute),
    })),
  ),
]

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function extractTemplateAssetHrefs(html) {
  const hrefs = new Set()
  const pattern = /<(?:link|script)\b[^>]*\b(?:href|src)="([^"]+)"/g
  let match
  while ((match = pattern.exec(html)) !== null) {
    hrefs.add(match[1])
  }
  return hrefs
}

function findPrimaryFontFile(manifest) {
  if (manifest) {
    for (const entry of Object.values(manifest)) {
      if (entry.file && /inter-latin-wght-normal.*\.woff2$/.test(entry.file)) {
        return entry.file
      }
      if (Array.isArray(entry.assets)) {
        for (const asset of entry.assets) {
          if (/inter-latin-wght-normal.*\.woff2$/.test(asset)) {
            return asset
          }
        }
      }
    }
  }
  const assetsDir = path.join(distDir, 'assets')
  if (fs.existsSync(assetsDir)) {
    const match = fs
      .readdirSync(assetsDir)
      .find((name) => /^inter-latin-wght-normal.*\.woff2$/.test(name))
    if (match) return `assets/${match}`
  }
  return null
}

function collectPreloadTags(route, manifest, templateHrefs, primaryFontFile) {
  const tags = []
  if (primaryFontFile) {
    const fontHref = `${base}${primaryFontFile}`
    if (!templateHrefs.has(fontHref)) {
      tags.push(
        `<link rel="preload" as="font" type="font/woff2" href="${escapeHtml(fontHref)}" crossorigin />`,
      )
    }
  }

  if (!manifest) return tags

  let locale = defaultLocale
  let stripped = route || '/'
  for (const code of nonDefaultLocales) {
    if (route === `/${code}` || route === `/${code}/`) {
      locale = code
      stripped = '/'
      break
    }
    if (route.startsWith(`/${code}/`)) {
      locale = code
      stripped = route.slice(code.length + 1) || '/'
      break
    }
  }
  const slug = stripped.replace(/^\/+|\/+$/g, '').replace(/\/index$/, '')

  const entryKeys = [`src/i18n/${locale}.ts`]

  if (!slug) {
    entryKeys.push('src/pages/HomePage.tsx')
  } else if (allDocSlugSet.has(slug)) {
    entryKeys.push(
      'src/lib/docs-loader.ts',
      `src/generated/docs-meta-${locale}.ts`,
      'src/layouts/DocsLayout.tsx',
    )

    const mdxCandidates = [
      `content/${locale}/${slug}.mdx`,
      `content/${locale}/${slug}/index.mdx`,
      `content/${defaultLocale}/${slug}.mdx`,
      `content/${defaultLocale}/${slug}/index.mdx`,
    ]
    for (const key of mdxCandidates) {
      if (manifest[key]) {
        entryKeys.push(key)
        break
      }
    }

    const labs = slugLabs[slug] ?? []
    for (const lab of labs) {
      entryKeys.push(`src/components/labs/${lab}.tsx`)
    }
  }

  const visited = new Set()
  const files = []
  const cssFiles = []

  function walk(key) {
    if (visited.has(key)) return
    visited.add(key)
    const entry = manifest[key]
    if (!entry) return
    if (entry.file && entry.file.endsWith('.js') && !files.includes(entry.file)) {
      files.push(entry.file)
    }
    if (Array.isArray(entry.css)) {
      for (const c of entry.css) {
        if (!cssFiles.includes(c)) cssFiles.push(c)
      }
    }
    if (Array.isArray(entry.imports)) {
      for (const imp of entry.imports) {
        walk(imp)
      }
    }
  }

  for (const key of entryKeys) {
    if (manifest[key]) walk(key)
  }

  for (const c of cssFiles) {
    const href = `${base}${c}`
    if (!templateHrefs.has(href)) {
      tags.push(`<link rel="stylesheet" crossorigin href="${escapeHtml(href)}" />`)
    }
  }

  for (const f of files) {
    const href = `${base}${f}`
    if (!templateHrefs.has(href)) {
      tags.push(`<link rel="modulepreload" crossorigin href="${escapeHtml(href)}" />`)
    }
  }

  return tags
}

function applyTemplate(template, { lang, title, description, headMeta, html, isNotFound = false }) {
  let out = template
    .replace(/<html lang="[^"]*"/, () => `<html lang="${escapeHtml(lang)}"`)
    .replace(/<title>[\s\S]*?<\/title>/, () => `<title>${escapeHtml(title)}</title>`)
    .replace(
      /<meta\s+name="description"\s+content="[^"]*"\s*\/>/,
      () => `<meta name="description" content="${escapeHtml(description)}" />`,
    )
    .replace('<!--app-head-->', () => headMeta)

  if (isNotFound) {
    out = out.replace(
      '<div id="root"><!--app-html--></div>',
      () => `<div id="root" data-ssr-404="1">${html}</div>`,
    )
  } else {
    out = out.replace('<!--app-html-->', () => html)
  }

  return out
}

const template = fs.readFileSync(path.join(distDir, 'index.html'), 'utf8')
const templateHrefs = extractTemplateAssetHrefs(template)
const manifestPath = path.join(distDir, '.vite', 'manifest.json')
const manifest = fs.existsSync(manifestPath)
  ? JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
  : null
const primaryFontFile = findPrimaryFontFile(manifest)
const serverEntryUrl = pathToFileURL(path.join(distSsrDir, 'entry-server.js')).href
const { render } = await import(serverEntryUrl)

const sitemapUrls = []

for (const { locale: routeLocale, canonicalRoute, route } of ROUTE_ENTRIES) {
  const { html, title, description, lang } = await render(route, base)

  const pageUrl = `${siteUrl}${route.replace(/^\//, '')}`
  const defaultRoute = buildLocalizedRoute(defaultLocale, canonicalRoute)
  const defaultPageUrl = `${siteUrl}${defaultRoute.replace(/^\//, '')}`
  const isLocalized = hasLocalizedContent(routeLocale, canonicalRoute)
  const canonicalHref = isLocalized ? pageUrl : defaultPageUrl

  if (isLocalized) {
    sitemapUrls.push(`  <url>\n    <loc>${escapeHtml(pageUrl)}</loc>\n  </url>`)
  }

  const alternateLinks = localeDefs
    .filter((def) => hasLocalizedContent(def.code, canonicalRoute))
    .map((def) => {
      const altRoute = buildLocalizedRoute(def.code, canonicalRoute)
      const altUrl = `${siteUrl}${altRoute.replace(/^\//, '')}`
      return `<link rel="alternate" hreflang="${escapeHtml(getHreflang(def))}" href="${escapeHtml(altUrl)}" />`
    })
  alternateLinks.push(
    `<link rel="alternate" hreflang="x-default" href="${escapeHtml(defaultPageUrl)}" />`,
  )

  const preloadTags = collectPreloadTags(route, manifest, templateHrefs, primaryFontFile)
  const headMeta = [
    `<link rel="canonical" href="${escapeHtml(canonicalHref)}" />`,
    ...alternateLinks,
    ...preloadTags,
    `<meta name="twitter:card" content="summary" />`,
    `<meta property="og:type" content="website" />`,
    `<meta property="og:title" content="${escapeHtml(title)}" />`,
    `<meta property="og:description" content="${escapeHtml(description)}" />`,
    `<meta property="og:image" content="${siteUrl}logo-512.png" />`,
    `<meta property="og:url" content="${escapeHtml(canonicalHref)}" />`,
  ].join('\n    ')

  const docHtml = applyTemplate(template, { lang, title, description, headMeta, html })

  const trimmed = route.replace(/^\/+|\/+$/g, '')
  const indexOutPath = trimmed
    ? path.join(distDir, trimmed, 'index.html')
    : path.join(distDir, 'index.html')

  fs.mkdirSync(path.dirname(indexOutPath), { recursive: true })
  fs.writeFileSync(indexOutPath, docHtml, 'utf8')

  // Also write flat <route>.html for non-trailing-slash URLs on GitHub Pages (e.g. /privacy)
  if (trimmed && !route.endsWith('/')) {
    const flatOutPath = path.join(distDir, `${trimmed}.html`)
    fs.mkdirSync(path.dirname(flatOutPath), { recursive: true })
    fs.writeFileSync(flatOutPath, docHtml, 'utf8')
  }
}

// Pre-render dedicated 404.html for GitHub Pages (avoids HomePage hydration mismatch & canonical pollution)
const notFound = await render('/404', base)
const notFoundPreloads = collectPreloadTags('/404', manifest, templateHrefs, primaryFontFile)
const notFoundHeadMeta = [
  `<meta name="robots" content="noindex" />`,
  ...notFoundPreloads,
].join('\n    ')
const notFoundHtml = applyTemplate(template, {
  lang: notFound.lang,
  title: notFound.title,
  description: notFound.description,
  headMeta: notFoundHeadMeta,
  html: notFound.html,
  isNotFound: true,
})
fs.writeFileSync(path.join(distDir, '404.html'), notFoundHtml, 'utf8')

// Emit static HTML redirects for consolidated legacy routes
const redirectLocales = [defaultLocale, ...nonDefaultLocales]
let redirectCount = 0
for (const entry of LEGACY_REDIRECTS) {
  for (const code of redirectLocales) {
    const fromRoute = code === defaultLocale ? entry.from : `/${code}${entry.from}`
    const toPath = code === defaultLocale ? entry.to : `/${code}${entry.to}`
    const targetHref = `${base}${toPath.replace(/^\//, '')}`
    const canonicalHref = `${siteUrl}${toPath.replace(/^\//, '')}`
    const redirectHtml = `<!doctype html>
<html lang="${escapeHtml(code)}">
  <head>
    <meta charset="UTF-8" />
    <title>Redirecting…</title>
    <meta http-equiv="refresh" content="0; url=${escapeHtml(targetHref)}" />
    <link rel="canonical" href="${escapeHtml(canonicalHref)}" />
    <script>location.replace(${JSON.stringify(targetHref)})</script>
  </head>
  <body>
    <p>Redirecting to <a href="${escapeHtml(targetHref)}">${escapeHtml(targetHref)}</a>…</p>
  </body>
</html>
`
    const trimmed = fromRoute.replace(/^\/+|\/+$/g, '')
    const indexOutPath = path.join(distDir, trimmed, 'index.html')
    const flatOutPath = path.join(distDir, `${trimmed}.html`)
    fs.mkdirSync(path.dirname(indexOutPath), { recursive: true })
    fs.writeFileSync(indexOutPath, redirectHtml, 'utf8')
    fs.writeFileSync(flatOutPath, redirectHtml, 'utf8')
    redirectCount++
  }
}

// Emit sitemap.xml and robots.txt for canonical & natively localized routes (excluding fallbacks & redirects)
const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemapUrls.join('\n')}
</urlset>
`
fs.writeFileSync(path.join(distDir, 'sitemap.xml'), sitemapXml, 'utf8')

const robotsTxt = `User-agent: *
Allow: /

Sitemap: ${siteUrl}sitemap.xml
`
fs.writeFileSync(path.join(distDir, 'robots.txt'), robotsTxt, 'utf8')

// Remove temporary SSR bundle and build manifest
fs.rmSync(distSsrDir, { recursive: true, force: true })
fs.rmSync(path.join(distDir, '.vite'), { recursive: true, force: true })

console.log(
  `[prerender] Pre-rendered ${ROUTE_ENTRIES.length} routes + 404.html (${sitemapUrls.length} indexed in sitemap.xml), ${redirectCount} legacy redirect(s), and robots.txt into dist/`,
)
