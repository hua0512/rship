import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import matter from 'gray-matter'
import GithubSlugger from 'github-slugger'

const here = path.dirname(fileURLToPath(import.meta.url))
const websiteRoot = path.resolve(here, '..')
const contentRoot = path.join(websiteRoot, 'content')
const generatedDir = path.join(websiteRoot, 'src', 'generated')
const publicDir = path.join(websiteRoot, 'public')
const rawOutRoot = path.join(publicDir, 'raw')
const cargoTomlPath = path.resolve(websiteRoot, '..', 'Cargo.toml')

function readCargoVersion() {
  try {
    const raw = fs.readFileSync(cargoTomlPath, 'utf8')
    const sectionMatch = raw.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/)
    const block = sectionMatch ? sectionMatch[1] : raw
    const verMatch = block.match(/^\s*version\s*=\s*"([^"]+)"/m)
    return verMatch ? verMatch[1] : '0.1.0'
  } catch {
    return '0.1.0'
  }
}

function walkMdx(dir, out = []) {
  if (!fs.existsSync(dir)) return out
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      walkMdx(full, out)
    } else if (entry.isFile() && entry.name.endsWith('.mdx')) {
      out.push(full)
    }
  }
  return out
}

function fileToSlug(localeDir, filePath) {
  const rel = path.relative(localeDir, filePath).replace(/\\/g, '/')
  const noExt = rel.replace(/\.mdx$/, '')
  if (noExt === 'index') return ''
  return noExt.replace(/\/index$/, '')
}

function stripInlineMarkdown(text) {
  return text
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    .replace(/<[^>]+>/g, '')
    .trim()
}

function extractHeadings(markdown) {
  const slugger = new GithubSlugger()
  const lines = markdown.split(/\r?\n/)
  const headings = []
  let inFence = false
  let fenceChar = ''

  for (const line of lines) {
    const fenceMatch = line.match(/^\s*(```+|~~~+)/)
    if (fenceMatch) {
      const marker = fenceMatch[1][0]
      if (!inFence) {
        inFence = true
        fenceChar = marker
      } else if (marker === fenceChar) {
        inFence = false
        fenceChar = ''
      }
      continue
    }
    if (inFence) continue

    const headingMatch = line.match(/^(#{1,4})\s+(.+?)\s*#*\s*$/)
    if (!headingMatch) continue

    const level = headingMatch[1].length
    const cleanText = stripInlineMarkdown(headingMatch[2])
    const id = slugger.slug(cleanText)
    if (level === 2 || level === 3) {
      headings.push({ id, text: cleanText, level })
    }
  }
  return headings
}

function toCleanMarkdown(body) {
  return body
    .replace(/^import\s+.*$/gm, '')
    .replace(/<Callout[^>]*title="([^"]*)"[^>]*>/g, '> **$1**\n>')
    .replace(/<Callout[^>]*>/g, '>')
    .replace(/<\/Callout>/g, '')
    .replace(/<CodeTabs[^>]*>/g, '')
    .replace(/<\/CodeTabs>/g, '')
    .replace(/<CodeTab[^>]*label="([^"]*)"[^>]*>/g, '#### $1\n')
    .replace(/<\/CodeTab>/g, '')
    .replace(/<CodeTabs[\s\S]*?\/>/g, '_[See interactive code tabs in documentation]_')
    .replace(/<span\b[^>]*\/>/g, '')
    .replace(/<[A-Z][A-Za-z0-9]*\s*\/>/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

function toSearchText(markdown) {
  return markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[#>*`|[\]()]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 2400)
}

const routeConfig = JSON.parse(fs.readFileSync(path.join(websiteRoot, 'routes.json'), 'utf8'))
const dirRoutes = new Set(routeConfig.dirSlugs)

function slugToRoutePath(slug) {
  if (!slug) return '/'
  if (dirRoutes.has(slug)) return `/${slug}/`
  return `/${slug}`
}

const appVersion = readCargoVersion()
const siteUrl = (process.env.DOCS_SITE_URL ?? 'https://hua0512.github.io/rship/').replace(/\/?$/, '/')

fs.mkdirSync(generatedDir, { recursive: true })
fs.mkdirSync(publicDir, { recursive: true })
fs.rmSync(rawOutRoot, { recursive: true, force: true })

const docsMeta = {}
const rawMarkdownByKey = {}
const searchDocs = []
const localeDefs = JSON.parse(fs.readFileSync(path.join(websiteRoot, 'locales.json'), 'utf8'))
const locales = localeDefs.map((l) => l.code)
const defaultLocale = localeDefs.find((l) => l.default)?.code ?? 'en'
const localeUnionType = locales.map((code) => JSON.stringify(code)).join(' | ')

for (const locale of locales) {
  const localeDir = path.join(contentRoot, locale)
  const files = walkMdx(localeDir).sort((a, b) => a.localeCompare(b))
  for (const file of files) {
    const raw = fs.readFileSync(file, 'utf8')
    const parsed = matter(raw)
    const slug = fileToSlug(localeDir, file)
    const relPath = path.relative(websiteRoot, file).replace(/\\/g, '/')
    const cleanMd = toCleanMarkdown(parsed.content)
    const headings = extractHeadings(parsed.content)
    const h1Match = parsed.content.match(/^#\s+(.+)$/m)
    const title = parsed.data.title || (h1Match ? stripInlineMarkdown(h1Match[1]) : slug)
    const description = parsed.data.description || ''
    const section = parsed.data.section || 'guide'
    const badge = parsed.data.badge || ''

    const rawMdPath = `${locale}/${slug || 'index'}.md`
    const fullCleanMd = `# ${title}\n\n${cleanMd}\n`
    const outRawPath = path.join(rawOutRoot, rawMdPath)
    fs.mkdirSync(path.dirname(outRawPath), { recursive: true })
    fs.writeFileSync(outRawPath, fullCleanMd, 'utf8')

    const key = `${locale}:${slug}`
    rawMarkdownByKey[key] = fullCleanMd
    docsMeta[key] = {
      locale,
      slug,
      routePath: slugToRoutePath(slug),
      sourcePath: relPath,
      rawMdPath,
      title,
      description,
      section,
      badge,
      headings,
    }

    searchDocs.push({
      locale,
      slug,
      routePath: slugToRoutePath(slug),
      title,
      description,
      section,
      headings: headings.map((h) => h.text),
      body: toSearchText(cleanMd),
    })
  }
}

const versionOutput = `/* Auto-generated by scripts/generate-meta.mjs. Do not edit manually. */

export const APP_VERSION = ${JSON.stringify(appVersion)}
`

const typesOutput = `/* Auto-generated by scripts/generate-meta.mjs. Do not edit manually. */

export interface DocHeading {
  id: string
  text: string
  level: 2 | 3
}

export interface DocMeta {
  locale: ${localeUnionType}
  slug: string
  routePath: string
  sourcePath: string
  rawMdPath: string
  title: string
  description: string
  section: string
  badge: string
  headings: DocHeading[]
  isFallback?: boolean
}

export interface SearchDocItem {
  locale: ${localeUnionType}
  slug: string
  routePath: string
  title: string
  description: string
  section: string
  headings: string[]
  body: string
}
`

fs.writeFileSync(path.join(generatedDir, 'version.ts'), versionOutput, 'utf8')
fs.writeFileSync(path.join(generatedDir, 'docs-meta.ts'), typesOutput, 'utf8')

const allSlugs = routeConfig.navSections.flatMap((section) => section.slugs)
for (const locale of locales) {
  const perLocale = {}
  for (const slug of allSlugs) {
    const localized = docsMeta[`${locale}:${slug}`]
    const fallback = docsMeta[`${defaultLocale}:${slug}`]
    const chosen = localized ?? fallback
    if (!chosen) continue
    perLocale[slug] = {
      ...chosen,
      isFallback: Boolean(locale !== defaultLocale && !localized),
    }
  }
  const localeOutput = `/* Auto-generated by scripts/generate-meta.mjs. Do not edit manually. */
import type { DocMeta } from './docs-meta'

export const DOCS_META: Record<string, DocMeta> = ${JSON.stringify(perLocale, null, 2)}
`
  fs.writeFileSync(path.join(generatedDir, `docs-meta-${locale}.ts`), localeOutput, 'utf8')
}
fs.writeFileSync(path.join(publicDir, 'search-index.json'), JSON.stringify(searchDocs), 'utf8')

// Generate llms.txt & llms-full.txt from default-locale docs
const enEntries = Object.entries(docsMeta)
  .filter(([, d]) => d.locale === defaultLocale)
  .map(([key, doc]) => ({ key, doc }))

const llmsLines = [
  '# rship',
  '',
  '> Cross-platform, low-memory (<= 64 MiB RSS), crash-resumable multi-cloud transfer and sync engine written in Rust.',
  '',
  `Version: v${appVersion}`,
  `Repository: https://github.com/hua0512/rship`,
  '',
  '## Documentation',
  '',
  ...enEntries.map(
    ({ doc }) =>
      `- [${doc.title}](${siteUrl}${doc.routePath.replace(/^\//, '')})${doc.description ? `: ${doc.description}` : ''}`,
  ),
  '',
  '## Full Context',
  '',
  `- [llms-full.txt](${siteUrl}llms-full.txt): Complete documentation bundle in Markdown.`,
  '',
]
fs.writeFileSync(path.join(publicDir, 'llms.txt'), llmsLines.join('\n'), 'utf8')

const llmsFull = enEntries
  .map(({ key, doc }) => `<!-- ${doc.routePath} -->\n\n${rawMarkdownByKey[key].trim()}`)
  .join('\n\n---\n\n')
fs.writeFileSync(path.join(publicDir, 'llms-full.txt'), llmsFull + '\n', 'utf8')

console.log(
  `[generate-meta] Generated metadata, raw markdown, and search index for ${Object.keys(docsMeta).length} doc(s), version v${appVersion}`,
)
