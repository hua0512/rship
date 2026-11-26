import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..', '..')
const repoAssets = path.join(repoRoot, 'assets')
const repoScripts = path.join(repoRoot, 'scripts')
const sitePublic = path.resolve(here, '..', 'public')

fs.mkdirSync(sitePublic, { recursive: true })

if (fs.existsSync(repoAssets)) {
  const mapping = [
    ['logo.svg', 'logo.svg'],
    ['logo.ico', 'favicon.ico'],
    ['logo-120.png', 'logo-120.png'],
    ['logo-512.png', 'logo-512.png'],
    ['logo-wordmark-dark.svg', 'logo-wordmark-dark.svg'],
    ['logo-wordmark-light.svg', 'logo-wordmark-light.svg'],
  ]

  for (const [srcName, dstName] of mapping) {
    const src = path.join(repoAssets, srcName)
    const dst = path.join(sitePublic, dstName)
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dst)
    }
  }
}

const installShSrc = path.join(repoScripts, 'install.sh')
if (fs.existsSync(installShSrc)) {
  const normalizedLf = fs.readFileSync(installShSrc, 'utf8').replace(/\r\n/g, '\n')
  fs.writeFileSync(path.join(sitePublic, 'install.sh'), normalizedLf, 'utf8')
}

const installPs1Src = path.join(repoScripts, 'install.ps1')
if (fs.existsSync(installPs1Src)) {
  fs.copyFileSync(installPs1Src, path.join(sitePublic, 'install.ps1'))
}
