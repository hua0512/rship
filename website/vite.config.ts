import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import mdx from '@mdx-js/rollup'
import remarkGfm from 'remark-gfm'
import remarkFrontmatter from 'remark-frontmatter'
import remarkMdxFrontmatter from 'remark-mdx-frontmatter'
import rehypeSlug from 'rehype-slug'
import rehypeShiki from '@shikijs/rehype'

const rawBase = process.env.DOCS_BASE ?? '/'
const base = `/${rawBase.replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/')

export default defineConfig(({ isSsrBuild }) => ({
  base,
  plugins: [
    {
      enforce: 'pre',
      ...mdx({
        providerImportSource: '@mdx-js/react',
        remarkPlugins: [
          remarkGfm,
          remarkFrontmatter,
          [remarkMdxFrontmatter, { name: 'frontmatter' }],
        ],
        rehypePlugins: [
          rehypeSlug,
          [
            rehypeShiki,
            {
              themes: {
                light: 'github-light',
                dark: 'github-dark-dimmed',
              },
              defaultColor: false,
              transformers: [
                {
                  name: 'rship-add-language-attr',
                  pre(this: { options?: { lang?: string } }, node: { properties?: Record<string, unknown> }) {
                    const lang = this.options?.lang
                    if (lang && node.properties) {
                      node.properties['data-language'] = lang === 'plaintext' ? 'text' : lang
                    }
                  },
                },
              ],
            },
          ],
        ],
      }),
    },
    react(),
    tailwindcss(),
  ],
  build: isSsrBuild
    ? undefined
    : {
        manifest: true,
        rolldownOptions: {
          output: {
            codeSplitting: {
              groups: [
                {
                  name: 'react-vendor',
                  test: /node_modules[\\/](?:react|react-dom|scheduler)[\\/]/,
                  priority: 30,
                },
                {
                  name: 'router-vendor',
                  test: /node_modules[\\/](?:react-router|@remix-run|cookie-es)[\\/]/,
                  priority: 25,
                },
              ],
            },
          },
        },
      },
  ssr: {
    noExternal: ['lucide-react'],
  },
}))
