/// <reference types="vite/client" />

declare module '*.mdx' {
  import type { ComponentType } from 'react'

  export interface MdxFrontmatter {
    title?: string
    description?: string
    section?: string
    badge?: string
  }

  export const frontmatter: MdxFrontmatter
  const MDXContent: ComponentType<{
    components?: Record<string, ComponentType<any>>
  }>
  export default MDXContent
}
