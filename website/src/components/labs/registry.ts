import { lazy, type ComponentType, type LazyExoticComponent } from 'react'
import { SLUG_TO_LABS, type LabName } from '../../lib/routes'

export type { LabName } from '../../lib/routes'

type LabComponent = ComponentType<Record<string, never>>

const LAB_LOADERS: Record<LabName, () => Promise<LabComponent>> = {
  VpsMemoryLab: () => import('./VpsMemoryLab').then((m) => m.VpsMemoryLab),
  ProviderComposer: () => import('./ProviderComposer').then((m) => m.ProviderComposer),
  ProviderMatrix: () => import('./ProviderMatrix').then((m) => m.ProviderMatrix),
  Oae2Xray: () => import('./Oae2Xray').then((m) => m.Oae2Xray),
  RcloneTranslator: () => import('./RcloneTranslator').then((m) => m.RcloneTranslator),
  ArchitectureGraph: () => import('./ArchitectureGraph').then((m) => m.ArchitectureGraph),
}

const resolvedLabs = new Map<LabName, LabComponent>()
const pendingLabs = new Map<LabName, Promise<LabComponent>>()
const lazyLabs = new Map<LabName, LazyExoticComponent<LabComponent>>()

export function getCachedLab(name: LabName): LabComponent | null {
  return resolvedLabs.get(name) ?? null
}

export function loadLab(name: LabName): Promise<LabComponent> {
  const cached = resolvedLabs.get(name)
  if (cached) return Promise.resolve(cached)

  const pending = pendingLabs.get(name)
  if (pending) return pending

  const promise = LAB_LOADERS[name]()
    .then((comp) => {
      resolvedLabs.set(name, comp)
      pendingLabs.delete(name)
      return comp
    })
    .catch((err) => {
      pendingLabs.delete(name)
      throw err
    })

  pendingLabs.set(name, promise)
  return promise
}

export function getLazyLab(name: LabName): LazyExoticComponent<LabComponent> {
  let lazyComp = lazyLabs.get(name)
  if (!lazyComp) {
    lazyComp = lazy(() => loadLab(name).then((comp) => ({ default: comp })))
    lazyLabs.set(name, lazyComp)
  }
  return lazyComp
}

export async function preloadLabsForSlug(slug: string): Promise<void> {
  const labs = SLUG_TO_LABS[slug]
  if (!labs?.length) return
  await Promise.all(labs.map((name) => loadLab(name)))
}
