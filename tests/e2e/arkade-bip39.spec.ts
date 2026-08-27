import {build} from 'esbuild'
import {mkdtemp, readFile, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join, resolve} from 'node:path'

import {expect, test, type Page} from '@playwright/test'

const projectRoot = resolve(__dirname, '../..')
const browserSource = resolve(__dirname, 'arkade-bip39.browser.ts')
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

type ProofResult = {
  network: string
  repositoryName: string
  identityIsMnemonic: boolean
  identityDescriptor: string
  walletDescriptors: Record<string, string> | undefined
  currentSigningDescriptor: string | undefined
  nextSigningDescriptor: string | undefined
  lastIndexUsed: number | undefined
  publicData: {
    descriptor: string
    xOnlyPublicKey: string
    compressedPublicKey: string
  }
  persistedState: unknown
  readonlySerialized: string
  capabilities: {
    identityCanSign: boolean
    readonlyCanSign: boolean
    readonlyCanSignMessage: boolean
    readonlyHasSignerSession: boolean
  }
}

type ProofInput = {
  mnemonic: string
  installationId: string
  accountId: string
  networkName: 'regtest'
  schemaVersion: string
  walletIds: [string, string]
  step?: 'initial' | 'reload'
}

declare global {
  interface Window {
    arkadeRepositoryName: (input: {
      installationId: string
      accountId: string
      networkName: 'regtest'
      schemaVersion: string
      apiKey?: string
      credential?: string
    }) => string
    runArkadeBip39Proof: (input: ProofInput) => Promise<ProofResult>
  }
}

const loadProof = async (
  page: Page,
  bundlePath: string,
  input: ProofInput,
  reload = false
): Promise<ProofResult> => {
  if (reload) {
    await page.reload()
  } else {
    await page.goto('/')
  }
  await page.addScriptTag({path: bundlePath})
  return page.evaluate(input => window.runArkadeBip39Proof(input), input)
}

const assertProof = (result: ProofResult): void => {
  expect(result.network).toBe('regtest')
  expect(result.identityIsMnemonic).toBe(true)
  expect(result.identityDescriptor).toBe(result.publicData.descriptor)
  expect(result.identityDescriptor).toMatch(/^tr\(\[.+\]tpub.+\/0\/\*\)$/)
  expect(result.publicData.xOnlyPublicKey).toMatch(/^[0-9a-f]{64}$/)
  expect(result.publicData.compressedPublicKey).toMatch(/^0[23][0-9a-f]{64}$/)
  expect(result.capabilities.identityCanSign).toBe(true)
  expect(result.capabilities.readonlyCanSign).toBe(false)
  expect(result.capabilities.readonlyCanSignMessage).toBe(false)
  expect(result.capabilities.readonlyHasSignerSession).toBe(false)

  const publicJson = JSON.stringify(result.publicData)
  expect(publicJson).not.toContain(mnemonic)
  const persistedJson = JSON.stringify(result.persistedState)
  expect(persistedJson).not.toContain(mnemonic)
  expect(persistedJson).not.toContain('"walletDescriptors"')
  expect(persistedJson).not.toMatch(/(?:mnemonic|private.?key|secret|seed)/i)
  expect(result.readonlySerialized).not.toContain(mnemonic)
  expect(result.readonlySerialized).not.toMatch(
    /(?:mnemonic|private.?key|secret|seed)/i
  )
}

const assertAttribution = (result: ProofResult): void => {
  expect(result.walletDescriptors).toBeDefined()
  expect(Object.values(result.walletDescriptors!)).toHaveLength(2)
  expect(new Set(Object.values(result.walletDescriptors!)).size).toBe(2)
  expect(Object.values(result.walletDescriptors!)).toEqual(
    expect.arrayContaining([
      expect.stringMatching(/^tr\(\[.+\]tpub.+\/0\/0\)$/),
      expect.stringMatching(/^tr\(\[.+\]tpub.+\/0\/1\)$/)
    ])
  )
}

test('proves descriptor attribution only (no receive intent or funded Wallet)', async ({
  browser
}) => {
  const input: ProofInput = {
    mnemonic,
    installationId: 'installation-test',
    accountId: 'account-test',
    networkName: 'regtest',
    schemaVersion: '1',
    walletIds: ['wallet-a', 'wallet-b']
  }
  const outputDirectory = await mkdtemp(join(tmpdir(), 'lnbits-arkade-bip39-'))
  const bundlePath = join(outputDirectory, 'arkade-bip39.js')

  try {
    await build({
      absWorkingDir: projectRoot,
      bundle: true,
      entryPoints: [browserSource],
      format: 'iife',
      outfile: bundlePath,
      platform: 'browser',
      target: 'es2022'
    })
    const bundle = await readFile(bundlePath, 'utf8')
    expect(bundle).not.toContain(input.mnemonic)

    const firstContext = await browser.newContext()
    const firstPage = await firstContext.newPage()
    const firstResult = await loadProof(firstPage, bundlePath, input)
    const reloadResult = await loadProof(
      firstPage,
      bundlePath,
      {
        ...input,
        step: 'reload'
      },
      true
    )

    const resetContext = await browser.newContext()
    const resetResult = await loadProof(
      await resetContext.newPage(),
      bundlePath,
      input
    )
    await resetContext.close()

    assertProof(firstResult)
    assertAttribution(firstResult)
    assertProof(reloadResult)
    expect(reloadResult.walletDescriptors).toBeUndefined()
    assertProof(resetResult)
    assertAttribution(resetResult)
    expect(firstResult.repositoryName).toBe(reloadResult.repositoryName)
    expect(firstResult.repositoryName).toBe(resetResult.repositoryName)
    expect(resetResult.identityDescriptor).toBe(firstResult.identityDescriptor)
    expect(resetResult.publicData).toEqual(firstResult.publicData)
    expect(reloadResult.currentSigningDescriptor).toBe(
      firstResult.walletDescriptors!['wallet-b']
    )
    expect(reloadResult.nextSigningDescriptor).not.toBe(
      firstResult.walletDescriptors!['wallet-a']
    )
    expect(reloadResult.nextSigningDescriptor).not.toBe(
      firstResult.walletDescriptors!['wallet-b']
    )
    expect(reloadResult.lastIndexUsed).toBe(2)

    const sameRepositoryName = await firstPage.evaluate(() =>
      window.arkadeRepositoryName({
        installationId: 'installation-test',
        accountId: 'account-test',
        networkName: 'regtest',
        schemaVersion: '1',
        apiKey: 'different-api-key',
        credential: 'different-credential'
      })
    )
    expect(sameRepositoryName).toBe(firstResult.repositoryName)
    await firstContext.close()
  } finally {
    await rm(outputDirectory, {force: true, recursive: true})
  }
})
