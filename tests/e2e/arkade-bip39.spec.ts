import {build} from 'esbuild'
import {createHash} from 'node:crypto'
import {mkdtemp, readFile, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join, resolve} from 'node:path'

import {expect, test, type Page} from '@playwright/test'
import {schnorr} from '@noble/curves/secp256k1.js'

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

type InvoiceMapping = Readonly<{
  action: 'lnbits-arkade-receive-v1'
  accountId: string
  walletId: string
  nativeRequestId: string
  idempotencyKey: string
  amountSat: number
  index: number
  address: string
  script: string
  childXonlyPubkey: string
  network: string
  serverUrl: string
  serverPubkey: string
  expiresAt: number
  signature: string
}>

type InvoiceProof = {
  repositoryName: string
  mappings: InvoiceMapping[]
  outstandingUnpaid: number
  indices: number[]
  uniqueAddresses: number
  uniqueScripts: number
  mappingsFrozen: boolean
  lastIndexUsed: number | undefined
  contractCount: number
  metadataHasSource: boolean
  metadataExactlySigningDescriptor: boolean
  duplicateRequestMapping: InvoiceMapping
  duplicateAckAccepted: boolean
  conflictRejected: boolean
  failOnceAfterLocalPersist: boolean
  retrySameMapping: boolean
  lateObservation: {
    nativeRequestId: string
    observedScript: string
    attributedScript: string
    outpoint: string
    afterLogicalExpiry: boolean
  }
  recovery?: {
    mappedRowsBeforeDeletion: number
    mappedRowsAfterDeletion: number
    usedSigningDescriptorCount: number
    recoveredContractCount: number
    recoveredDescriptorsExact: boolean
    recoveredScriptsExact: boolean
    recoveredAddressesExact: boolean
    recoveredMetadataExact: boolean
    watermarkUnchanged: boolean
    secondRecoveryIdempotent: boolean
    nextAllocationIndex: number
    nextAllocationFresh: boolean
  }
  transportPayloads: string[]
}

type CompleteLossRecoveryProof = {
  repositoryName: string
  priorLocalStorageEntries: number
  priorIndexedDbNames: string[]
  freshWalletRepository: boolean
  freshContractRepository: boolean
  mappingsUnchanged: boolean
  publicMappingCount: number
  enumeratedDescriptorCount: number
  firstRecoveryCreatedCount: number
  recoveredContractCount: number
  recoveredDescriptorsExact: boolean
  recoveredScriptsExact: boolean
  recoveredAddressesExact: boolean
  recoveredChildKeysExact: boolean
  recoveredMetadataExact: boolean
  highestMappedIndex: number
  watermarkBeforeRecoveryIndex: number
  watermarkAfterRecoveryIndex: number
  secondRecoveryCreatedCount: number
  secondRecoveryWatermarkUnchanged: boolean
  nextAllocationIndex: number
  nextAllocationFresh: boolean
  lateObservation: {
    nativeRequestId: string
    mappingIndex: number
    observedScript: string
    attributedScript: string
    outpoint: string
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
    runArkadeInvoiceAllocatorProof: (
      input: Omit<ProofInput, 'walletIds'> & {
        invoiceCount?: number
        walletId?: string
        amountSat?: number
        serverUrl?: string
      }
    ) => Promise<InvoiceProof>
    runArkadeCompleteBrowserLossRecoveryProof: (input: {
      mnemonic: string
      mappings: InvoiceMapping[]
    }) => Promise<CompleteLossRecoveryProof>
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

const stableInvoiceId = (index: number, salt: number): string =>
  (BigInt(index) + BigInt(salt)).toString(16).padStart(32, '0')

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], byte => parseInt(byte, 16))

const canonicalInvoiceStatement = (mapping: InvoiceMapping): string =>
  [
    `action=${mapping.action}`,
    `account_id=${mapping.accountId}`,
    `wallet_id=${mapping.walletId}`,
    `native_request_id=${mapping.nativeRequestId}`,
    `idempotency_key=${mapping.idempotencyKey}`,
    `amount_sat=${mapping.amountSat}`,
    `index=${mapping.index}`,
    `address=${mapping.address}`,
    `script=${mapping.script}`,
    `child_xonly_pubkey=${mapping.childXonlyPubkey}`,
    `network=${mapping.network}`,
    `server_url=${mapping.serverUrl}`,
    `server_pubkey=${mapping.serverPubkey}`,
    `expires_at=${mapping.expiresAt}`
  ].join('\n')

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

test('proves browser-owned allocation, contract-row recovery, and reload attribution', async ({
  browser
}) => {
  const input = {
    mnemonic,
    installationId: `invoice-installation-${Date.now()}`,
    accountId: 'account-test',
    networkName: 'regtest' as const,
    schemaVersion: '1',
    invoiceCount: 25
  }
  const outputDirectory = await mkdtemp(
    join(tmpdir(), 'lnbits-arkade-invoice-')
  )
  const bundlePath = join(outputDirectory, 'arkade-invoice.js')

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
    const browserSourceText = await readFile(browserSource, 'utf8')
    const allocatorSource = browserSourceText.slice(
      browserSourceText.indexOf('const runInvoiceAllocatorProof'),
      browserSourceText.indexOf('Object.assign(window')
    )
    expect(allocatorSource).not.toContain('getAddress(')
    const firstContext = await browser.newContext()
    const page = await firstContext.newPage()
    await page.goto('/')
    await page.addScriptTag({path: bundlePath})
    const first = await page.evaluate(
      value => window.runArkadeInvoiceAllocatorProof(value),
      input
    )

    expect(first.outstandingUnpaid).toBeGreaterThan(20)
    expect(first.indices).toEqual(
      [...Array(input.invoiceCount).keys()].map(index => index + 1)
    )
    expect(first.uniqueAddresses).toBe(input.invoiceCount)
    expect(first.uniqueScripts).toBe(input.invoiceCount)
    expect(first.lastIndexUsed).toBe(input.invoiceCount)
    expect(first.contractCount).toBe(input.invoiceCount)
    expect(first.metadataHasSource).toBe(false)
    expect(first.metadataExactlySigningDescriptor).toBe(true)
    expect(first.duplicateAckAccepted).toBe(true)
    expect(first.conflictRejected).toBe(true)
    expect(first.failOnceAfterLocalPersist).toBe(true)
    expect(first.retrySameMapping).toBe(true)
    expect(first.recovery).toEqual({
      mappedRowsBeforeDeletion: input.invoiceCount,
      mappedRowsAfterDeletion: 0,
      usedSigningDescriptorCount: input.invoiceCount + 1,
      recoveredContractCount: input.invoiceCount,
      recoveredDescriptorsExact: true,
      recoveredScriptsExact: true,
      recoveredAddressesExact: true,
      recoveredMetadataExact: true,
      watermarkUnchanged: true,
      secondRecoveryIdempotent: true,
      nextAllocationIndex: input.invoiceCount + 1,
      nextAllocationFresh: true
    })
    expect(first.lateObservation).toEqual({
      nativeRequestId: stableInvoiceId(0, 0),
      observedScript: first.mappings[0].script,
      attributedScript: first.mappings[0].script,
      outpoint: 'a'.repeat(64) + ':0',
      afterLogicalExpiry: true
    })
    expect(first.mappings).toHaveLength(input.invoiceCount)
    expect(
      first.mappings.every(
        mapping => mapping.action === 'lnbits-arkade-receive-v1'
      )
    ).toBe(true)
    expect(
      first.mappings.every(mapping =>
        /^[0-9a-f]{32}$/.test(mapping.nativeRequestId)
      )
    ).toBe(true)
    expect(
      first.mappings.every(mapping =>
        /^[0-9a-f]{32}$/.test(mapping.idempotencyKey)
      )
    ).toBe(true)
    expect(first.mappings.every(mapping => mapping.amountSat === 1000)).toBe(
      true
    )
    expect(
      first.mappings.every(
        mapping =>
          mapping.accountId === 'account-test' &&
          mapping.walletId === 'wallet-test' &&
          mapping.network === 'regtest' &&
          mapping.serverUrl === 'http://arkade.test' &&
          /^[0-9a-f]{64}$/.test(mapping.serverPubkey) &&
          Number.isSafeInteger(mapping.expiresAt)
      )
    ).toBe(true)
    expect(
      first.mappings.every(mapping =>
        /^[0-9a-f]{64}$/.test(mapping.childXonlyPubkey)
      )
    ).toBe(true)
    expect(first.mappingsFrozen).toBe(true)
    expect(
      first.mappings.every(mapping => /^[0-9a-f]{128}$/.test(mapping.signature))
    ).toBe(true)
    expect(
      first.mappings.every(mapping =>
        schnorr.verify(
          fromHex(mapping.signature),
          createHash('sha256')
            .update(Buffer.from(canonicalInvoiceStatement(mapping), 'ascii'))
            .digest(),
          fromHex(mapping.childXonlyPubkey)
        )
      )
    ).toBe(true)
    const publicJson = JSON.stringify(first.mappings)
    expect(publicJson).not.toMatch(
      /mnemonic|seed|private.?key|xpub|descriptor|source/i
    )
    expect(first.transportPayloads.join('\n')).not.toMatch(
      /mnemonic|seed|private.?key|xpub|descriptor|source/i
    )

    await page.reload()
    await page.addScriptTag({path: bundlePath})
    const reload = await page.evaluate(
      value =>
        window.runArkadeInvoiceAllocatorProof({...value, step: 'reload'}),
      input
    )
    expect(reload.repositoryName).toBe(first.repositoryName)
    expect(reload.mappings).toEqual(first.mappings)
    expect(reload.indices).toEqual(first.indices)
    expect(reload.uniqueScripts).toBe(input.invoiceCount)
    expect(reload.contractCount).toBe(input.invoiceCount)
    expect(reload.lastIndexUsed).toBe(input.invoiceCount + 1)
    await firstContext.close()
  } finally {
    await rm(outputDirectory, {force: true, recursive: true})
  }
})

test('proves complete browser loss recovery from mnemonic and public mappings', async ({
  browser
}) => {
  const allocatorInput = {
    mnemonic,
    installationId: `complete-loss-installation-${Date.now()}`,
    accountId: 'account-test',
    networkName: 'regtest' as const,
    schemaVersion: '1',
    invoiceCount: 25
  }
  const outputDirectory = await mkdtemp(
    join(tmpdir(), 'lnbits-arkade-complete-loss-')
  )
  const bundlePath = join(outputDirectory, 'arkade-complete-loss.js')

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

    const sourceContext = await browser.newContext()
    const sourcePage = await sourceContext.newPage()
    await sourcePage.goto('/')
    await sourcePage.addScriptTag({path: bundlePath})
    const allocated = await sourcePage.evaluate(
      value => window.runArkadeInvoiceAllocatorProof(value),
      allocatorInput
    )
    const mappingSnapshot = JSON.stringify(allocated.mappings)
    const publicJson = JSON.stringify(allocated.mappings)
    expect(publicJson).not.toMatch(
      /mnemonic|seed|private.?key|xpub|descriptor|source/i
    )
    await sourceContext.close()

    const recoveryContext = await browser.newContext()
    const recoveryPage = await recoveryContext.newPage()
    await recoveryPage.goto('/')
    await recoveryPage.addScriptTag({path: bundlePath})
    const recovered = await recoveryPage.evaluate(
      value => window.runArkadeCompleteBrowserLossRecoveryProof(value),
      {mnemonic, mappings: allocated.mappings}
    )

    expect(recovered.repositoryName).not.toBe(allocated.repositoryName)
    expect(recovered.priorLocalStorageEntries).toBe(0)
    expect(recovered.priorIndexedDbNames).toEqual([])
    expect(recovered.freshWalletRepository).toBe(true)
    expect(recovered.freshContractRepository).toBe(true)
    expect(recovered.mappingsUnchanged).toBe(true)
    expect(JSON.stringify(allocated.mappings)).toBe(mappingSnapshot)
    expect(recovered.publicMappingCount).toBe(allocatorInput.invoiceCount)
    expect(recovered.enumeratedDescriptorCount).toBeGreaterThanOrEqual(
      allocatorInput.invoiceCount
    )
    expect(recovered.firstRecoveryCreatedCount).toBe(
      allocatorInput.invoiceCount
    )
    expect(recovered.recoveredContractCount).toBe(allocatorInput.invoiceCount)
    expect(recovered.recoveredDescriptorsExact).toBe(true)
    expect(recovered.recoveredScriptsExact).toBe(true)
    expect(recovered.recoveredAddressesExact).toBe(true)
    expect(recovered.recoveredChildKeysExact).toBe(true)
    expect(recovered.recoveredMetadataExact).toBe(true)
    expect(recovered.highestMappedIndex).toBe(allocatorInput.invoiceCount)
    expect(recovered.watermarkBeforeRecoveryIndex).toBe(0)
    expect(recovered.watermarkAfterRecoveryIndex).toBe(
      recovered.highestMappedIndex
    )
    expect(recovered.secondRecoveryCreatedCount).toBe(0)
    expect(recovered.secondRecoveryWatermarkUnchanged).toBe(true)
    expect(recovered.nextAllocationIndex).toBe(recovered.highestMappedIndex + 1)
    expect(recovered.nextAllocationFresh).toBe(true)
    expect(recovered.lateObservation).toEqual({
      nativeRequestId: allocated.mappings.at(-1)!.nativeRequestId,
      mappingIndex: allocated.mappings.at(-1)!.index,
      observedScript: allocated.mappings.at(-1)!.script,
      attributedScript: allocated.mappings.at(-1)!.script,
      outpoint: 'b'.repeat(64) + ':1'
    })
    await recoveryContext.close()
  } finally {
    await rm(outputDirectory, {force: true, recursive: true})
  }
})
