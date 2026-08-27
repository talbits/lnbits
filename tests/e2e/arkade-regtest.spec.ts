import {execFile} from 'node:child_process'
import {mkdtemp, readFile, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join, resolve} from 'node:path'
import {promisify} from 'node:util'

import {expect, test, type BrowserContext, type Page} from '@playwright/test'
import {build} from 'esbuild'

const execFileAsync = promisify(execFile)
const projectRoot = resolve(__dirname, '../..')
const browserSource = resolve(__dirname, 'arkade-bip39.browser.ts')
const regtestRoot = resolve(
  process.env.ARKADE_REGTEST_DIR || join(projectRoot, '../arkade-regtest')
)
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const amounts = {walletA: 80_000, walletB: 120_000}
const adminUrl = 'http://localhost:7071'
const arkServerUrl = 'http://localhost:7070'
const zeroIntentFees = {
  offchainInputFee: '0.0',
  onchainInputFee: '0.0',
  offchainOutputFee: '0.0',
  onchainOutputFee: '0.0'
}

type IntentFees = Record<string, string>

const readIntentFees = async (): Promise<IntentFees> => {
  const response = await fetch(`${adminUrl}/v1/admin/intentFees`)
  if (!response.ok) {
    throw new Error('failed to read regtest intent fees')
  }
  const body = (await response.json()) as {fees?: unknown}
  const fees = body.fees
  if (
    !fees ||
    typeof fees !== 'object' ||
    Array.isArray(fees) ||
    Object.keys(fees).length === 0 ||
    Object.values(fees).some(value => typeof value !== 'string')
  ) {
    throw new Error('regtest intent fee response has an unusable shape')
  }
  return {...fees} as IntentFees
}

type Balance = {
  boarding: {confirmed: number; unconfirmed: number; total: number}
  settled: number
  preconfirmed: number
  available: number
  total: number
}

type ProofResult = {
  repositoryName: string
  identityDescriptor: string
  address: string
  boardingAddress: string
  balance: Balance
  recipientScript: string
  receives: Array<{
    walletId: 'wallet-a' | 'wallet-b'
    address: string
    script: string
    signingDescriptor: string
  }>
  vtxos: Array<{
    txid: string
    vout: number
    value: number
    script: string
    isPreconfirmed?: boolean
    isSpent?: boolean
    isSwept?: boolean
    settledBy?: string
    spentBy?: string
  }>
  persistedState: unknown
  contracts: unknown[]
}

type ProofInput = {
  mnemonic: string
  installationId: string
  accountId: string
  networkName: 'regtest'
  schemaVersion: string
  arkServerUrl: string
  esploraUrl: string
  restore?: boolean
  mode?: 'start' | 'final' | 'dispose' | 'restore'
  receives?: ProofResult['receives']
}

declare global {
  interface Window {
    runArkadeRegtestProof: (input: ProofInput) => Promise<ProofResult>
  }
}

const loadProof = async (
  page: Page,
  bundlePath: string,
  input: ProofInput,
  reload = false,
  reuse = false
): Promise<ProofResult> => {
  if (reload) {
    await page.reload()
  } else if (!reuse) {
    await page.goto('/')
  }
  if (!reuse) {
    await page.addScriptTag({path: bundlePath})
  }
  return page.evaluate(input => window.runArkadeRegtestProof(input), input)
}

type IndexedVtxo = ProofResult['vtxos'][number] & {
  commitmentTxids?: string[]
}

type IndexedVtxoResponse = {
  outpoint: {txid: string; vout: number}
  amount: string
  script: string
  commitmentTxids?: string[]
  isPreconfirmed?: boolean
  isSpent?: boolean
  isSwept?: boolean
  settledBy?: string
  spentBy?: string
}

type AttributionLedger = {
  owners: Map<string, 'wallet-a' | 'wallet-b'>
  receipts: Map<string, {walletId: 'wallet-a' | 'wallet-b'; value: number}>
  credits: Map<'wallet-a' | 'wallet-b', number>
}

const applyReceipt = (
  ledger: AttributionLedger,
  walletId: 'wallet-a' | 'wallet-b',
  vtxo: IndexedVtxo
): void => {
  if (ledger.owners.get(vtxo.script) !== walletId) {
    throw new Error(`script is not owned by ${walletId}`)
  }
  const receiptId = `${vtxo.txid}:${vtxo.vout}`
  const existing = ledger.receipts.get(receiptId)
  if (existing) {
    if (existing.walletId !== walletId || existing.value !== vtxo.value) {
      throw new Error(`receipt ${receiptId} changed attribution`)
    }
    return
  }
  ledger.receipts.set(receiptId, {walletId, value: vtxo.value})
  ledger.credits.set(walletId, ledger.credits.get(walletId)! + vtxo.value)
}

test('receives and restores native regtest Arkade funds from the mnemonic', async ({
  browser
}) => {
  const accountId = `account-${Date.now()}`
  const input: ProofInput = {
    mnemonic,
    installationId: 'installation-regtest',
    accountId,
    networkName: 'regtest',
    schemaVersion: '1',
    arkServerUrl,
    esploraUrl: 'http://localhost:3000/api'
  }
  const outputDirectory = await mkdtemp(
    join(tmpdir(), 'lnbits-arkade-regtest-')
  )
  const bundlePath = join(outputDirectory, 'arkade-regtest.js')
  let context: BrowserContext | undefined
  let page: Page | undefined
  let freshContext: BrowserContext | undefined
  let walletDisposed = false

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
    expect(await readFile(bundlePath, 'utf8')).not.toContain(mnemonic)

    const requests: string[] = []
    context = await browser.newContext()
    page = await context.newPage()
    page.on('request', request =>
      requests.push(`${request.url()} ${request.postData() || ''}`)
    )
    const initial = await loadProof(page, bundlePath, {
      ...input,
      mode: 'start'
    })
    expect(initial.address).toMatch(/^tark1/)
    expect(initial.boardingAddress).toMatch(/^bcrt1/)
    expect(initial.persistedState).not.toBeNull()
    expect(initial.contracts.length).toBeGreaterThan(0)
    expect(initial.receives).toHaveLength(2)
    const [walletA, walletB] = initial.receives
    expect(walletA).toMatchObject({walletId: 'wallet-a'})
    expect(walletB).toMatchObject({walletId: 'wallet-b'})
    expect(walletA.address).toMatch(/^tark1/)
    expect(walletB.address).toMatch(/^tark1/)
    expect(walletA.script).not.toBe(walletB.script)
    expect(walletA.address).not.toBe(walletB.address)
    expect(walletA.signingDescriptor).not.toBe(walletB.signingDescriptor)
    for (const receive of initial.receives) {
      expect(
        initial.contracts.some(
          (contract: {script?: string}) => contract.script === receive.script
        )
      ).toBe(false)
    }
    const firstReceive = walletA
    const initialOutpoints = new Set(
      initial.vtxos.map(vtxo => `${vtxo.txid}:${vtxo.vout}`)
    )

    const senderDataDir = `/tmp/lnbits-arkade-regtest-sender-${process.pid}-${Date.now()}`
    const runSender = (args: string[]) =>
      execFileAsync(process.execPath, [
        join(regtestRoot, 'regtest.mjs'),
        'ark',
        '--datadir',
        senderDataDir,
        ...args
      ])
    const runRegtest = (args: string[]) =>
      execFileAsync(process.execPath, [
        join(regtestRoot, 'regtest.mjs'),
        ...args
      ])
    const readIndexedVtxos = async (script: string): Promise<IndexedVtxo[]> => {
      const response = await fetch(
        `${arkServerUrl}/v1/indexer/vtxos?scripts=${encodeURIComponent(script)}`
      )
      if (!response.ok) return []
      const body = (await response.json()) as {
        vtxos?: IndexedVtxoResponse[]
      }
      return (body.vtxos || []).map(vtxo => ({
        txid: vtxo.outpoint.txid,
        vout: vtxo.outpoint.vout,
        value: Number(vtxo.amount),
        script: vtxo.script,
        commitmentTxids: vtxo.commitmentTxids,
        isPreconfirmed: vtxo.isPreconfirmed,
        isSpent: vtxo.isSpent,
        isSwept: vtxo.isSwept,
        settledBy: vtxo.settledBy,
        spentBy: vtxo.spentBy
      }))
    }
    const initialScriptOutpoints = new Map<string, Set<string>>()
    for (const receive of initial.receives) {
      initialScriptOutpoints.set(
        receive.script,
        new Set(
          (await readIndexedVtxos(receive.script)).map(
            vtxo => `${vtxo.txid}:${vtxo.vout}`
          )
        )
      )
    }

    let originalIntentFees: IntentFees | undefined
    let proofReceives: ProofResult['receives'] | undefined
    try {
      await runSender([
        'init',
        '--password',
        'proof-password',
        '--prvkey',
        '1111111111111111111111111111111111111111111111111111111111111111',
        '--server-url',
        arkServerUrl,
        '--explorer',
        'http://mempool_web/api'
      ])

      originalIntentFees = await readIntentFees()
      let feesChanged = false
      try {
        feesChanged = true
        const response = await fetch(`${adminUrl}/v1/admin/intentFees`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({fees: zeroIntentFees})
        })
        if (!response.ok) {
          throw new Error('failed to disable regtest intent fees')
        }
        const {stdout: noteOutput} = await runRegtest([
          'arkd',
          'note',
          '--amount',
          '300000'
        ])
        const note = noteOutput.trim().split(/\s+/).pop()
        if (!note?.startsWith('arknote')) {
          throw new Error('arkd did not return a credit note')
        }
        await runSender([
          'redeem-notes',
          '--notes',
          note,
          '--password',
          'proof-password'
        ])
      } finally {
        if (feesChanged) {
          const response = await fetch(`${adminUrl}/v1/admin/intentFees`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({fees: originalIntentFees})
          })
          if (!response.ok) {
            throw new Error('failed to restore regtest intent fees')
          }
        }
      }

      const sendReceive = async (
        receive: (typeof initial.receives)[number],
        amount: number
      ) => {
        await runSender([
          'send',
          '--to',
          receive.address,
          '--amount',
          String(amount),
          '--password',
          'proof-password'
        ])
      }

      await sendReceive(walletB, amounts.walletB)
      let secondIndexed: IndexedVtxo | undefined
      await expect
        .poll(
          async () => {
            secondIndexed = (await readIndexedVtxos(walletB.script)).find(
              vtxo =>
                vtxo.value === amounts.walletB &&
                !initialScriptOutpoints
                  .get(walletB.script)!
                  .has(`${vtxo.txid}:${vtxo.vout}`) &&
                !initialOutpoints.has(`${vtxo.txid}:${vtxo.vout}`) &&
                !vtxo.isSpent &&
                !vtxo.isSwept
            )
            return secondIndexed?.value
          },
          {timeout: 30_000}
        )
        .toBe(amounts.walletB)
      expect(secondIndexed?.script).toBe(walletB.script)
      expect(secondIndexed?.isPreconfirmed).toBe(true)
      expect(secondIndexed?.commitmentTxids?.length).toBeGreaterThan(0)

      await sendReceive(firstReceive, amounts.walletA)
      let firstIndexed: IndexedVtxo | undefined
      await expect
        .poll(
          async () => {
            firstIndexed = (await readIndexedVtxos(firstReceive.script)).find(
              vtxo =>
                vtxo.value === amounts.walletA &&
                !initialScriptOutpoints
                  .get(firstReceive.script)!
                  .has(`${vtxo.txid}:${vtxo.vout}`) &&
                !initialOutpoints.has(`${vtxo.txid}:${vtxo.vout}`) &&
                !vtxo.isSpent &&
                !vtxo.isSwept
            )
            return firstIndexed?.value
          },
          {timeout: 30_000}
        )
        .toBe(amounts.walletA)
      expect(firstIndexed?.script).toBe(firstReceive.script)
      expect(firstIndexed?.isPreconfirmed).toBe(true)
      expect(firstIndexed?.commitmentTxids?.length).toBeGreaterThan(0)

      proofReceives = initial.receives

      let finalProof: ProofResult | undefined
      await expect
        .poll(
          async () => {
            finalProof = await loadProof(
              page,
              bundlePath,
              {...input, mode: 'final'},
              false,
              true
            )
            return finalProof.vtxos.filter(vtxo =>
              initial.receives.some(receive => receive.script === vtxo.script)
            ).length
          },
          {timeout: 30_000}
        )
        .toBeGreaterThanOrEqual(2)
      expect(finalProof).toBeDefined()
      for (const receive of initial.receives) {
        expect(finalProof!.contracts).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              script: receive.script,
              metadata: expect.objectContaining({
                signingDescriptor: receive.signingDescriptor
              })
            })
          ])
        )
      }

      const ledger: AttributionLedger = {
        owners: new Map(
          initial.receives.map(receive => [receive.script, receive.walletId])
        ),
        receipts: new Map(),
        credits: new Map([
          ['wallet-a', 0],
          ['wallet-b', 0]
        ])
      }
      expect(ledger.owners.size).toBe(2)
      applyReceipt(ledger, 'wallet-a', firstIndexed!)
      applyReceipt(ledger, 'wallet-b', secondIndexed!)
      expect(
        [...ledger.credits.values()].reduce((sum, value) => sum + value, 0)
      ).toBe(amounts.walletA + amounts.walletB)
      expect(ledger.credits.get('wallet-a')).toBe(amounts.walletA)
      expect(ledger.credits.get('wallet-b')).toBe(amounts.walletB)
      const replayedCredits = new Map(ledger.credits)
      applyReceipt(ledger, 'wallet-a', firstIndexed!)
      applyReceipt(ledger, 'wallet-b', secondIndexed!)
      expect(ledger.credits).toEqual(replayedCredits)
      const wrongWalletCredits = new Map(ledger.credits)
      expect(() => applyReceipt(ledger, 'wallet-b', firstIndexed!)).toThrow(
        'script is not owned by wallet-b'
      )
      expect(ledger.credits).toEqual(wrongWalletCredits)

      expect(finalProof!.vtxos).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            txid: firstIndexed!.txid,
            vout: firstIndexed!.vout,
            value: amounts.walletA,
            script: walletA.script,
            isPreconfirmed: true
          }),
          expect.objectContaining({
            txid: secondIndexed!.txid,
            vout: secondIndexed!.vout,
            value: amounts.walletB,
            script: walletB.script,
            isPreconfirmed: true
          })
        ])
      )
      expect(finalProof!.balance.available).toBe(
        initial.balance.available + amounts.walletA + amounts.walletB
      )
      expect(
        finalProof!.balance.settled + finalProof!.balance.preconfirmed
      ).toBe(
        initial.balance.settled +
          initial.balance.preconfirmed +
          amounts.walletA +
          amounts.walletB
      )
      expect(finalProof!.balance.total).toBe(
        initial.balance.total + amounts.walletA + amounts.walletB
      )

      for (const [script, indexed] of [
        [walletA.script, firstIndexed!],
        [walletB.script, secondIndexed!]
      ] as const) {
        const refreshed = (await readIndexedVtxos(script)).find(
          vtxo => vtxo.txid === indexed.txid && vtxo.vout === indexed.vout
        )
        expect(refreshed).toMatchObject({
          value: indexed.value,
          script,
          isSpent: false,
          isSwept: false,
          isPreconfirmed: true
        })
        expect(refreshed?.commitmentTxids?.length).toBeGreaterThan(0)
      }

      expect(JSON.stringify(finalProof!.persistedState)).not.toMatch(
        /(?:mnemonic|private.?key|secret|seed)/i
      )
      expect(JSON.stringify(finalProof!.contracts)).not.toMatch(
        /(?:mnemonic|private.?key|secret|seed)/i
      )
      expect(requests.join('\n')).not.toContain(mnemonic)
      await loadProof(
        page,
        bundlePath,
        {...input, mode: 'dispose'},
        false,
        true
      )
      walletDisposed = true

      const restoreInput: ProofInput = {
        ...input,
        accountId,
        mode: 'restore',
        restore: true,
        receives: proofReceives
      }
      const restored = await loadProof(page, bundlePath, restoreInput, true)
      expect(restored.repositoryName).toBe(initial.repositoryName)
      expect(restored.identityDescriptor).toBe(initial.identityDescriptor)
      expect(restored.receives).toEqual(proofReceives)
      expect(restored.vtxos).toEqual(
        expect.arrayContaining(
          proofReceives!.map((receive, index) =>
            expect.objectContaining({
              txid: index === 0 ? firstIndexed!.txid : secondIndexed!.txid,
              vout: index === 0 ? firstIndexed!.vout : secondIndexed!.vout,
              value: index === 0 ? amounts.walletA : amounts.walletB,
              script: receive.script
            })
          )
        )
      )
      expect(restored.balance.available).toBe(
        initial.balance.available + amounts.walletA + amounts.walletB
      )
      expect(restored.balance.settled + restored.balance.preconfirmed).toBe(
        initial.balance.settled +
          initial.balance.preconfirmed +
          amounts.walletA +
          amounts.walletB
      )
      expect(restored.balance.total).toBe(
        initial.balance.total + amounts.walletA + amounts.walletB
      )
      expect(requests.join('\n')).not.toContain(mnemonic)
      await context.close()
      context = undefined

      freshContext = await browser.newContext()
      const freshPage = await freshContext.newPage()
      freshPage.on('request', request =>
        requests.push(`${request.url()} ${request.postData() || ''}`)
      )
      const freshRestored = await loadProof(freshPage, bundlePath, restoreInput)
      expect(freshRestored.vtxos).toEqual(restored.vtxos)
      expect(freshRestored.balance).toEqual(restored.balance)
      expect(requests.join('\n')).not.toContain(mnemonic)
      await freshContext.close()
      freshContext = undefined
    } finally {
      if (!walletDisposed && context && page) {
        await loadProof(
          page,
          bundlePath,
          {...input, mode: 'dispose'},
          false,
          true
        ).catch(() => undefined)
      }
      await freshContext?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await execFileAsync('docker', [
        'exec',
        'arkd',
        'rm',
        '-rf',
        '--',
        senderDataDir
      ]).catch(() => undefined)
    }

    if (originalIntentFees) {
      expect(await readIntentFees()).toEqual(originalIntentFees)
    }
  } finally {
    await freshContext?.close().catch(() => undefined)
    await context?.close().catch(() => undefined)
    await rm(outputDirectory, {force: true, recursive: true})
  }
})
