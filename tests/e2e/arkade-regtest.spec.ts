import {execFile} from 'node:child_process'
import {mkdtemp, readFile, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join, resolve} from 'node:path'
import {promisify} from 'node:util'

import {expect, test, type Page} from '@playwright/test'
import {build} from 'esbuild'

const execFileAsync = promisify(execFile)
const projectRoot = resolve(__dirname, '../..')
const browserSource = resolve(__dirname, 'arkade-bip39.browser.ts')
const regtestRoot = resolve(
  process.env.ARKADE_REGTEST_DIR || join(projectRoot, '../arkade-regtest')
)
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const amount = 100_000
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
  reload = false
): Promise<ProofResult> => {
  if (reload) {
    await page.reload()
  } else {
    await page.goto('/')
  }
  await page.addScriptTag({path: bundlePath})
  return page.evaluate(input => window.runArkadeRegtestProof(input), input)
}

test('receives and restores native regtest Arkade funds from the mnemonic', async ({
  browser
}) => {
  const input: ProofInput = {
    mnemonic,
    installationId: 'installation-regtest',
    accountId: `account-${Date.now()}`,
    networkName: 'regtest',
    schemaVersion: '1',
    arkServerUrl,
    esploraUrl: 'http://localhost:3000/api'
  }
  const outputDirectory = await mkdtemp(
    join(tmpdir(), 'lnbits-arkade-regtest-')
  )
  const bundlePath = join(outputDirectory, 'arkade-regtest.js')

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
    const context = await browser.newContext()
    const page = await context.newPage()
    page.on('request', request =>
      requests.push(`${request.url()} ${request.postData() || ''}`)
    )
    const initial = await loadProof(page, bundlePath, input)
    expect(initial.address).toMatch(/^tark1/)
    expect(initial.boardingAddress).toMatch(/^bcrt1/)
    expect(initial.persistedState).not.toBeNull()
    expect(initial.contracts.length).toBeGreaterThan(0)
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

      const originalIntentFees = await readIntentFees()
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
          '200000'
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

      await runSender([
        'send',
        '--to',
        initial.address,
        '--amount',
        String(amount),
        '--password',
        'proof-password'
      ])
    } finally {
      await execFileAsync('docker', [
        'exec',
        'arkd',
        'rm',
        '-rf',
        '--',
        senderDataDir
      ]).catch(() => undefined)
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
    const readIndexedVtxos = async (): Promise<IndexedVtxo[]> => {
      const response = await fetch(
        `${arkServerUrl}/v1/indexer/vtxos?scripts=${encodeURIComponent(
          initial.recipientScript
        )}`
      )
      if (!response.ok) {
        return []
      }
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
    let indexedRecipient: IndexedVtxo | undefined
    await expect
      .poll(
        async () => {
          indexedRecipient = (await readIndexedVtxos()).find(
            vtxo =>
              vtxo.script === initial.recipientScript &&
              vtxo.value === amount &&
              !initialOutpoints.has(`${vtxo.txid}:${vtxo.vout}`) &&
              !vtxo.isSpent &&
              !vtxo.isSwept
          )
          return indexedRecipient?.value
        },
        {timeout: 30_000}
      )
      .toBe(amount)
    expect(indexedRecipient).toBeDefined()
    expect(indexedRecipient?.commitmentTxids?.length).toBeGreaterThan(0)

    let reloaded: ProofResult | undefined
    await expect
      .poll(
        async () => {
          reloaded = await loadProof(
            page,
            bundlePath,
            {...input, restore: true},
            true
          )
          const restoredRecipient = reloaded.vtxos.find(
            vtxo =>
              vtxo.script === initial.recipientScript &&
              vtxo.value === amount &&
              !initialOutpoints.has(`${vtxo.txid}:${vtxo.vout}`) &&
              !vtxo.isSpent &&
              !vtxo.isSwept
          )
          return restoredRecipient?.value
        },
        {timeout: 30_000}
      )
      .toBe(amount)
    expect(reloaded).toBeDefined()
    const reloadedProof = reloaded!
    expect(reloadedProof.repositoryName).toBe(initial.repositoryName)
    expect(reloadedProof.identityDescriptor).toBe(initial.identityDescriptor)
    expect(
      reloadedProof.balance.settled + reloadedProof.balance.preconfirmed
    ).toBe(initial.balance.settled + initial.balance.preconfirmed + amount)
    expect(reloadedProof.balance.available).toBe(
      initial.balance.available + amount
    )
    expect(reloadedProof.balance.total).toBe(initial.balance.total + amount)
    const recipientVtxos = reloadedProof.vtxos.filter(
      vtxo =>
        vtxo.script === initial.recipientScript &&
        vtxo.value === amount &&
        !initialOutpoints.has(`${vtxo.txid}:${vtxo.vout}`) &&
        !vtxo.isSpent &&
        !vtxo.isSwept
    )
    expect(recipientVtxos).toHaveLength(1)
    const recipientVtxo = recipientVtxos[0]
    expect(recipientVtxo.isPreconfirmed).toBe(true)

    const refreshedIndexedRecipient = (await readIndexedVtxos()).find(
      vtxo =>
        vtxo.txid === recipientVtxo.txid && vtxo.vout === recipientVtxo.vout
    )
    expect(refreshedIndexedRecipient).toMatchObject({
      value: amount,
      script: initial.recipientScript,
      isSpent: false,
      isSwept: false
    })
    expect(refreshedIndexedRecipient?.isPreconfirmed).toBe(true)
    expect(refreshedIndexedRecipient?.commitmentTxids?.length).toBeGreaterThan(
      0
    )
    expect(JSON.stringify(reloadedProof.persistedState)).not.toMatch(
      /(?:mnemonic|private.?key|secret|seed)/i
    )
    expect(JSON.stringify(reloadedProof.contracts)).not.toMatch(
      /(?:mnemonic|private.?key|secret|seed)/i
    )
    expect(requests.join('\n')).not.toContain(mnemonic)
    await context.close()

    const restoredContext = await browser.newContext()
    const restoredPage = await restoredContext.newPage()
    restoredPage.on('request', request =>
      requests.push(`${request.url()} ${request.postData() || ''}`)
    )
    const restored = await loadProof(restoredPage, bundlePath, {
      ...input,
      restore: true
    })
    expect(restored.repositoryName).toBe(initial.repositoryName)
    expect(restored.identityDescriptor).toBe(initial.identityDescriptor)
    expect(restored.balance).toEqual(reloadedProof.balance)
    expect(restored.vtxos).toEqual(reloadedProof.vtxos)
    expect(requests.join('\n')).not.toContain(mnemonic)
    await restoredContext.close()
  } finally {
    await rm(outputDirectory, {force: true, recursive: true})
  }
})
