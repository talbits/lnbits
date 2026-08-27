import {execFile} from 'node:child_process'
import {mkdtemp, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join, resolve} from 'node:path'
import {promisify} from 'node:util'

import {expect, test, type BrowserContext, type Page} from '@playwright/test'
import {ArkAddress} from '@arkade-os/sdk'
import {build} from 'esbuild'

const execFileAsync = promisify(execFile)
const projectRoot = resolve(__dirname, '../..')
const regtestRoot = resolve(
  process.env.ARKADE_REGTEST_DIR || join(projectRoot, '../arkade-regtest')
)
const officialUrl = 'http://localhost:3003'
const arkServerUrl = 'http://localhost:7070'
const adminUrl = 'http://localhost:7071'
const amounts = [80_000, 120_000]
const sendAmount = 50_000
const zeroIntentFees = {
  offchainInputFee: '0.0',
  onchainInputFee: '0.0',
  offchainOutputFee: '0.0',
  onchainOutputFee: '0.0'
}

type Receive = {address: string; script: string}
type IndexedVtxo = {
  txid: string
  vout: number
  value: number
  script: string
  isPreconfirmed?: boolean
  isSpent?: boolean
  isSwept?: boolean
  spentBy?: string
}
type IntentFees = Record<string, string>

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

const readIntentFees = async (): Promise<IntentFees> => {
  const response = await fetch(`${adminUrl}/v1/admin/intentFees`)
  if (!response.ok) throw new Error('failed to read regtest intent fees')
  const body = (await response.json()) as {fees?: unknown}
  if (
    !body.fees ||
    typeof body.fees !== 'object' ||
    Array.isArray(body.fees) ||
    Object.keys(body.fees).length === 0 ||
    Object.values(body.fees).some(value => typeof value !== 'string')
  ) {
    throw new Error('regtest intent fee response has an unusable shape')
  }
  return {...body.fees} as IntentFees
}

const readIndexedVtxos = async (script: string): Promise<IndexedVtxo[]> => {
  const response = await fetch(
    `${arkServerUrl}/v1/indexer/vtxos?scripts=${encodeURIComponent(script)}`
  )
  if (!response.ok) return []
  const body = (await response.json()) as {
    vtxos?: Array<{
      outpoint: {txid: string; vout: number}
      amount: string
      script: string
      isPreconfirmed?: boolean
      isSpent?: boolean
      isSwept?: boolean
      spentBy?: string
    }>
  }
  return (body.vtxos || []).map(vtxo => ({
    txid: vtxo.outpoint.txid,
    vout: vtxo.outpoint.vout,
    value: Number(vtxo.amount),
    script: vtxo.script,
    isPreconfirmed: vtxo.isPreconfirmed,
    isSpent: vtxo.isSpent,
    isSwept: vtxo.isSwept,
    spentBy: vtxo.spentBy
  }))
}

const noSecretIn = (values: string[], mnemonic: string, message: string) => {
  if (values.some(value => value.includes(mnemonic))) throw new Error(message)
}

const loadHarnessProof = async (
  page: Page,
  bundlePath: string,
  input: Record<string, unknown>,
  reuse = false
) => {
  if (!reuse) {
    await page.goto('http://127.0.0.1:4173/')
    await page.addScriptTag({path: bundlePath})
  }
  return page.evaluate(input => {
    const runner = window.runArkadeRegtestProof
    if (!runner) throw new Error('Arkade harness was not loaded')
    return runner(input as never)
  }, input)
}

test('official Arkade wallet recovers and spends HD mnemonic funds', async ({
  browser
}) => {
  const runId = `${process.pid}-${Date.now()}`
  const installationId = `official-${runId}`
  const accountId = `official-${runId}`
  const repositoryInput = {
    installationId,
    accountId,
    networkName: 'regtest',
    schemaVersion: '1',
    arkServerUrl,
    esploraUrl: 'http://localhost:3000/api'
  }
  const outputDirectory = await mkdtemp(
    join(tmpdir(), 'lnbits-arkade-official-recovery-')
  )
  const bundlePath = join(outputDirectory, 'arkade-official-recovery.js')
  const browserOptions = {
    screenshot: 'off' as const,
    trace: 'off' as const,
    video: 'off' as const
  }
  let officialContext: BrowserContext | undefined
  let harnessContext: BrowserContext | undefined
  let harnessPage: Page | undefined
  let harnessStarted = false
  let harnessDisposed = false
  let mnemonic = ''
  const officialRequests: string[] = []
  const harnessRequests: string[] = []
  const senderDataDir = `/tmp/lnbits-arkade-official-sender-${runId}`
  const recipientDataDir = `/tmp/lnbits-arkade-official-recipient-${runId}`
  const runArk = (datadir: string, args: string[]) =>
    execFileAsync(process.execPath, [
      join(regtestRoot, 'regtest.mjs'),
      'ark',
      '--datadir',
      datadir,
      ...args
    ])
  const runRegtest = (args: string[]) =>
    execFileAsync(process.execPath, [join(regtestRoot, 'regtest.mjs'), ...args])

  try {
    await build({
      absWorkingDir: projectRoot,
      bundle: true,
      entryPoints: [resolve(__dirname, 'arkade-bip39.browser.ts')],
      format: 'iife',
      outfile: bundlePath,
      platform: 'browser',
      target: 'es2022'
    })

    officialContext = await browser.newContext(browserOptions)
    const createPage = await officialContext.newPage()
    createPage.on('request', request =>
      officialRequests.push(`${request.url()} ${request.postData() || ''}`)
    )
    await createPage.goto(`${officialUrl}#localhost`)
    await createPage
      .getByTestId('onboarding-devmode-tap')
      .click({clickCount: 3, delay: 40})
    await createPage
      .getByRole('button', {name: /create wallet/i})
      .first()
      .click()
    await createPage.getByTestId('toggle-hd-rotation').click()
    await createPage
      .getByRole('button', {name: 'Create wallet', exact: true})
      .last()
      .click()
    await createPage
      .getByTestId('top-right-settings')
      .waitFor({timeout: 30_000})
    await createPage.getByTestId('top-right-settings').click()
    await createPage.getByRole('button', {name: /^backup$/i}).click()
    await createPage
      .getByRole('button', {name: /view recovery phrase/i})
      .click()
    await createPage.getByRole('button', {name: 'Confirm', exact: true}).click()
    mnemonic = (await createPage.getByTestId('private-key').innerText()).trim()
    if (!/^[a-z]+(?:\s+[a-z]+){11}$/i.test(mnemonic)) {
      throw new Error('official wallet did not yield a standard mnemonic')
    }
    noSecretIn(officialRequests, mnemonic, 'official wallet sent its mnemonic')
    await officialContext.close()
    officialContext = undefined

    harnessContext = await browser.newContext(browserOptions)
    harnessPage = await harnessContext.newPage()
    harnessPage.on('request', request =>
      harnessRequests.push(`${request.url()} ${request.postData() || ''}`)
    )
    const initial = await loadHarnessProof(harnessPage, bundlePath, {
      ...repositoryInput,
      mnemonic,
      mode: 'start'
    })
    harnessStarted = true
    if (!initial.receives || initial.receives.length !== 2) {
      throw new Error('harness did not allocate two HD receive scripts')
    }
    const receives = initial.receives as Receive[]
    const runSender = (args: string[]) => runArk(senderDataDir, args)
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
      const feeResponse = await fetch(`${adminUrl}/v1/admin/intentFees`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({fees: zeroIntentFees})
      })
      if (!feeResponse.ok)
        throw new Error('failed to disable regtest intent fees')
      const {stdout} = await runRegtest(['arkd', 'note', '--amount', '300000'])
      const note = stdout.trim().split(/\s+/).pop()
      if (!note?.startsWith('arknote'))
        throw new Error('arkd did not return a credit note')
      await runSender([
        'redeem-notes',
        '--notes',
        note,
        '--password',
        'proof-password'
      ])
    } finally {
      if (feesChanged) {
        const feeResponse = await fetch(`${adminUrl}/v1/admin/intentFees`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({fees: originalIntentFees})
        })
        if (!feeResponse.ok)
          throw new Error('failed to restore regtest intent fees')
      }
    }
    const initialOutpoints = new Set(
      initial.vtxos.map(
        (vtxo: {txid: string; vout: number}) => `${vtxo.txid}:${vtxo.vout}`
      )
    )
    const received: IndexedVtxo[] = []
    for (const [index, receive] of Array.from(receives.entries()).reverse()) {
      await runSender([
        'send',
        '--to',
        receive.address,
        '--amount',
        String(amounts[index]),
        '--password',
        'proof-password'
      ])
      let found: IndexedVtxo | undefined
      await expect
        .poll(
          async () => {
            found = (await readIndexedVtxos(receive.script)).find(
              vtxo =>
                vtxo.value === amounts[index] &&
                !initialOutpoints.has(`${vtxo.txid}:${vtxo.vout}`) &&
                !vtxo.isSpent &&
                !vtxo.isSwept
            )
            return found?.value
          },
          {timeout: 30_000}
        )
        .toBe(amounts[index])
      if (!found) throw new Error('indexer did not return funded receive')
      received[index] = found
    }
    await expect
      .poll(
        async () => {
          const result = await loadHarnessProof(
            harnessPage!,
            bundlePath,
            {
              ...repositoryInput,
              mnemonic,
              mode: 'final'
            },
            true
          )
          return result.vtxos.filter((vtxo: IndexedVtxo) =>
            receives.some(receive => receive.script === vtxo.script)
          ).length
        },
        {timeout: 30_000}
      )
      .toBeGreaterThanOrEqual(2)
    await loadHarnessProof(
      harnessPage,
      bundlePath,
      {
        ...repositoryInput,
        mnemonic,
        mode: 'dispose'
      },
      true
    )
    harnessDisposed = true
    noSecretIn(harnessRequests, mnemonic, 'harness sent its mnemonic')
    await harnessContext.close()
    harnessContext = undefined
    harnessPage = undefined

    await runArk(recipientDataDir, [
      'init',
      '--password',
      'recipient-password',
      '--prvkey',
      '2222222222222222222222222222222222222222222222222222222222222222',
      '--server-url',
      arkServerUrl,
      '--explorer',
      'http://mempool_web/api'
    ])
    const {stdout: recipientOutput} = await runArk(recipientDataDir, [
      'receive'
    ])
    const recipientAddress = recipientOutput.match(/tark1[0-9a-z]+/)?.[0]
    if (!recipientAddress)
      throw new Error('recipient CLI did not return a tark1 address')
    const recipientScript = toHex(ArkAddress.decode(recipientAddress).pkScript)
    const recipientBaseline = new Set(
      (await readIndexedVtxos(recipientScript)).map(
        vtxo => `${vtxo.txid}:${vtxo.vout}`
      )
    )
    officialContext = await browser.newContext(browserOptions)
    const restorePage = await officialContext.newPage()
    restorePage.on('request', request =>
      officialRequests.push(`${request.url()} ${request.postData() || ''}`)
    )
    await restorePage.goto(`${officialUrl}#localhost`)
    await restorePage
      .getByTestId('onboarding-devmode-tap')
      .click({clickCount: 3, delay: 40})
    await restorePage
      .getByRole('button', {name: /other login options/i})
      .click()
    await restorePage.getByRole('button', {name: /restore wallet/i}).click()
    await restorePage.locator('input[name=private-key]').fill(mnemonic)
    const hdOptions = restorePage.getByText('HD', {exact: true})
    if ((await hdOptions.count()) !== 1) {
      throw new Error('official wallet did not expose one HD restore option')
    }
    await hdOptions.click()
    await restorePage
      .getByRole('button', {name: 'Continue', exact: true})
      .click()
    await restorePage.getByTestId('home-action-send').waitFor({timeout: 90_000})
    const homeText = await restorePage.locator('body').innerText()
    if (/No transactions yet/.test(homeText)) {
      throw new Error('official wallet did not display recovered activity')
    }

    await restorePage.getByTestId('home-action-send').click()
    await restorePage.locator('input[name=send-address]').fill(recipientAddress)
    const btcAmountMode = restorePage.getByRole('button', {
      name: 'Enter amount in BTC',
      exact: true
    })
    if (await btcAmountMode.count()) await btcAmountMode.click()
    await restorePage.locator('input[name=send-amount]').fill('0.0005')
    await restorePage.waitForTimeout(1_000)
    await restorePage
      .getByRole('button', {name: 'Continue', exact: true})
      .click()
    await restorePage.getByRole('button', {name: /tap to sign/i}).click()
    await restorePage.getByText('Payment sent').waitFor({timeout: 90_000})

    await expect
      .poll(
        async () => {
          const current = (
            await Promise.all(
              receives.map(receive => readIndexedVtxos(receive.script))
            )
          ).flat()
          return current.find(vtxo =>
            received.some(
              input =>
                input.txid === vtxo.txid &&
                input.vout === vtxo.vout &&
                vtxo.isSpent
            )
          )
        },
        {timeout: 60_000}
      )
      .not.toBeUndefined()
    let recipientVtxo: IndexedVtxo | undefined
    await expect
      .poll(
        async () => {
          recipientVtxo = (await readIndexedVtxos(recipientScript)).find(
            vtxo =>
              vtxo.value === sendAmount &&
              !recipientBaseline.has(`${vtxo.txid}:${vtxo.vout}`) &&
              !vtxo.isSpent &&
              !vtxo.isSwept
          )
          return recipientVtxo?.value
        },
        {timeout: 60_000}
      )
      .toBe(sendAmount)
    if (!recipientVtxo?.txid)
      throw new Error('recipient output lacked an outpoint')
    noSecretIn(officialRequests, mnemonic, 'official wallet sent its mnemonic')
  } finally {
    if (harnessStarted && !harnessDisposed && harnessPage) {
      await loadHarnessProof(
        harnessPage,
        bundlePath,
        {
          ...repositoryInput,
          mnemonic,
          mode: 'dispose'
        },
        true
      ).catch(() => undefined)
    }
    await officialContext?.close().catch(() => undefined)
    await harnessContext?.close().catch(() => undefined)
    await execFileAsync('docker', [
      'exec',
      'arkd',
      'rm',
      '-rf',
      '--',
      senderDataDir
    ]).catch(() => undefined)
    await execFileAsync('docker', [
      'exec',
      'arkd',
      'rm',
      '-rf',
      '--',
      recipientDataDir
    ]).catch(() => undefined)
    await rm(outputDirectory, {force: true, recursive: true})
  }
})
