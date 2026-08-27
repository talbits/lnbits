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

test('restores confirmed regtest boarding funds from the mnemonic', async ({
  browser
}) => {
  const input: ProofInput = {
    mnemonic,
    installationId: 'installation-regtest',
    accountId: `account-${Date.now()}`,
    networkName: 'regtest',
    schemaVersion: '1',
    arkServerUrl: 'http://localhost:7070',
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

    await execFileAsync(process.execPath, [
      join(regtestRoot, 'regtest.mjs'),
      'faucet',
      initial.boardingAddress,
      '0.001',
      '--confirm'
    ])

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
          return reloaded.balance.boarding.confirmed
        },
        {timeout: 30_000}
      )
      .toBe(initial.balance.boarding.confirmed + amount)
    expect(reloaded).toBeDefined()
    const reloadedProof = reloaded!
    expect(reloadedProof.repositoryName).toBe(initial.repositoryName)
    expect(reloadedProof.identityDescriptor).toBe(initial.identityDescriptor)
    expect(reloadedProof.balance.total).toBe(initial.balance.total + amount)
    expect(JSON.stringify(reloadedProof.persistedState)).not.toMatch(
      /(?:mnemonic|private.?key|secret|seed)/i
    )
    expect(JSON.stringify(reloadedProof.contracts)).not.toContain(mnemonic)
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
    expect(requests.join('\n')).not.toContain(mnemonic)
    await restoredContext.close()
  } finally {
    await rm(outputDirectory, {force: true, recursive: true})
  }
})
