'use strict'

const assert = require('node:assert/strict')
const {readFileSync} = require('node:fs')
const {webcrypto} = require('node:crypto')
const vm = require('node:vm')
const {buildSync} = require('esbuild')
const {
  ArkAddress,
  CSVMultisigTapscript,
  DefaultVtxo,
  MnemonicIdentity,
  deriveDescriptorLeafPubKey
} = require('@arkade-os/sdk')

const productionBundle = readFileSync(
  'lnbits/static/js/pages/arkade-enrollment.js',
  'utf8'
)
assert.equal(productionBundle.includes('__ARKADE_ENROLLMENT_TEST__'), false)
assert.equal(productionBundle.includes('__setTestReady'), false)
const testBundlePath = '/tmp/arkade-enrollment-test.js'
buildSync({
  entryPoints: ['lnbits/static/js/pages/arkade-enrollment.src.js'],
  bundle: true,
  minify: true,
  legalComments: 'none',
  format: 'iife',
  target: 'es2020',
  define: {ARKADE_ENROLLMENT_TEST: 'true'},
  outfile: testBundlePath
})
const bundle = readFileSync(testBundlePath, 'utf8')
const accountId = 'aa'.repeat(16)
const serverPubkey =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const serverBytes = Buffer.from(serverPubkey, 'hex')
const intentId = 'cc'.repeat(16)
const walletId = 'wallet-1'
const identity = MnemonicIdentity.fromMnemonic(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  {isMainnet: false}
)

const hex = bytes => Buffer.from(bytes).toString('hex')
const future = () =>
  new Date(Math.ceil(Date.now() / 1000) * 1000 + 600_000).toISOString()

const makeFixture = ({amountSat, inputValue, dust = 100, store} = {}) => {
  const amount = amountSat ?? 700
  const value = inputValue ?? 1_000
  const inputDescriptor = identity.descriptor.replace('/0/*)', '/0/1)')
  const inputPubkey = deriveDescriptorLeafPubKey(inputDescriptor)
  const options = {
    pubKey: inputPubkey,
    serverPubKey: serverBytes,
    csvTimelock: {type: 'blocks', value: 144n}
  }
  const inputScript = new DefaultVtxo.Script(options)
  const destinationScript = new DefaultVtxo.Script({
    ...options,
    pubKey: deriveDescriptorLeafPubKey(
      identity.descriptor.replace('/0/*)', '/0/2)')
    )
  })
  const destination = destinationScript.address('tark', serverBytes)
  const descriptor = identity.descriptor.replace('/0/*)', '/0/0)')
  const changePubkey = deriveDescriptorLeafPubKey(descriptor)
  const changeScript = new DefaultVtxo.Script({
    ...options,
    pubKey: changePubkey
  })
  const changeAddress = changeScript.address('tark', serverBytes)
  const input = {
    txid: 'dd'.repeat(32),
    vout: 1,
    value,
    script: hex(inputScript.pkScript),
    tapTree: inputScript.encode(),
    forfeitTapLeafScript: inputScript.forfeit(),
    intentTapLeafScript: inputScript.exit(),
    createdAt: new Date(),
    isUnrolled: false
  }
  const wallet = {
    offchainTapscript: inputScript,
    serverUnrollScript: CSVMultisigTapscript.encode({
      timelock: {type: 'blocks', value: 144n},
      pubkeys: [serverBytes]
    }),
    arkProvider: {getInfo: async () => ({dust: BigInt(dust)})},
    indexerProvider: {},
    getSpendableVtxos: async () => [input],
    getNewAddresses: async () => [
      {
        address: changeAddress,
        signingDescriptor: descriptor,
        contract: {
          type: 'default',
          address: changeAddress,
          script: hex(changeScript.pkScript),
          metadata: {signingDescriptor: descriptor}
        }
      }
    ],
    dispose: async () => {},
    submitCount: 0,
    buildArgs: null,
    buildAndSubmitOffchainTx: async (...args) => {
      wallet.buildArgs = args
      wallet.submitCount += 1
      if (state.broadcastError) throw new Error('broadcast failed')
      return {arkTxid: 'ee'.repeat(32)}
    }
  }
  const binding = {
    state: 'ready',
    account_id: accountId,
    network: 'regtest',
    server_url: 'http://arkade.test',
    server_pubkey: serverPubkey,
    identity_xonly_pubkey: '11'.repeat(32)
  }
  const base = {
    intent_id: intentId,
    account_id: accountId,
    wallet_id: walletId,
    amount_msat: amount * 1000,
    max_fee_msat: 0,
    destination: destination.encode(),
    destination_kind: 'arkade_address',
    network: binding.network,
    server_url: binding.server_url,
    server_pubkey: binding.server_pubkey,
    expires_at: future()
  }
  const state = {
    status: 'reserved',
    authError: null,
    commitAuthError: false,
    mismatch: false,
    mismatchOnGet: 0,
    tamperedReleased: false,
    mutateDuringAuthorize: false,
    lockDuringAuthorize: false,
    broadcastError: false
  }
  const requests = []
  const window = makeWindow(store)
  window.__ARKADE_ENROLLMENT_TEST__ = {}
  vm.runInNewContext(bundle, window)
  const realmBytes = value =>
    vm.runInNewContext(
      `Uint8Array.from(${JSON.stringify(Array.from(value))})`,
      window
    )
  const realmLeaf = leaf => [
    {
      version: leaf[0].version,
      internalKey: realmBytes(leaf[0].internalKey),
      merklePath: leaf[0].merklePath.map(realmBytes)
    },
    realmBytes(leaf[1])
  ]
  const realmInput = {
    ...input,
    tapTree: realmBytes(input.tapTree),
    forfeitTapLeafScript: realmLeaf(input.forfeitTapLeafScript),
    intentTapLeafScript: realmLeaf(input.intentTapLeafScript)
  }
  wallet.offchainTapscript = {
    options: {
      ...options,
      pubKey: realmBytes(options.pubKey),
      serverPubKey: realmBytes(options.serverPubKey)
    }
  }
  wallet.serverUnrollScript = {
    script: realmBytes(wallet.serverUnrollScript.script)
  }
  wallet.getSpendableVtxos = async () => [realmInput]
  wallet.indexerProvider.getVtxos = async options => {
    wallet.indexerArgs.push(options)
    return {vtxos: [realmInput]}
  }
  wallet.indexerArgs = []
  wallet.refreshArgs = []
  wallet.finalizeArgs = null
  wallet.finalizeCount = 0
  wallet.finalizeResult = {finalized: [], pending: []}
  wallet.lockOnRefresh = false
  const manager = {
    annotateVtxos: async inputs => inputs,
    refreshVtxos: async options => {
      wallet.refreshArgs.push(options)
      if (wallet.lockOnRefresh) {
        wallet.lockOnRefresh = false
        window.ArkadeEnrollment.lock()
      }
    }
  }
  wallet.getContractManager = async () => manager
  wallet.finalizePendingTxs = async inputs => {
    wallet.finalizeCount += 1
    wallet.finalizeArgs = inputs
    if (wallet.clearSpentOnFinalize) realmInput.isSpent = false
    return wallet.finalizeResult
  }
  window.g = {user: {id: accountId}}
  window.ArkadeEnrollment.__setTestReady(binding, wallet)
  window.LNbits = {
    api: {
      arkadeOutgoingIntent: async requestedIntentId => {
        requests.push({method: 'GET'})
        const getCount = requests.filter(item => item.method === 'GET').length
        const committed =
          state.status !== 'reserved' &&
          (state.status !== 'released' || state.tamperedReleased)
        return {
          data: {
            ...base,
            intent_id: requestedIntentId || intentId,
            status: state.status,
            destination_script: committed
              ? state.mismatch || state.mismatchOnGet === getCount
                ? '00'
                : hex(destinationScript.pkScript)
              : null,
            inputs: committed
              ? [
                  {
                    intent_id: requestedIntentId || intentId,
                    txid: input.txid,
                    vout: input.vout,
                    amount_sat: input.value
                  }
                ]
              : [],
            change_index: committed && value > amount ? 0 : null,
            change_script:
              committed && value > amount ? hex(changeScript.pkScript) : null,
            change_amount_sat:
              committed && value > amount ? value - amount : null
          }
        }
      },
      arkadeSubmittedOutgoingIntents: async () => ({
        data:
          state.status === 'submitted'
            ? [(await window.LNbits.api.arkadeOutgoingIntent(intentId)).data]
            : []
      }),
      arkadeOutgoingAuthorize: async (_id, data) => {
        requests.push({method: 'POST', data})
        if (state.mutateDuringAuthorize)
          realmInput.forfeitTapLeafScript[1][0] ^= 1
        if (state.commitAuthError) state.status = 'submitted'
        if (state.authError) throw new Error('transport lost')
        state.status = 'submitted'
        if (state.lockDuringAuthorize) window.ArkadeEnrollment.lock()
        const change = data.change
        return {
          data: {
            ...base,
            status: 'submitted',
            destination_script: data.destination_script,
            inputs: data.inputs.map(item => ({
              intent_id: _id,
              ...item
            })),
            change_index: change?.index ?? null,
            change_script: change?.script ?? null,
            change_amount_sat: change?.amount_sat ?? null
          }
        }
      }
    }
  }
  return {
    window,
    wallet,
    state,
    requests,
    input: realmInput,
    destination,
    destinationScript,
    changeScript
  }
}

const makeWindow = (store = new Map()) => {
  const window = {
    window: null,
    globalThis: null,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    URL,
    location: {origin: 'http://lnbits.test', pathname: '/wallet'},
    localStorage: {
      getItem: key => store.get(key) ?? null,
      setItem: (key, value) => store.set(key, String(value))
    },
    indexedDB: {},
    addEventListener: () => {},
    clearTimeout,
    setTimeout,
    console
  }
  window.window = window
  window.globalThis = window
  return window
}

async function main() {
  const noChange = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const prepared = await noChange.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  assert.equal(noChange.wallet.submitCount, 0)
  assert.equal(noChange.requests.length, 1)
  await assert.rejects(
    noChange.window.ArkadeEnrollment.submitOutgoing(prepared, {
      approved: false
    }),
    /approval required/
  )
  assert.equal(noChange.requests.length, 1)
  const result = await noChange.window.ArkadeEnrollment.submitOutgoing(
    prepared,
    {approved: true}
  )
  assert.equal(result.reconciliationRequired, true)
  assert.equal(noChange.wallet.submitCount, 1)
  assert.equal(noChange.requests[1].method, 'GET')
  assert.equal(noChange.requests[2].method, 'POST')
  assert.equal(noChange.requests[2].data.change, null)
  assert.equal(
    JSON.stringify(noChange.requests[2].data.inputs),
    JSON.stringify([{txid: 'dd'.repeat(32), vout: 1, amount_sat: 1_000}])
  )
  assert.equal(
    noChange.requests[2].data.destination_script,
    hex(noChange.destinationScript.pkScript)
  )
  assert.equal(noChange.wallet.buildArgs[0][0].txid, 'dd'.repeat(32))
  assert.equal(noChange.wallet.buildArgs[0][0].vout, 1)
  assert.equal(noChange.wallet.buildArgs[0][0].value, 1_000)
  assert.equal(noChange.wallet.buildArgs[1][0].amount, 1_000n)
  assert.deepEqual(
    [...noChange.wallet.buildArgs[1][0].script],
    [...noChange.destinationScript.pkScript]
  )
  assert.strictEqual(
    noChange.wallet.buildArgs[2],
    noChange.wallet.serverUnrollScript
  )
  for (const secretField of [
    'mnemonic',
    'seed',
    'privateKey',
    'xprv',
    'password',
    'private_descriptor'
  ]) {
    assert.equal(secretField in result, false)
    assert.equal(secretField in noChange.requests[2].data, false)
  }

  const change = makeFixture({amountSat: 700, inputValue: 1_000})
  const changePlan = await change.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  assert.equal(changePlan.change.amount_sat, 300)
  assert.throws(() => {
    changePlan.change.amount_sat = 1
  }, TypeError)
  await change.window.ArkadeEnrollment.submitOutgoing(changePlan, {
    approved: true
  })
  assert.equal(change.requests[2].data.change.amount_sat, 300)
  assert.equal(
    change.requests[2].data.change.script,
    hex(change.changeScript.pkScript)
  )
  assert.equal(change.wallet.buildArgs[1].length, 2)
  assert.equal(change.wallet.buildArgs[1][1].amount, 300n)
  assert.deepEqual(
    [...change.wallet.buildArgs[1][1].script],
    [...change.changeScript.pkScript]
  )

  const dust = makeFixture({amountSat: 950, inputValue: 1_000, dust: 100})
  await assert.rejects(
    dust.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId),
    /below dust/
  )

  const locked = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const lockedPlan = await locked.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  locked.window.ArkadeEnrollment.lock()
  await assert.rejects(
    locked.window.ArkadeEnrollment.submitOutgoing(lockedPlan, {approved: true}),
    /locked/
  )
  assert.equal(locked.requests.length, 1)
  assert.equal(locked.wallet.submitCount, 0)

  const mutated = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const mutatedPlan = await mutated.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  mutated.state.mutateDuringAuthorize = true
  await assert.rejects(
    mutated.window.ArkadeEnrollment.submitOutgoing(mutatedPlan, {
      approved: true
    })
  )
  assert.equal(mutated.wallet.submitCount, 0)

  const mutation = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const mutationPlan = await mutation.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  assert.equal(Object.isFrozen(mutationPlan.inputs), true)
  assert.equal(Object.isFrozen(mutationPlan.inputs[0]), true)
  assert.equal(Object.isFrozen(mutationPlan.change), true)
  await assert.rejects(
    mutation.window.ArkadeEnrollment.submitOutgoing(
      {...mutationPlan, destinationScript: '00'},
      {approved: true}
    ),
    /preparation is invalid/
  )
  assert.equal(mutation.wallet.submitCount, 0)

  const mismatch = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const mismatchPlan = await mismatch.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  mismatch.state.authError = true
  mismatch.state.commitAuthError = true
  mismatch.state.mismatch = true
  await assert.rejects(
    mismatch.window.ArkadeEnrollment.submitOutgoing(mismatchPlan, {
      approved: true
    }),
    error =>
      error.status === 'authorization_unknown' &&
      error.reconciliationRequired === true
  )
  assert.equal(mismatch.wallet.submitCount, 0)

  const responseMismatch = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const responseMismatchPlan =
    await responseMismatch.window.ArkadeEnrollment.prepareOutgoing(
      intentId,
      walletId
    )
  const originalAuthorize =
    responseMismatch.window.LNbits.api.arkadeOutgoingAuthorize
  responseMismatch.window.LNbits.api.arkadeOutgoingAuthorize = async (
    _id,
    data
  ) => {
    const response = await originalAuthorize(_id, data)
    response.data.destination_script = '00'
    return response
  }
  await assert.rejects(
    responseMismatch.window.ArkadeEnrollment.submitOutgoing(
      responseMismatchPlan,
      {approved: true}
    ),
    /authorization changed/
  )
  assert.equal(responseMismatch.wallet.submitCount, 0)

  const precommit = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const precommitPlan = await precommit.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  precommit.state.authError = true
  await assert.rejects(
    precommit.window.ArkadeEnrollment.submitOutgoing(precommitPlan, {
      approved: true
    }),
    /authorization failed/
  )
  assert.equal(precommit.wallet.submitCount, 0)

  const committed = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const committedPlan = await committed.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  committed.state.authError = true
  committed.state.status = 'submitted'
  const committedResult =
    await committed.window.ArkadeEnrollment.submitOutgoing(committedPlan, {
      approved: true
    })
  assert.equal(committedResult.reconciliationRequired, true)
  assert.equal(committed.wallet.submitCount, 1)

  const unknown = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const unknownPlan = await unknown.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  unknown.state.authError = true
  const originalGet = unknown.window.LNbits.api.arkadeOutgoingIntent
  let unknownGetCount = 0
  unknown.window.LNbits.api.arkadeOutgoingIntent = async (...args) => {
    unknownGetCount += 1
    if (unknownGetCount >= 2) throw new Error('offline')
    return originalGet(...args)
  }
  await assert.rejects(
    unknown.window.ArkadeEnrollment.submitOutgoing(unknownPlan, {
      approved: true
    }),
    error =>
      error.status === 'authorization_unknown' &&
      error.reconciliationRequired === true
  )
  assert.equal(unknown.wallet.submitCount, 0)

  const broadcast = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const broadcastPlan = await broadcast.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  broadcast.state.broadcastError = true
  await assert.rejects(
    broadcast.window.ArkadeEnrollment.submitOutgoing(broadcastPlan, {
      approved: true
    }),
    error =>
      error.status === 'submitted' && error.reconciliationRequired === true
  )
  assert.equal(broadcast.wallet.submitCount, 1)

  const recovery = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const recoveryPlan = await recovery.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  recovery.state.status = 'submitted'
  await assert.rejects(
    recovery.window.ArkadeEnrollment.recoverOutgoing(intentId),
    /approval required/
  )
  assert.equal(recovery.wallet.finalizeArgs, null)
  recovery.wallet.refreshArgs = []
  const recovered = await recovery.window.ArkadeEnrollment.recoverOutgoing(
    intentId,
    {approved: true}
  )
  assert.equal(recovered.reconciliationRequired, true)
  assert.strictEqual(recovery.wallet.finalizeArgs[0], recovery.input)
  assert.equal(recovery.wallet.refreshArgs.length, 2)
  assert.equal(recovery.wallet.submitCount, 1)
  assert.equal(recoveryPlan.previewCommitment.length > 0, true)

  const concurrent = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await concurrent.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  concurrent.state.status = 'submitted'
  const [concurrentA, concurrentB] = await Promise.all([
    concurrent.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    }),
    concurrent.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    })
  ])
  assert.strictEqual(concurrentA, concurrentB)
  assert.equal(concurrent.wallet.finalizeCount, 1)
  assert.equal(concurrent.wallet.submitCount, 1)

  for (const result of [
    {finalized: ['ff'.repeat(32)], pending: []},
    {finalized: [], pending: ['ff'.repeat(32)]}
  ]) {
    const pendingFinalization = makeFixture({
      amountSat: 1_000,
      inputValue: 1_000
    })
    await pendingFinalization.window.ArkadeEnrollment.prepareOutgoing(
      intentId,
      walletId
    )
    pendingFinalization.state.status = 'submitted'
    pendingFinalization.wallet.finalizeResult = result
    const pendingResult =
      await pendingFinalization.window.ArkadeEnrollment.recoverOutgoing(
        intentId,
        {approved: true}
      )
    assert.equal(pendingResult.phase, 'reconciliation_required')
    assert.equal(pendingFinalization.wallet.refreshArgs.length, 2)
    assert.equal(
      pendingFinalization.requests.filter(item => item.method === 'GET').length,
      3
    )
    assert.equal(pendingFinalization.wallet.submitCount, 0)
  }

  const recoveryRace = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await recoveryRace.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  recoveryRace.state.status = 'submitted'
  recoveryRace.wallet.lockOnRefresh = true
  const recoveryRaceResult =
    await recoveryRace.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    })
  assert.equal(recoveryRaceResult.phase, 'reconciliation_required')
  assert.equal(recoveryRace.wallet.finalizeArgs, null)
  assert.equal(recoveryRace.wallet.submitCount, 0)

  const submitRace = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const submitRacePlan =
    await submitRace.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  submitRace.state.lockDuringAuthorize = true
  await assert.rejects(
    submitRace.window.ArkadeEnrollment.submitOutgoing(submitRacePlan, {
      approved: true
    }),
    /locked/
  )
  assert.equal(submitRace.wallet.submitCount, 0)

  const reloadStore = new Map()
  const firstLoad = makeFixture({
    amountSat: 1_000,
    inputValue: 1_000,
    store: reloadStore
  })
  await firstLoad.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  const reloaded = makeFixture({
    amountSat: 1_000,
    inputValue: 1_000,
    store: reloadStore
  })
  assert.equal(
    (await reloaded.window.ArkadeEnrollment.listOutgoing()).length,
    1
  )

  const browserLoss = makeFixture({amountSat: 1_000, inputValue: 1_000})
  browserLoss.state.status = 'submitted'
  const hydrated = await browserLoss.window.ArkadeEnrollment.listOutgoing()
  assert.equal(hydrated.length, 1)
  assert.equal(hydrated[0].intentId, intentId)
  assert.equal(hydrated[0].phase, 'submitted')
  assert.equal(
    JSON.stringify(browserLoss.wallet.indexerArgs[0].outpoints),
    JSON.stringify([
      {txid: browserLoss.input.txid, vout: browserLoss.input.vout}
    ])
  )

  const spentRecovery = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await spentRecovery.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  spentRecovery.state.status = 'submitted'
  spentRecovery.input.isSpent = true
  spentRecovery.wallet.clearSpentOnFinalize = true
  const spentResult =
    await spentRecovery.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    })
  assert.equal(spentResult.status, 'submitted')
  assert.equal(spentRecovery.wallet.submitCount, 1)
  assert.strictEqual(spentRecovery.wallet.finalizeArgs[0], spentRecovery.input)

  const secondGetMismatch = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await secondGetMismatch.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  secondGetMismatch.state.status = 'submitted'
  secondGetMismatch.state.mismatchOnGet = 3
  const mismatchResult =
    await secondGetMismatch.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    })
  assert.equal(mismatchResult.phase, 'reconciliation_required')
  assert.equal(secondGetMismatch.wallet.submitCount, 0)

  const tampered = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await tampered.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  const journalKey = `lnbits-arkade-outgoing-v1:http://lnbits.test:${accountId}`
  const journal = JSON.parse(tampered.window.localStorage.getItem(journalKey))
  journal[0].previewCommitment = '00'
  tampered.window.localStorage.setItem(journalKey, JSON.stringify(journal))
  tampered.state.status = 'submitted'
  const tamperedResult = await tampered.window.ArkadeEnrollment.recoverOutgoing(
    intentId,
    {approved: true}
  )
  assert.equal(tamperedResult.phase, 'reconciliation_required')
  assert.equal(tampered.wallet.finalizeArgs, null)

  const lockedRecovery = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await lockedRecovery.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  lockedRecovery.window.ArkadeEnrollment.lock()
  await assert.rejects(
    lockedRecovery.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    }),
    /wallet is locked/
  )

  const terminal = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await terminal.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  terminal.state.status = 'settled'
  const terminalResult = await terminal.window.ArkadeEnrollment.recoverOutgoing(
    intentId,
    {approved: true}
  )
  assert.equal(terminalResult.status, 'settled')
  assert.equal(terminal.wallet.submitCount, 0)
  assert.equal(terminal.wallet.finalizeArgs, null)

  const released = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await released.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  released.state.status = 'released'
  const releasedResult = await released.window.ArkadeEnrollment.recoverOutgoing(
    intentId,
    {approved: true}
  )
  assert.equal(releasedResult.status, 'released')
  assert.equal(
    (await released.window.ArkadeEnrollment.listOutgoing()).length,
    0
  )
  assert.equal(released.wallet.finalizeCount, 0)

  const tamperedReleased = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await tamperedReleased.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  tamperedReleased.state.status = 'released'
  tamperedReleased.state.tamperedReleased = true
  const tamperedReleasedResult =
    await tamperedReleased.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    })
  assert.equal(tamperedReleasedResult.phase, 'reconciliation_required')
  assert.equal(
    (await tamperedReleased.window.ArkadeEnrollment.listOutgoing()).length,
    1
  )
  assert.equal(tamperedReleased.wallet.finalizeCount, 0)

  const submittedReleased = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await submittedReleased.window.ArkadeEnrollment.prepareOutgoing(
    intentId,
    walletId
  )
  const submittedReleasedKey = `lnbits-arkade-outgoing-v1:http://lnbits.test:${accountId}`
  const submittedReleasedJournal = JSON.parse(
    submittedReleased.window.localStorage.getItem(submittedReleasedKey)
  )
  submittedReleasedJournal[0].phase = 'submitted'
  submittedReleased.window.localStorage.setItem(
    submittedReleasedKey,
    JSON.stringify(submittedReleasedJournal)
  )
  submittedReleased.state.status = 'released'
  const submittedReleasedResult =
    await submittedReleased.window.ArkadeEnrollment.recoverOutgoing(intentId, {
      approved: true
    })
  assert.equal(submittedReleasedResult.phase, 'reconciliation_required')
  assert.equal(
    (await submittedReleased.window.ArkadeEnrollment.listOutgoing()).length,
    1
  )
  assert.equal(submittedReleased.wallet.finalizeCount, 0)

  const disputed = makeFixture({amountSat: 1_000, inputValue: 1_000})
  await disputed.window.ArkadeEnrollment.prepareOutgoing(intentId, walletId)
  disputed.state.status = 'disputed'
  const disputedResult = await disputed.window.ArkadeEnrollment.recoverOutgoing(
    intentId,
    {approved: true}
  )
  assert.equal(disputedResult.status, 'disputed')
  assert.equal(disputedResult.reconciliationRequired, true)
  assert.equal(
    (await disputed.window.ArkadeEnrollment.listOutgoing()).length,
    1
  )

  const fullJournal = makeFixture({amountSat: 1_000, inputValue: 1_000})
  const journalIds = Array.from({length: 32}, (_, index) =>
    index.toString(16).padStart(32, '0')
  )
  for (const journalId of journalIds)
    await fullJournal.window.ArkadeEnrollment.prepareOutgoing(
      journalId,
      walletId
    )
  const fullJournalKey = `lnbits-arkade-outgoing-v1:http://lnbits.test:${accountId}`
  const beforeFull = fullJournal.window.localStorage.getItem(fullJournalKey)
  await assert.rejects(
    fullJournal.window.ArkadeEnrollment.prepareOutgoing(
      'ff'.repeat(16),
      walletId
    ),
    /journal is full/
  )
  assert.equal(
    fullJournal.window.localStorage.getItem(fullJournalKey),
    beforeFull
  )

  const terminalJournal = makeFixture({amountSat: 1_000, inputValue: 1_000})
  for (let index = 0; index < 40; index++) {
    terminalJournal.state.status = 'reserved'
    const terminalId = index.toString(16).padStart(32, '0')
    await terminalJournal.window.ArkadeEnrollment.prepareOutgoing(
      terminalId,
      walletId
    )
    terminalJournal.state.status = index % 2 ? 'released' : 'settled'
    assert.equal(
      (await terminalJournal.window.ArkadeEnrollment.listOutgoing()).length,
      0
    )
  }
  console.log('arkade outgoing browser helper checks passed')
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
