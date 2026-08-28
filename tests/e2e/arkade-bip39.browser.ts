import {
  ContractManager,
  DefaultVtxo,
  deriveDescriptorLeafPubKey,
  getNetwork,
  HDDescriptorProvider,
  IndexedDBContractRepository,
  IndexedDBWalletRepository,
  MnemonicIdentity,
  timelockToSequence,
  Wallet
} from '@arkade-os/sdk'

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], byte => parseInt(byte, 16))

type RepositoryInputs = {
  installationId: string
  accountId: string
  networkName: 'regtest'
  schemaVersion: string
}

type ProofVtxo = {
  txid: string
  vout: number
  value: number
  script: string
  isPreconfirmed?: boolean
  isSpent?: boolean
  isSwept?: boolean
  settledBy?: string
  spentBy?: string
}

type Receive = {
  walletId: 'wallet-a' | 'wallet-b'
  address: string
  script: string
  signingDescriptor: string
}

type RegtestMode = 'start' | 'final' | 'send' | 'dispose' | 'restore'

const requireText = (name: string, value: string): string => {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${name} must be non-empty`)
  }
  return value.trim()
}

const repositoryNameFor = ({
  installationId,
  accountId,
  networkName,
  schemaVersion
}: RepositoryInputs): string =>
  `lnbits-arkade-${JSON.stringify([
    requireText('installationId', installationId),
    requireText('accountId', accountId),
    requireText('networkName', networkName),
    requireText('schemaVersion', schemaVersion)
  ])}`

const runProof = async ({
  mnemonic,
  installationId,
  accountId,
  networkName = 'regtest',
  schemaVersion = '1',
  walletIds,
  step = 'initial'
}: RepositoryInputs & {
  mnemonic: string
  walletIds: [string, string]
  step?: 'initial' | 'reload'
}) => {
  const network = getNetwork(networkName)
  const identity = MnemonicIdentity.fromMnemonic(mnemonic, {isMainnet: false})
  const repositoryName = repositoryNameFor({
    installationId,
    accountId,
    networkName,
    schemaVersion
  })
  const repository = new IndexedDBWalletRepository(repositoryName)
  const descriptorProvider = await HDDescriptorProvider.create(
    identity,
    repository
  )
  const walletState = await repository.getWalletState()
  let walletDescriptors: Record<string, string> | undefined
  if (step === 'initial') {
    if (walletState) {
      throw new Error('initial proof must use an empty repository')
    }
    const descriptors = [
      await descriptorProvider.getNextSigningDescriptor(),
      await descriptorProvider.getNextSigningDescriptor()
    ]
    const normalizedWalletIds = walletIds.map((walletId, index) =>
      requireText(`walletIds[${index}]`, walletId)
    )
    if (new Set(normalizedWalletIds).size !== 2) {
      throw new Error('walletIds must identify two distinct wallets')
    }
    walletDescriptors = Object.fromEntries(
      normalizedWalletIds.map((walletId, index) => [
        walletId,
        descriptors[index]
      ])
    )
  } else if (!walletState) {
    throw new Error('reload proof requires persisted SDK wallet state')
  }
  const currentSigningDescriptor =
    await descriptorProvider.getCurrentSigningDescriptor()
  const nextSigningDescriptor =
    step === 'reload'
      ? await descriptorProvider.getNextSigningDescriptor()
      : undefined
  const readonlyIdentity = await identity.toReadonly()
  const publicData = {
    descriptor: readonlyIdentity.descriptor,
    xOnlyPublicKey: toHex(await readonlyIdentity.xOnlyPublicKey()),
    compressedPublicKey: toHex(await readonlyIdentity.compressedPublicKey())
  }
  const persistedState = await repository.getWalletState()

  return {
    network: network.name,
    repositoryName,
    identityIsMnemonic: identity instanceof MnemonicIdentity,
    identityDescriptor: identity.descriptor,
    walletDescriptors,
    currentSigningDescriptor,
    nextSigningDescriptor,
    lastIndexUsed: await descriptorProvider.getLastIndexUsed(),
    publicData,
    persistedState,
    readonlySerialized: JSON.stringify(readonlyIdentity),
    capabilities: {
      identityCanSign: typeof identity.sign === 'function',
      readonlyCanSign: typeof readonlyIdentity.sign === 'function',
      readonlyCanSignMessage:
        typeof readonlyIdentity.signMessage === 'function',
      readonlyHasSignerSession:
        typeof readonlyIdentity.signerSession === 'function'
    }
  }
}

type LiveWallet = {
  wallet: Awaited<ReturnType<typeof Wallet.create>>
  walletRepository: IndexedDBWalletRepository
  contractRepository: IndexedDBContractRepository
  repositoryName: string
  identity: MnemonicIdentity
  receives: Receive[]
}

let liveWallet: LiveWallet | undefined

const receiveForDescriptor = (
  wallet: Awaited<ReturnType<typeof Wallet.create>>,
  walletId: Receive['walletId'],
  signingDescriptor: string
): Receive => {
  const current = wallet.offchainTapscript
  const tapscript = new DefaultVtxo.Script({
    ...current.options,
    pubKey: deriveDescriptorLeafPubKey(signingDescriptor)
  })
  return {
    walletId,
    address: tapscript
      .address(wallet.network.hrp, tapscript.options.serverPubKey)
      .encode(),
    script: toHex(tapscript.pkScript),
    signingDescriptor
  }
}

const snapshotRegtestWallet = async (
  state: LiveWallet,
  receives: Receive[]
) => {
  const vtxos = (await state.wallet.getVtxos()).map(
    ({
      txid,
      vout,
      value,
      script,
      isPreconfirmed,
      isSpent,
      isSwept,
      settledBy,
      spentBy
    }): ProofVtxo => ({
      txid,
      vout,
      value,
      script,
      isPreconfirmed,
      isSpent,
      isSwept,
      settledBy,
      spentBy
    })
  )
  return {
    repositoryName: state.repositoryName,
    identityDescriptor: state.identity.descriptor,
    address: await state.wallet.getAddress(),
    boardingAddress: await state.wallet.getBoardingAddress(),
    balance: await state.wallet.getBalance(),
    recipientScript: state.wallet.defaultContractScript,
    receives,
    vtxos,
    persistedState: await state.walletRepository.getWalletState(),
    contracts: await state.contractRepository.getContracts()
  }
}

const runRegtestProof = async ({
  mnemonic,
  passphrase,
  installationId,
  accountId,
  networkName = 'regtest',
  schemaVersion = '1',
  arkServerUrl,
  esploraUrl,
  restore = false,
  mode = restore ? 'restore' : 'start',
  receives = [],
  sendRecipientAddress,
  sendAmount
}: RepositoryInputs & {
  mnemonic: string
  passphrase?: string
  arkServerUrl: string
  esploraUrl: string
  restore?: boolean
  mode?: RegtestMode
  receives?: Receive[]
  sendRecipientAddress?: string
  sendAmount?: number
}) => {
  const repositoryName = repositoryNameFor({
    installationId,
    accountId,
    networkName,
    schemaVersion
  })
  if (mode === 'start') {
    if (liveWallet) {
      throw new Error('a live Arkade wallet is already active')
    }
    const identity = MnemonicIdentity.fromMnemonic(mnemonic, {
      isMainnet: false,
      passphrase
    })
    const walletRepository = new IndexedDBWalletRepository(repositoryName)
    const contractRepository = new IndexedDBContractRepository(repositoryName)
    const wallet = await Wallet.create({
      identity,
      arkServerUrl,
      esploraUrl,
      storage: {
        walletRepository,
        contractRepository
      },
      walletMode: 'hd',
      settlementConfig: false
    })
    const manager = await wallet.getContractManager()
    const descriptors = [
      await wallet.getNextSigningDescriptor(),
      await wallet.getNextSigningDescriptor()
    ]
    if (!descriptors[0] || !descriptors[1]) {
      throw new Error('Arkade HD wallet did not allocate receive descriptors')
    }
    await manager.refillLookAhead()
    const receives = [
      receiveForDescriptor(wallet, 'wallet-a', descriptors[0]),
      receiveForDescriptor(wallet, 'wallet-b', descriptors[1])
    ]
    liveWallet = {
      wallet,
      walletRepository,
      contractRepository,
      repositoryName,
      identity,
      receives
    }
    return snapshotRegtestWallet(liveWallet, liveWallet.receives)
  }

  if (mode === 'send') {
    if (!liveWallet) {
      throw new Error('send requires the live Arkade wallet')
    }
    if (!sendRecipientAddress || !sendAmount) {
      throw new Error('send requires a recipient address and positive amount')
    }
    const sendTxid = await liveWallet.wallet.send({
      address: sendRecipientAddress,
      amount: sendAmount
    })
    return {
      ...(await snapshotRegtestWallet(liveWallet, liveWallet.receives)),
      sendTxid
    }
  }

  if (mode === 'final' || mode === 'dispose') {
    if (!liveWallet) {
      throw new Error(`${mode} requires the live Arkade wallet`)
    }
    const result = await snapshotRegtestWallet(liveWallet, liveWallet.receives)
    if (mode === 'dispose') {
      await liveWallet.wallet.dispose()
      liveWallet = undefined
    }
    return result
  }

  if (mode !== 'restore') {
    throw new Error(`unknown Arkade proof mode: ${mode}`)
  }

  const walletRepository = new IndexedDBWalletRepository(repositoryName)
  const contractRepository = new IndexedDBContractRepository(repositoryName)
  const identity = MnemonicIdentity.fromMnemonic(mnemonic, {
    isMainnet: false,
    passphrase
  })
  const wallet = await Wallet.create({
    identity,
    arkServerUrl,
    esploraUrl,
    storage: {walletRepository, contractRepository},
    walletMode: 'hd',
    settlementConfig: false
  })
  try {
    await wallet.restore({gapLimit: 5})
    return snapshotRegtestWallet(
      {
        wallet,
        walletRepository,
        contractRepository,
        repositoryName,
        identity,
        receives
      },
      receives
    )
  } finally {
    await wallet.dispose()
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

type InvoiceProofInput = RepositoryInputs & {
  mnemonic: string
  step?: 'initial' | 'reload'
  invoiceCount?: number
  walletId?: string
  amountSat?: number
  serverUrl?: string
}

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
  transportPayloads: string[]
}

const invoiceRepositoryNameFor = (input: RepositoryInputs): string =>
  `${repositoryNameFor(input)}-invoice-proof`

const stableInvoiceId = (index: number, salt: number): string =>
  (BigInt(index) + BigInt(salt)).toString(16).padStart(32, '0')

const canonicalInvoiceStatement = (mapping: {
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
}): string =>
  [
    'action=lnbits-arkade-receive-v1',
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

class IsolatedIndexer {
  private readonly funded = new Map<string, unknown[]>()

  async getVtxos(options?: {scripts?: string[]; outpoints?: unknown[]}) {
    const scripts = options?.scripts
    const vtxos = Array.from(this.funded.entries())
      .filter(([script]) => !scripts || scripts.includes(script))
      .flatMap(([, values]) => values)
    return {vtxos}
  }

  async subscribeForScripts() {
    return 'isolated-invoice-proof'
  }

  async unsubscribeForScripts() {}

  getSubscription() {
    return (async function* () {})()
  }

  fund(script: string, vtxo: unknown) {
    this.funded.set(script, [...(this.funded.get(script) ?? []), vtxo])
  }
}

const readInvoiceMappings = (key: string): InvoiceMapping[] => {
  const value = localStorage.getItem(key)
  return value
    ? (JSON.parse(value) as InvoiceMapping[]).map(mapping =>
        Object.freeze(mapping)
      )
    : []
}

const writeInvoiceMappings = (key: string, mappings: InvoiceMapping[]) => {
  localStorage.setItem(key, JSON.stringify(mappings))
}

const mappingPayload = (mapping: InvoiceMapping): string =>
  JSON.stringify(mapping)

const persistInvoiceMapping = (
  key: string,
  mapping: InvoiceMapping
): InvoiceMapping => {
  const mappings = readInvoiceMappings(key)
  const existing = mappings.find(
    item => item.nativeRequestId === mapping.nativeRequestId
  )
  if (existing) {
    if (mappingPayload(existing) !== mappingPayload(mapping)) {
      throw new Error('invoice allocation conflict')
    }
    return existing
  }
  const immutableMapping = Object.freeze(mapping)
  mappings.push(immutableMapping)
  writeInvoiceMappings(key, mappings)
  return immutableMapping
}

const acknowledgeInvoice = (
  journalKey: string,
  acknowledgementKey: string,
  mapping: InvoiceMapping,
  transportPayloads: string[],
  failOnceKey?: string
): InvoiceMapping => {
  const journalMapping = readInvoiceMappings(journalKey).find(
    item => item.nativeRequestId === mapping.nativeRequestId
  )
  if (
    !journalMapping ||
    mappingPayload(journalMapping) !== mappingPayload(mapping)
  ) {
    throw new Error('invoice acknowledgement conflict')
  }
  const acknowledgements = readInvoiceMappings(acknowledgementKey)
  const existing = acknowledgements.find(
    item => item.nativeRequestId === mapping.nativeRequestId
  )
  if (existing) {
    if (mappingPayload(existing) !== mappingPayload(mapping)) {
      throw new Error('invoice acknowledgement conflict')
    }
    return existing
  }
  if (failOnceKey && !localStorage.getItem(failOnceKey)) {
    localStorage.setItem(failOnceKey, 'failed')
    throw new Error('simulated backend acknowledgement failure')
  }
  transportPayloads.push(mappingPayload(mapping))
  acknowledgements.push(Object.freeze(mapping))
  writeInvoiceMappings(acknowledgementKey, acknowledgements)
  return mapping
}

const runInvoiceAllocatorProof = async ({
  mnemonic,
  installationId,
  accountId,
  networkName = 'regtest',
  schemaVersion = '1',
  step = 'initial',
  invoiceCount = 25,
  walletId = 'wallet-test',
  amountSat = 1000,
  serverUrl = 'http://arkade.test'
}: InvoiceProofInput): Promise<InvoiceProof> => {
  if (!Number.isSafeInteger(invoiceCount) || invoiceCount <= 20) {
    throw new Error('invoiceCount must be greater than 20')
  }
  const repositoryName = invoiceRepositoryNameFor({
    installationId,
    accountId,
    networkName,
    schemaVersion
  })
  const journalKey = `${repositoryName}:journal`
  const acknowledgementKey = `${repositoryName}:backend-ack`
  const failOnceKey = `${acknowledgementKey}:fail-once`
  const transportPayloads: string[] = []
  const repository = new IndexedDBWalletRepository(repositoryName)
  const contractRepository = new IndexedDBContractRepository(repositoryName)
  const identity = MnemonicIdentity.fromMnemonic(mnemonic, {isMainnet: false})
  const descriptorProvider = await HDDescriptorProvider.create(
    identity,
    repository
  )
  const indexer = new IsolatedIndexer()
  const manager = await ContractManager.create({
    indexerProvider: indexer as never,
    contractRepository,
    walletRepository: repository,
    watcherConfig: {failsafePollIntervalMs: 60 * 60 * 1000}
  })
  const serverPubKey = fromHex(
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  )
  const csvTimelock = {value: 144n, type: 'blocks' as const}
  const mappings = readInvoiceMappings(journalKey)

  if (step === 'initial' && mappings.length) {
    throw new Error('initial invoice proof must use an empty browser state')
  }
  if (step === 'reload' && mappings.length !== invoiceCount) {
    throw new Error('reload invoice proof lost persisted mappings')
  }

  const allocate = async (
    nativeRequestId: string,
    failAckOnce = false
  ): Promise<InvoiceMapping> => {
    const existing = readInvoiceMappings(journalKey).find(
      mapping => mapping.nativeRequestId === nativeRequestId
    )
    if (existing)
      return acknowledgeInvoice(
        journalKey,
        acknowledgementKey,
        existing,
        transportPayloads
      )

    const signingDescriptor =
      await descriptorProvider.getNextSigningDescriptor()
    if (!signingDescriptor) throw new Error('missing signing descriptor')
    const indexMatch = signingDescriptor.match(/\/0\/(\d+)\)$/)
    if (!indexMatch) throw new Error('unparseable signing descriptor')
    const index = Number(indexMatch[1])
    const pubKey = deriveDescriptorLeafPubKey(signingDescriptor)
    const tapscript = new DefaultVtxo.Script({
      pubKey,
      serverPubKey,
      csvTimelock
    })
    const script = toHex(tapscript.pkScript)
    const address = tapscript
      .address(getNetwork(networkName).hrp, serverPubKey)
      .encode()
    const serverPubkeyHex = toHex(serverPubKey)
    const mapping = Object.freeze({
      action: 'lnbits-arkade-receive-v1' as const,
      accountId,
      walletId,
      nativeRequestId,
      idempotencyKey: stableInvoiceId(index, 0x1000),
      amountSat,
      index,
      address,
      script,
      childXonlyPubkey: toHex(pubKey),
      network: networkName,
      serverUrl,
      serverPubkey: serverPubkeyHex,
      expiresAt: 1,
      signature: ''
    })
    const statement = canonicalInvoiceStatement(mapping)
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(statement))
    )
    const signature = toHex(
      await descriptorProvider.signMessageWithDescriptor(
        signingDescriptor,
        digest,
        'schnorr'
      )
    )
    // Isolated SDK 0.4.66 proof only; P2-8 must check released #810 and
    // replace this manual allocator with its supported receive API.
    await manager.createContract({
      type: 'default',
      params: {
        pubKey: toHex(pubKey),
        serverPubKey: toHex(serverPubKey),
        csvTimelock: timelockToSequence(csvTimelock).toString()
      },
      script,
      address,
      metadata: {signingDescriptor}
    })
    const signedMapping = Object.freeze({...mapping, signature})
    const persistedMapping = persistInvoiceMapping(journalKey, signedMapping)
    return acknowledgeInvoice(
      journalKey,
      acknowledgementKey,
      persistedMapping,
      transportPayloads,
      failAckOnce ? failOnceKey : undefined
    )
  }

  if (step === 'initial') {
    let failOnceAfterLocalPersist = false
    let retrySameMapping = false
    let retryMapping: InvoiceMapping | undefined
    for (let index = 0; index < invoiceCount; index++) {
      const nativeRequestId = stableInvoiceId(index, 0)
      if (index === 3) {
        try {
          await allocate(nativeRequestId, true)
        } catch (error) {
          failOnceAfterLocalPersist =
            error instanceof Error &&
            error.message.includes('backend acknowledgement failure')
        }
        retryMapping = await allocate(nativeRequestId)
        retrySameMapping = true
      } else {
        await allocate(nativeRequestId)
      }
    }
    const duplicateRequestMapping = await allocate(stableInvoiceId(0, 0))
    let conflictRejected = false
    try {
      acknowledgeInvoice(
        journalKey,
        acknowledgementKey,
        {
          ...duplicateRequestMapping,
          script: `${duplicateRequestMapping.script}00`
        },
        transportPayloads
      )
    } catch (error) {
      conflictRejected =
        error instanceof Error && error.message.includes('conflict')
    }
    if (!conflictRejected)
      throw new Error('conflicting invoice acknowledgement accepted')

    const oldMapping = readInvoiceMappings(journalKey)[0]
    indexer.fund(oldMapping.script, {
      txid: 'a'.repeat(64),
      vout: 0,
      value: 1000,
      script: oldMapping.script,
      isPreconfirmed: false,
      isSpent: false,
      isSwept: false
    })
    await manager.refreshVtxos({scripts: [oldMapping.script]})
    const persistedOldVtxos = await repository.getVtxos(oldMapping.address)
    const oldVtxo = persistedOldVtxos.find(
      vtxo => vtxo.script === oldMapping.script
    )
    if (!oldVtxo) throw new Error('funded invoice VTXO was not persisted')
    await manager.dispose()
    const contracts = await contractRepository.getContracts()
    const persistedState = await repository.getWalletState()
    const persistedMappings = readInvoiceMappings(journalKey)
    const metadata = contracts.map(contract => contract.metadata ?? {})
    const persistedRetryMapping = persistedMappings.find(
      mapping => mapping.nativeRequestId === stableInvoiceId(3, 0)
    )
    const lateObservation = {
      nativeRequestId: oldMapping.nativeRequestId,
      observedScript: oldVtxo.script,
      attributedScript: oldMapping.script,
      outpoint: `${oldVtxo.txid}:${oldVtxo.vout}`,
      afterLogicalExpiry: Date.now() > oldMapping.expiresAt
    }
    if (!persistedState || contracts.length !== invoiceCount) {
      throw new Error('invoice contracts or watermark were not persisted')
    }
    return {
      repositoryName,
      mappings: persistedMappings,
      outstandingUnpaid: invoiceCount - 1,
      indices: persistedMappings.map(mapping => mapping.index),
      uniqueAddresses: new Set(
        persistedMappings.map(mapping => mapping.address)
      ).size,
      uniqueScripts: new Set(persistedMappings.map(mapping => mapping.script))
        .size,
      mappingsFrozen: persistedMappings.every(mapping =>
        Object.isFrozen(mapping)
      ),
      lastIndexUsed: await descriptorProvider.getLastIndexUsed(),
      contractCount: contracts.length,
      metadataHasSource: metadata.some(item => 'source' in item),
      metadataExactlySigningDescriptor: metadata.every(
        item =>
          Object.keys(item).length === 1 &&
          typeof item.signingDescriptor === 'string'
      ),
      duplicateRequestMapping,
      duplicateAckAccepted: true,
      conflictRejected,
      failOnceAfterLocalPersist,
      retrySameMapping:
        retrySameMapping &&
        !!retryMapping &&
        !!persistedRetryMapping &&
        mappingPayload(retryMapping) === mappingPayload(persistedRetryMapping),
      lateObservation,
      transportPayloads
    }
  }

  const contracts = await contractRepository.getContracts()
  const persistedMappings = readInvoiceMappings(journalKey)
  const duplicateRequestMapping = await allocate(stableInvoiceId(0, 0))
  await manager.dispose()
  return {
    repositoryName,
    mappings: persistedMappings,
    outstandingUnpaid: invoiceCount - 1,
    indices: persistedMappings.map(mapping => mapping.index),
    uniqueAddresses: new Set(persistedMappings.map(mapping => mapping.address))
      .size,
    uniqueScripts: new Set(persistedMappings.map(mapping => mapping.script))
      .size,
    mappingsFrozen: persistedMappings.every(mapping =>
      Object.isFrozen(mapping)
    ),
    lastIndexUsed: await descriptorProvider.getLastIndexUsed(),
    contractCount: contracts.length,
    metadataHasSource: contracts.some(
      contract => 'source' in (contract.metadata ?? {})
    ),
    metadataExactlySigningDescriptor: contracts.every(
      contract =>
        Object.keys(contract.metadata ?? {}).length === 1 &&
        typeof contract.metadata?.signingDescriptor === 'string'
    ),
    duplicateRequestMapping,
    duplicateAckAccepted: true,
    conflictRejected: false,
    failOnceAfterLocalPersist: true,
    retrySameMapping: true,
    lateObservation: {
      nativeRequestId: stableInvoiceId(0, 0),
      observedScript: persistedMappings[0].script,
      attributedScript: persistedMappings[0].script,
      outpoint: 'a'.repeat(64) + ':0',
      afterLogicalExpiry: true
    },
    transportPayloads
  }
}

Object.assign(window, {
  arkadeRepositoryName: repositoryNameFor,
  runArkadeBip39Proof: runProof,
  runArkadeRegtestProof: runRegtestProof,
  runArkadeInvoiceAllocatorProof: runInvoiceAllocatorProof
})
