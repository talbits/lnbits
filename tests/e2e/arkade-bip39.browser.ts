import {
  CSVMultisigTapscript,
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

const isolatedWalletProviders = (
  networkName: 'regtest',
  serverPubKey: Uint8Array,
  indexer: IsolatedIndexer
) => {
  const network = getNetwork(networkName)
  const csvTimelock = {value: 144n, type: 'blocks' as const}
  const forfeitScript = new DefaultVtxo.Script({
    pubKey: serverPubKey,
    serverPubKey,
    csvTimelock
  })
  return {
    arkProvider: {
      getInfo: async () => ({
        boardingExitDelay: 288n,
        checkpointTapscript: toHex(
          CSVMultisigTapscript.encode({
            timelock: {value: 4096n, type: 'blocks'},
            pubkeys: [serverPubKey]
          }).script
        ),
        deprecatedSigners: [],
        digest: 'isolated-invoice-proof',
        dust: 330n,
        fees: {intentFee: {}, txFeeRate: '0'},
        forfeitAddress: forfeitScript.onchainAddress(network),
        forfeitPubkey: toHex(serverPubKey),
        network: networkName,
        serviceStatus: {},
        sessionDuration: 3600n,
        signerPubkey: toHex(serverPubKey),
        unilateralExitDelay: 144n,
        utxoMaxAmount: -1n,
        utxoMinAmount: 0n,
        version: 'isolated-invoice-proof',
        vtxoMaxAmount: -1n,
        vtxoMinAmount: 0n
      }),
      onServerInfoChanged: () => () => {},
      getEventStream: async function* () {},
      getTransactionsStream: async function* () {}
    },
    indexerProvider: indexer,
    onchainProvider: {getCoins: async () => []}
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
  const serverPubKey = fromHex(
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  )
  const indexer = new IsolatedIndexer()
  const providers = isolatedWalletProviders(networkName, serverPubKey, indexer)
  const wallet = await Wallet.create({
    identity,
    arkProvider: providers.arkProvider as never,
    indexerProvider: providers.indexerProvider as never,
    onchainProvider: providers.onchainProvider as never,
    storage: {walletRepository: repository, contractRepository},
    walletMode: 'hd',
    settlementConfig: false,
    watcherConfig: {failsafePollIntervalMs: 60 * 60 * 1000}
  })
  const manager = await wallet.getContractManager()
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

    const [newAddress] = await wallet.getNewAddresses({forceNew: true})
    if (!newAddress?.signingDescriptor || !newAddress.contract) {
      throw new Error(
        'SDK allocator did not return a signing descriptor/contract'
      )
    }
    const signingDescriptor = newAddress.signingDescriptor
    const indexMatch = signingDescriptor.match(/\/0\/(\d+)\)$/)
    if (!indexMatch) throw new Error('unparseable signing descriptor')
    const index = Number(indexMatch[1])
    const pubKey = deriveDescriptorLeafPubKey(signingDescriptor)
    const script = newAddress.contract.script
    const address = newAddress.address
    if (!script || newAddress.contract.address !== address) {
      throw new Error('SDK allocator returned mismatched contract data')
    }
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
    const contracts = await contractRepository.getContracts()
    const persistedState = await repository.getWalletState()
    const persistedMappings = readInvoiceMappings(journalKey)
    const invoiceScripts = new Set(
      persistedMappings.map(mapping => mapping.script)
    )
    const invoiceContracts = contracts.filter(contract =>
      invoiceScripts.has(contract.script)
    )
    const persistedRetryMapping = persistedMappings.find(
      mapping => mapping.nativeRequestId === stableInvoiceId(3, 0)
    )
    if (!persistedState || invoiceContracts.length !== invoiceCount) {
      throw new Error('invoice contracts or watermark were not persisted')
    }
    const watermarkBeforeRecovery = await descriptorProvider.getLastIndexUsed()
    await wallet.dispose()
    for (const mapping of persistedMappings) {
      await contractRepository.deleteContract(mapping.script)
    }
    const mappedRowsAfterDeletion = (
      await contractRepository.getContracts({
        script: persistedMappings.map(mapping => mapping.script)
      })
    ).length
    if (mappedRowsAfterDeletion !== 0) {
      throw new Error('invoice contract rows survived simulated loss')
    }

    const reopenedWallet = await Wallet.create({
      identity,
      arkProvider: providers.arkProvider as never,
      indexerProvider: providers.indexerProvider as never,
      onchainProvider: providers.onchainProvider as never,
      storage: {walletRepository: repository, contractRepository},
      walletMode: 'hd',
      settlementConfig: false,
      watcherConfig: {failsafePollIntervalMs: 60 * 60 * 1000}
    })
    const reopenedManager = await reopenedWallet.getContractManager()
    const reopenedDescriptorProvider = await HDDescriptorProvider.create(
      identity,
      repository
    )
    const originalByScript = new Map(
      invoiceContracts.map(contract => [contract.script, contract])
    )
    const mappingByScript = new Map(
      persistedMappings.map(mapping => [mapping.script, mapping])
    )
    const contractProjection = (contract: {
      type: string
      params: Record<string, string>
      script: string
      address: string
      state: string
      metadata?: Record<string, unknown>
    }): string =>
      JSON.stringify({
        type: contract.type,
        params: contract.params,
        script: contract.script,
        address: contract.address,
        state: contract.state,
        metadata: contract.metadata
      })
    const mappedScripts = persistedMappings.map(mapping => mapping.script)
    const recoverMissingContracts = async () => {
      const usedSigningDescriptors =
        await reopenedWallet.getUsedSigningDescriptors()
      const existing = await contractRepository.getContracts({
        script: mappedScripts
      })
      const existingScripts = new Set(existing.map(contract => contract.script))
      const matchedDescriptors = new Map<string, string>()
      let createdCount = 0
      for (const signingDescriptor of usedSigningDescriptors) {
        const pubKey = deriveDescriptorLeafPubKey(signingDescriptor)
        const tapscript = new DefaultVtxo.Script({
          ...reopenedWallet.offchainTapscript.options,
          pubKey
        })
        const script = toHex(tapscript.pkScript)
        const address = tapscript
          .address(reopenedWallet.network.hrp, tapscript.options.serverPubKey)
          .encode()
        const mapping = mappingByScript.get(script)
        if (!mapping || mapping.address !== address) continue
        if (mapping.childXonlyPubkey !== toHex(pubKey)) {
          throw new Error(
            'descriptor matched invoice script with wrong child key'
          )
        }
        matchedDescriptors.set(mapping.script, signingDescriptor)
        if (existingScripts.has(script)) continue
        await reopenedManager.createContract({
          type: 'default',
          params: {
            pubKey: toHex(pubKey),
            serverPubKey: toHex(tapscript.options.serverPubKey),
            csvTimelock: timelockToSequence(
              tapscript.options.csvTimelock
            ).toString()
          },
          script,
          address,
          state: 'active',
          metadata: {signingDescriptor}
        })
        existingScripts.add(script)
        createdCount += 1
      }
      if (matchedDescriptors.size !== persistedMappings.length) {
        throw new Error(
          'used descriptors did not recover every invoice mapping'
        )
      }
      const recoveredContracts = await contractRepository.getContracts({
        script: mappedScripts
      })
      if (recoveredContracts.length !== invoiceCount) {
        throw new Error(
          'recovery did not rebuild every missing invoice contract'
        )
      }
      return {
        usedSigningDescriptors,
        matchedDescriptors,
        recoveredContracts,
        createdCount
      }
    }
    const firstRecovery = await recoverMissingContracts()
    if (firstRecovery.createdCount !== invoiceCount) {
      throw new Error('first recovery did not create exactly the missing rows')
    }
    const {usedSigningDescriptors, matchedDescriptors, recoveredContracts} =
      firstRecovery
    const recoveryExact = persistedMappings.every(mapping => {
      const original = originalByScript.get(mapping.script)
      const recovered = recoveredContracts.find(
        contract => contract.script === mapping.script
      )
      const descriptor = matchedDescriptors.get(mapping.script)
      return (
        !!original &&
        !!recovered &&
        !!descriptor &&
        recovered.script === original.script &&
        recovered.address === original.address &&
        recovered.metadata?.signingDescriptor === descriptor &&
        contractProjection(recovered) === contractProjection(original)
      )
    })
    if (!recoveryExact)
      throw new Error('recovered contract differs from original')

    const secondRecovery = await recoverMissingContracts()
    const recoveredAfterSecondPass = secondRecovery.recoveredContracts
    const secondRecoveryIdempotent =
      secondRecovery.createdCount === 0 &&
      recoveredAfterSecondPass.every(contract => {
        const before = recoveredContracts.find(
          item => item.script === contract.script
        )
        return (
          !!before &&
          contractProjection(contract) === contractProjection(before)
        )
      })
    if (!secondRecoveryIdempotent) {
      throw new Error('second recovery changed contract rows')
    }
    const watermarkAfterRecovery =
      await reopenedDescriptorProvider.getLastIndexUsed()
    if (watermarkAfterRecovery !== watermarkBeforeRecovery) {
      throw new Error('recovery changed the allocation watermark')
    }
    const [nextAddress] = await reopenedWallet.getNewAddresses({forceNew: true})
    if (!nextAddress?.signingDescriptor || !nextAddress.contract) {
      throw new Error('fresh allocation after recovery failed')
    }
    const nextIndexMatch = nextAddress.signingDescriptor.match(/\/0\/(\d+)\)$/)
    if (!nextIndexMatch) throw new Error('unparseable post-recovery descriptor')
    const nextAllocationIndex = Number(nextIndexMatch[1])
    const nextAllocationFresh =
      nextAllocationIndex >
        Math.max(...persistedMappings.map(({index}) => index)) &&
      !invoiceScripts.has(nextAddress.contract.script) &&
      !new Set(persistedMappings.map(mapping => mapping.address)).has(
        nextAddress.address
      )
    if (!nextAllocationFresh) {
      throw new Error('post-recovery allocation reused an invoice artifact')
    }
    indexer.fund(oldMapping.script, {
      txid: 'a'.repeat(64),
      vout: 0,
      value: 1000,
      script: oldMapping.script,
      isPreconfirmed: false,
      isSpent: false,
      isSwept: false
    })
    await reopenedManager.refreshVtxos({scripts: [oldMapping.script]})
    const persistedOldVtxos = await repository.getVtxos(oldMapping.address)
    const oldVtxo = persistedOldVtxos.find(
      vtxo => vtxo.script === oldMapping.script
    )
    if (!oldVtxo)
      throw new Error('funded invoice VTXO was not persisted after recovery')
    const lateObservation = {
      nativeRequestId: oldMapping.nativeRequestId,
      observedScript: oldVtxo.script,
      attributedScript: oldMapping.script,
      outpoint: `${oldVtxo.txid}:${oldVtxo.vout}`,
      afterLogicalExpiry: Date.now() > oldMapping.expiresAt
    }
    await reopenedWallet.dispose()
    const metadata = invoiceContracts.map(contract => contract.metadata ?? {})
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
      lastIndexUsed: watermarkBeforeRecovery,
      contractCount: invoiceContracts.length,
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
      recovery: {
        mappedRowsBeforeDeletion: invoiceContracts.length,
        mappedRowsAfterDeletion,
        usedSigningDescriptorCount: usedSigningDescriptors.length,
        recoveredContractCount: recoveredContracts.length,
        recoveredDescriptorsExact: recoveryExact,
        recoveredScriptsExact: recoveryExact,
        recoveredAddressesExact: recoveryExact,
        recoveredMetadataExact: recoveryExact,
        watermarkUnchanged: watermarkAfterRecovery === watermarkBeforeRecovery,
        secondRecoveryIdempotent,
        nextAllocationIndex,
        nextAllocationFresh
      },
      transportPayloads
    }
  }

  const contracts = await contractRepository.getContracts()
  const persistedMappings = readInvoiceMappings(journalKey)
  const invoiceScripts = new Set(
    persistedMappings.map(mapping => mapping.script)
  )
  const invoiceContracts = contracts.filter(contract =>
    invoiceScripts.has(contract.script)
  )
  const duplicateRequestMapping = await allocate(stableInvoiceId(0, 0))
  await wallet.dispose()
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
    contractCount: invoiceContracts.length,
    metadataHasSource: invoiceContracts.some(
      contract => 'source' in (contract.metadata ?? {})
    ),
    metadataExactlySigningDescriptor: invoiceContracts.every(
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

const runCompleteBrowserLossRecoveryProof = async ({
  mnemonic,
  mappings
}: {
  mnemonic: string
  mappings: InvoiceMapping[]
}): Promise<CompleteLossRecoveryProof> => {
  const priorLocalStorageEntries = localStorage.length
  const priorIndexedDbNames = (await indexedDB.databases())
    .map(database => database.name)
    .filter((name): name is string => typeof name === 'string')
  if (priorLocalStorageEntries || priorIndexedDbNames.length) {
    throw new Error('complete-loss proof requires a fresh browser context')
  }
  if (!mappings.length) throw new Error('public receive mappings are required')

  const mappingSnapshot = JSON.stringify(mappings)
  const publicMappings = mappings.map(mapping => Object.freeze({...mapping}))
  const firstMapping = publicMappings[0]
  if (
    firstMapping.network !== 'regtest' ||
    !/^[0-9a-f]{64}$/.test(firstMapping.serverPubkey) ||
    publicMappings.some(
      mapping =>
        mapping.network !== firstMapping.network ||
        mapping.serverUrl !== firstMapping.serverUrl ||
        mapping.serverPubkey !== firstMapping.serverPubkey ||
        !Number.isSafeInteger(mapping.index) ||
        mapping.index < 0
    ) ||
    new Set(publicMappings.map(mapping => mapping.index)).size !==
      publicMappings.length
  ) {
    throw new Error('public receive mappings have inconsistent server data')
  }

  const repositoryName = `lnbits-arkade-complete-loss-${crypto.randomUUID()}`
  const repository = new IndexedDBWalletRepository(repositoryName)
  const contractRepository = new IndexedDBContractRepository(repositoryName)
  const freshWalletRepository = (await repository.getWalletState()) === null
  const freshContractRepository =
    (await contractRepository.getContracts()).length === 0
  if (!freshWalletRepository || !freshContractRepository) {
    throw new Error('complete-loss proof repositories were not empty')
  }

  const identity = MnemonicIdentity.fromMnemonic(mnemonic, {isMainnet: false})
  const indexer = new IsolatedIndexer()
  const providers = isolatedWalletProviders(
    'regtest',
    fromHex(firstMapping.serverPubkey),
    indexer
  )
  const wallet = await Wallet.create({
    identity,
    arkProvider: providers.arkProvider as never,
    indexerProvider: providers.indexerProvider as never,
    onchainProvider: providers.onchainProvider as never,
    storage: {walletRepository: repository, contractRepository},
    walletMode: 'hd',
    settlementConfig: false,
    watcherConfig: {failsafePollIntervalMs: 60 * 60 * 1000}
  })
  const manager = await wallet.getContractManager()
  const highestMappedIndex = Math.max(
    ...publicMappings.map(mapping => mapping.index)
  )
  const descriptorIndex = (descriptor: string): number => {
    const match = descriptor.match(/\/0\/(\d+)\)$/)
    if (!match) throw new Error('unparseable recovered signing descriptor')
    return Number(match[1])
  }
  const enumerateThroughHighestMapping = async () => {
    const currentDescriptor = await wallet.getCurrentSigningDescriptor()
    const currentIndex = currentDescriptor
      ? descriptorIndex(currentDescriptor)
      : -1
    return wallet.getUsedSigningDescriptors({
      lookAhead: Math.max(0, highestMappedIndex - currentIndex)
    })
  }
  const deriveMappedDescriptors = async () => {
    const descriptors = await enumerateThroughHighestMapping()
    const derivedByIndex = new Map(
      descriptors.map(descriptor => {
        const pubKey = deriveDescriptorLeafPubKey(descriptor)
        const tapscript = new DefaultVtxo.Script({
          ...wallet.offchainTapscript.options,
          pubKey
        })
        return [
          descriptorIndex(descriptor),
          {
            descriptor,
            pubKey,
            script: toHex(tapscript.pkScript),
            address: tapscript
              .address(wallet.network.hrp, tapscript.options.serverPubKey)
              .encode(),
            tapscript
          }
        ] as const
      })
    )
    const recovered = publicMappings.map(mapping => ({
      mapping,
      derived: derivedByIndex.get(mapping.index)
    }))
    return {descriptors, recovered}
  }
  const recover = async () => {
    const {descriptors, recovered} = await deriveMappedDescriptors()
    const existingScripts = new Set(
      (
        await contractRepository.getContracts({
          script: publicMappings.map(mapping => mapping.script)
        })
      ).map(contract => contract.script)
    )
    let createdCount = 0
    for (const {mapping, derived} of recovered) {
      if (
        !derived ||
        derived.script !== mapping.script ||
        derived.address !== mapping.address ||
        toHex(derived.pubKey) !== mapping.childXonlyPubkey
      ) {
        throw new Error(`public mapping ${mapping.index} did not rederive`)
      }
      if (existingScripts.has(mapping.script)) continue
      await manager.createContract({
        type: 'default',
        params: {
          pubKey: toHex(derived.pubKey),
          serverPubKey: toHex(derived.tapscript.options.serverPubKey),
          csvTimelock: timelockToSequence(
            derived.tapscript.options.csvTimelock
          ).toString()
        },
        script: derived.script,
        address: derived.address,
        state: 'active',
        metadata: {signingDescriptor: derived.descriptor}
      })
      existingScripts.add(mapping.script)
      createdCount += 1
    }
    const highest = recovered.find(
      item => item.mapping.index === highestMappedIndex
    )?.derived
    if (!highest) throw new Error('highest public mapping did not rederive')
    await wallet.advanceSigningDescriptorWatermark(highest.descriptor)
    return {descriptors, recovered, createdCount}
  }

  const watermarkBeforeRecovery = await wallet.getCurrentSigningDescriptor()
  if (!watermarkBeforeRecovery) throw new Error('fresh wallet has no watermark')
  const firstRecovery = await recover()
  const watermarkAfterRecovery = await wallet.getCurrentSigningDescriptor()
  if (!watermarkAfterRecovery) throw new Error('recovery did not set watermark')
  const recoveredContracts = await contractRepository.getContracts({
    script: publicMappings.map(mapping => mapping.script)
  })
  const contractByScript = new Map(
    recoveredContracts.map(contract => [contract.script, contract])
  )
  const recoveredDescriptorsExact = firstRecovery.recovered.every(
    ({mapping, derived}) =>
      !!derived && descriptorIndex(derived.descriptor) === mapping.index
  )
  const recoveredScriptsExact = firstRecovery.recovered.every(
    ({mapping, derived}) => derived?.script === mapping.script
  )
  const recoveredAddressesExact = firstRecovery.recovered.every(
    ({mapping, derived}) => derived?.address === mapping.address
  )
  const recoveredChildKeysExact = firstRecovery.recovered.every(
    ({mapping, derived}) =>
      !!derived && toHex(derived.pubKey) === mapping.childXonlyPubkey
  )
  const recoveredMetadataExact = firstRecovery.recovered.every(
    ({mapping, derived}) => {
      const metadata = contractByScript.get(mapping.script)?.metadata
      return (
        !!derived &&
        Object.keys(metadata ?? {}).length === 1 &&
        metadata?.signingDescriptor === derived.descriptor
      )
    }
  )

  const secondRecovery = await recover()
  const watermarkAfterSecondRecovery =
    await wallet.getCurrentSigningDescriptor()
  const [nextAddress] = await wallet.getNewAddresses({forceNew: true})
  if (!nextAddress?.signingDescriptor || !nextAddress.contract) {
    throw new Error('fresh allocation after complete-loss recovery failed')
  }
  const nextAllocationIndex = descriptorIndex(nextAddress.signingDescriptor)
  const mappedScripts = new Set(publicMappings.map(mapping => mapping.script))
  const mappedAddresses = new Set(
    publicMappings.map(mapping => mapping.address)
  )
  const nextAllocationFresh =
    nextAllocationIndex > highestMappedIndex &&
    !mappedScripts.has(nextAddress.contract.script) &&
    !mappedAddresses.has(nextAddress.address)

  const highMapping = publicMappings.find(
    mapping => mapping.index === highestMappedIndex
  )!
  indexer.fund(highMapping.script, {
    txid: 'b'.repeat(64),
    vout: 1,
    value: highMapping.amountSat,
    script: highMapping.script,
    isPreconfirmed: false,
    isSpent: false,
    isSwept: false
  })
  await manager.refreshVtxos({scripts: [highMapping.script]})
  const highVtxo = (await repository.getVtxos(highMapping.address)).find(
    vtxo => vtxo.script === highMapping.script
  )
  if (!highVtxo) throw new Error('recovered high mapping missed funded VTXO')

  await wallet.dispose()
  return {
    repositoryName,
    priorLocalStorageEntries,
    priorIndexedDbNames,
    freshWalletRepository,
    freshContractRepository,
    mappingsUnchanged: JSON.stringify(publicMappings) === mappingSnapshot,
    publicMappingCount: publicMappings.length,
    enumeratedDescriptorCount: firstRecovery.descriptors.length,
    firstRecoveryCreatedCount: firstRecovery.createdCount,
    recoveredContractCount: recoveredContracts.length,
    recoveredDescriptorsExact,
    recoveredScriptsExact,
    recoveredAddressesExact,
    recoveredChildKeysExact,
    recoveredMetadataExact,
    highestMappedIndex,
    watermarkBeforeRecoveryIndex: descriptorIndex(watermarkBeforeRecovery),
    watermarkAfterRecoveryIndex: descriptorIndex(watermarkAfterRecovery),
    secondRecoveryCreatedCount: secondRecovery.createdCount,
    secondRecoveryWatermarkUnchanged:
      watermarkAfterSecondRecovery === watermarkAfterRecovery,
    nextAllocationIndex,
    nextAllocationFresh,
    lateObservation: {
      nativeRequestId: highMapping.nativeRequestId,
      mappingIndex: highMapping.index,
      observedScript: highVtxo.script,
      attributedScript: highMapping.script,
      outpoint: `${highVtxo.txid}:${highVtxo.vout}`
    }
  }
}

Object.assign(window, {
  arkadeRepositoryName: repositoryNameFor,
  runArkadeBip39Proof: runProof,
  runArkadeRegtestProof: runRegtestProof,
  runArkadeInvoiceAllocatorProof: runInvoiceAllocatorProof,
  runArkadeCompleteBrowserLossRecoveryProof: runCompleteBrowserLossRecoveryProof
})
