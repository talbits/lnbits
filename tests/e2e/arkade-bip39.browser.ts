import {
  getNetwork,
  HDDescriptorProvider,
  IndexedDBContractRepository,
  IndexedDBWalletRepository,
  MnemonicIdentity,
  Wallet
} from '@arkade-os/sdk'

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

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
}

type RegtestMode = 'start' | 'after-first' | 'final' | 'dispose' | 'restore'

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
  installationId,
  accountId,
  networkName = 'regtest',
  schemaVersion = '1',
  arkServerUrl,
  esploraUrl,
  restore = false,
  mode = restore ? 'restore' : 'start',
  receives = []
}: RepositoryInputs & {
  mnemonic: string
  arkServerUrl: string
  esploraUrl: string
  restore?: boolean
  mode?: RegtestMode
  receives?: Receive[]
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
    const identity = MnemonicIdentity.fromMnemonic(mnemonic, {isMainnet: false})
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
    const first: Receive = {
      walletId: 'wallet-a',
      address: await wallet.getAddress(),
      script: wallet.defaultContractScript
    }
    liveWallet = {
      wallet,
      walletRepository,
      contractRepository,
      repositoryName,
      identity,
      receives: [first]
    }
    return snapshotRegtestWallet(liveWallet, liveWallet.receives)
  }

  if (mode === 'after-first' || mode === 'final' || mode === 'dispose') {
    if (!liveWallet) {
      throw new Error(`${mode} requires the live Arkade wallet`)
    }
    if (mode === 'after-first') {
      const first = liveWallet.receives[0]
      const deadline = Date.now() + 30_000
      while ((await liveWallet.wallet.getAddress()) === first.address) {
        if (Date.now() >= deadline) {
          throw new Error('Arkade receive rotation did not produce wallet-b')
        }
        await new Promise(resolve => setTimeout(resolve, 250))
      }
      const second: Receive = {
        walletId: 'wallet-b',
        address: await liveWallet.wallet.getAddress(),
        script: liveWallet.wallet.defaultContractScript
      }
      if (second.script === first.script) {
        throw new Error('Arkade receive rotation reused wallet-a script')
      }
      liveWallet.receives = [first, second]
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
  const identity = MnemonicIdentity.fromMnemonic(mnemonic, {isMainnet: false})
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

Object.assign(window, {
  arkadeRepositoryName: repositoryNameFor,
  runArkadeBip39Proof: runProof,
  runArkadeRegtestProof: runRegtestProof
})
