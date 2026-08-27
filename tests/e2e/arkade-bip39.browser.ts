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

const runRegtestProof = async ({
  mnemonic,
  installationId,
  accountId,
  networkName = 'regtest',
  schemaVersion = '1',
  arkServerUrl,
  esploraUrl,
  restore = false
}: RepositoryInputs & {
  mnemonic: string
  arkServerUrl: string
  esploraUrl: string
  restore?: boolean
}) => {
  const repositoryName = repositoryNameFor({
    installationId,
    accountId,
    networkName,
    schemaVersion
  })
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
    if (restore) {
      await wallet.restore({gapLimit: 5})
    }
    return {
      repositoryName,
      identityDescriptor: identity.descriptor,
      address: await wallet.getAddress(),
      boardingAddress: await wallet.getBoardingAddress(),
      balance: await wallet.getBalance(),
      persistedState: await walletRepository.getWalletState(),
      contracts: await contractRepository.getContracts()
    }
  } finally {
    await wallet.dispose()
  }
}

Object.assign(window, {
  arkadeRepositoryName: repositoryNameFor,
  runArkadeBip39Proof: runProof,
  runArkadeRegtestProof: runRegtestProof
})
