import {
  ArkAddress,
  DefaultVtxo,
  IndexedDBContractRepository,
  IndexedDBWalletRepository,
  MnemonicIdentity,
  Wallet,
  buildOffchainTx,
  deriveDescriptorLeafPubKey,
  isSpendable,
  selectVirtualCoins
} from '@arkade-os/sdk'
import {generateMnemonic, validateMnemonic} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'

const DB_NAME = 'lnbits-arkade-vault-v1'
const STORE_NAME = 'vaults'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600_000
const IDLE_TIMEOUT_MS = 15 * 60 * 1000
declare const ARKADE_ENROLLMENT_TEST: boolean
const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/
const NETWORK = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/
const IDENTITY_DESCRIPTOR =
  /^tr\(\[[0-9a-f]{8}\/86'\/[01]'\/0'\](?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+\/0\/\*\)$/
const PASSWORD_MIN_LENGTH = 12
const MAX_CIPHERTEXT_BYTES = 1024 * 1024
const RECEIVE_JOURNAL_PREFIX = 'lnbits-arkade-receive-v1'
const OUTGOING_JOURNAL_PREFIX = 'lnbits-arkade-outgoing-v1'
const OUTGOING_JOURNAL_VERSION = 1
const MAX_OUTGOING_JOURNAL_RECORDS = 32
const MAX_OUTGOING_JOURNAL_BYTES = 128 * 1024
const OUTGOING_PHASES = new Set([
  'prepared',
  'authorization_unknown',
  'submitted',
  'reconciliation_required'
])
const RECORD_FIELDS = new Set([
  'accountId',
  'version',
  'kdf',
  'iterations',
  'salt',
  'iv',
  'ciphertext',
  'tagLength',
  'network',
  'identityXonlyPubkey',
  'idempotencyKey'
])

type VaultRecord = {
  accountId: string
  version?: number
  kdf?: 'PBKDF2-HMAC-SHA256'
  iterations?: number
  salt?: ArrayBuffer
  iv?: ArrayBuffer
  ciphertext?: ArrayBuffer
  tagLength?: 128
  network?: string
  identityXonlyPubkey?: string
  idempotencyKey: string
}

let identity: MnemonicIdentity | null = null
let activeBinding: any = null
let idleTimer: number | undefined
let allocationWallet: Awaited<ReturnType<typeof Wallet.create>> | null = null
let allocationWalletKey = ''
let unlockGeneration = 0

type ReceiveMapping = Readonly<{
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
  exitTapleaf: string
  exitControlBlock: string
}>

type OutgoingChange = Readonly<{
  index: number
  address: string
  script: string
  child_xonly_pubkey: string
  amount_sat: number
  exit_tapleaf: string
  exit_control_block: string
}>

type OutgoingPrepared = Readonly<{
  intentId: string
  accountId: string
  walletId: string
  amountSat: number
  destination: string
  destinationScript: string
  inputs: ReadonlyArray<{
    txid: string
    vout: number
    amount_sat: number
    script: string
  }>
  change: OutgoingChange | null
  previewCommitment: string
}>

type OutgoingJournalInput = Readonly<{
  txid: string
  vout: number
  amount_sat: number
  script: string
}>

type OutgoingJournalChange = Readonly<{
  index: number
  script: string
  amount_sat: number
}>

type OutgoingJournal = Readonly<{
  version: 1
  intentId: string
  accountId: string
  walletId: string
  amountSat: number
  destination: string
  destinationScript: string
  inputs: ReadonlyArray<OutgoingJournalInput>
  change: OutgoingJournalChange | null
  previewCommitment: string
  network: string
  serverUrl: string
  serverPubkey: string
  expiresAt: number
  phase:
    | 'prepared'
    | 'authorization_unknown'
    | 'submitted'
    | 'reconciliation_required'
}>

type ArkadeWallet = Awaited<ReturnType<typeof Wallet.create>>
type SpendableVtxo = Awaited<
  ReturnType<ArkadeWallet['getSpendableVtxos']>
>[number]

type OutgoingPlan = {
  publicPlan: OutgoingPrepared
  wallet: ArkadeWallet
  inputs: SpendableVtxo[]
  outputs: {script: Uint8Array; amount: bigint}[]
  generation: number
  accountId: string
  intentId: string
  walletId: string
  amountMsat: number
  expiresAt: number
  destination: string
  destinationScript: string
  change: OutgoingChange | null
  previewCommitment: string
  bindingFingerprint: string
}

const outgoingPlans = new WeakMap<object, OutgoingPlan>()
const outgoingRecoveries = new Map<string, Promise<any>>()

class ArkadeOutgoingReconciliationError extends Error {
  readonly reconciliationRequired = true
  readonly status: 'authorization_unknown' | 'submitted'

  constructor(intentId: string, status: 'authorization_unknown' | 'submitted') {
    super(`Arkade outgoing ${intentId} requires reconciliation`)
    this.name = 'ArkadeOutgoingReconciliationError'
    this.status = status
  }
}

const bytesToHex = (bytes: Uint8Array) =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

const fromHex = (value: string) =>
  Uint8Array.from(value.match(/../g) || [], pair => parseInt(pair, 16))

const randomHex = (bytes: number) =>
  bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))

const receiveJournalKey = (accountId: string) =>
  `${RECEIVE_JOURNAL_PREFIX}:${location.origin}:${accountId}`

const readReceiveJournal = (accountId: string): ReceiveMapping[] => {
  const value = localStorage.getItem(receiveJournalKey(accountId))
  if (!value) return []
  const mappings = JSON.parse(value)
  if (!Array.isArray(mappings)) throw new Error('receive journal corrupt')
  return mappings
}

const persistReceiveMapping = (
  accountId: string,
  mapping: ReceiveMapping
): ReceiveMapping => {
  const mappings = readReceiveJournal(accountId)
  const existing = mappings.find(
    item => item.nativeRequestId === mapping.nativeRequestId
  )
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(mapping))
      throw new Error('receive allocation conflict')
    return existing
  }
  mappings.push(mapping)
  localStorage.setItem(receiveJournalKey(accountId), JSON.stringify(mappings))
  return mapping
}

const outgoingJournalKey = (accountId: string) =>
  `${OUTGOING_JOURNAL_PREFIX}:${location.origin}:${accountId}`

const isHex = (value: unknown, min = 2, max = 4096): value is string =>
  typeof value === 'string' &&
  value.length >= min &&
  value.length <= max &&
  value.length % 2 === 0 &&
  /^[0-9a-f]+$/i.test(value)

const strictOutgoingJournal = (value: unknown): value is OutgoingJournal[] => {
  if (!Array.isArray(value) || value.length > MAX_OUTGOING_JOURNAL_RECORDS)
    return false
  return value.every(record => {
    if (!record || typeof record !== 'object') return false
    const item = record as any
    if (
      Object.keys(item).sort().join(',') !==
      [
        'accountId',
        'amountSat',
        'change',
        'destination',
        'destinationScript',
        'expiresAt',
        'inputs',
        'intentId',
        'network',
        'phase',
        'previewCommitment',
        'serverPubkey',
        'serverUrl',
        'version',
        'walletId'
      ]
        .sort()
        .join(',')
    )
      return false
    if (
      item.version !== OUTGOING_JOURNAL_VERSION ||
      !HEX32.test(item.intentId) ||
      typeof item.accountId !== 'string' ||
      typeof item.walletId !== 'string' ||
      !Number.isSafeInteger(item.amountSat) ||
      item.amountSat <= 0 ||
      typeof item.destination !== 'string' ||
      !item.destination ||
      !isHex(item.destinationScript) ||
      !Array.isArray(item.inputs) ||
      item.inputs.length < 1 ||
      item.inputs.length > 100 ||
      typeof item.previewCommitment !== 'string' ||
      !item.previewCommitment ||
      item.previewCommitment.length > 64 * 1024 ||
      !NETWORK.test(item.network) ||
      typeof item.serverUrl !== 'string' ||
      !item.serverUrl ||
      !HEX64.test(item.serverPubkey) ||
      !Number.isSafeInteger(item.expiresAt) ||
      item.expiresAt < 0 ||
      !OUTGOING_PHASES.has(item.phase)
    )
      return false
    if (
      !item.inputs.every(
        (input: any) =>
          input &&
          Object.keys(input).sort().join(',') ===
            'amount_sat,script,txid,vout' &&
          HEX64.test(input.txid) &&
          Number.isSafeInteger(input.vout) &&
          input.vout >= 0 &&
          Number.isSafeInteger(input.amount_sat) &&
          input.amount_sat > 0 &&
          isHex(input.script)
      )
    )
      return false
    if (
      new Set(item.inputs.map((input: any) => `${input.txid}:${input.vout}`))
        .size !== item.inputs.length
    )
      return false
    return (
      item.change === null ||
      (item.change &&
        Object.keys(item.change).sort().join(',') ===
          'amount_sat,index,script' &&
        Number.isSafeInteger(item.change.index) &&
        item.change.index >= 0 &&
        Number.isSafeInteger(item.change.amount_sat) &&
        item.change.amount_sat > 0 &&
        isHex(item.change.script))
    )
  })
}

const readOutgoingJournal = (accountId: string): OutgoingJournal[] => {
  const value = localStorage.getItem(outgoingJournalKey(accountId))
  if (!value) return []
  if (new TextEncoder().encode(value).byteLength > MAX_OUTGOING_JOURNAL_BYTES)
    throw new Error('outgoing journal too large')
  let journal: unknown
  try {
    journal = JSON.parse(value)
  } catch {
    throw new Error('outgoing journal corrupt')
  }
  if (!strictOutgoingJournal(journal))
    throw new Error('outgoing journal corrupt')
  return journal
}

const journalMatchesBinding = (
  record: OutgoingJournal,
  accountId: string,
  binding: any
) =>
  record.accountId === accountId &&
  binding?.account_id === accountId &&
  record.network === binding?.network &&
  record.serverUrl === binding?.server_url &&
  record.serverPubkey === binding?.server_pubkey

const persistOutgoingJournal = (record: OutgoingJournal) => {
  const journal = readOutgoingJournal(record.accountId)
  const existingIndex = journal.findIndex(
    item => item.intentId === record.intentId
  )
  if (existingIndex >= 0) {
    const existing = journal[existingIndex]
    const {phase: _oldPhase, ...oldImmutable} = existing
    const {phase: _newPhase, ...newImmutable} = record
    if (JSON.stringify(oldImmutable) !== JSON.stringify(newImmutable))
      throw new Error('outgoing journal conflict')
    journal[existingIndex] = record
  } else {
    if (journal.length >= MAX_OUTGOING_JOURNAL_RECORDS)
      throw new Error('outgoing journal is full')
    journal.push(record)
  }
  const serialized = JSON.stringify(journal)
  if (
    new TextEncoder().encode(serialized).byteLength > MAX_OUTGOING_JOURNAL_BYTES
  )
    throw new Error('outgoing journal too large')
  localStorage.setItem(outgoingJournalKey(record.accountId), serialized)
  return record
}

const updateOutgoingJournalPhase = (
  accountId: string,
  intentId: string,
  phase: OutgoingJournal['phase']
) => {
  const journal = readOutgoingJournal(accountId)
  const index = journal.findIndex(item => item.intentId === intentId)
  if (index < 0) throw new Error('outgoing journal entry missing')
  persistOutgoingJournal({...journal[index], phase})
}

const removeOutgoingJournal = (accountId: string, intentId: string) => {
  const journal = readOutgoingJournal(accountId).filter(
    item => item.intentId !== intentId
  )
  localStorage.setItem(outgoingJournalKey(accountId), JSON.stringify(journal))
}

const reconcileTerminalOutgoing = async (
  accountId: string,
  journal: OutgoingJournal[]
) => {
  for (const record of journal) {
    try {
      const response = (await LNbits.api.arkadeOutgoingIntent(record.intentId))
        .data
      if (
        (response.status === 'released' &&
          releasedOutgoingJournalMatches(record, response, activeBinding)) ||
        (response.status === 'settled' &&
          outgoingJournalResponseMatches(record, response, activeBinding))
      )
        removeOutgoingJournal(accountId, record.intentId)
    } catch {
      // Keep records that cannot be independently reconciled.
    }
  }
  return readOutgoingJournal(accountId)
}

const expirySeconds = (value: unknown): number => {
  const seconds =
    typeof value === 'number' ? value : Date.parse(String(value)) / 1000
  if (!Number.isSafeInteger(seconds) || seconds < 0)
    throw new Error('invalid receive expiry')
  return seconds
}

const validateBinding = (
  value: any,
  accountId: string,
  expected?: {
    idempotencyKey?: string
    identityXonlyPubkey?: string
    identityDescriptor?: string
    previous?: any
  }
) => {
  if (
    !value ||
    value.account_id !== accountId ||
    !HEX32.test(value.enrollment_id || '') ||
    !HEX32.test(value.idempotency_key || '') ||
    !NETWORK.test(value.network || '') ||
    typeof value.server_url !== 'string' ||
    !value.server_url ||
    !HEX64.test(value.server_pubkey || '') ||
    (expected?.idempotencyKey &&
      value.idempotency_key !== expected.idempotencyKey)
  )
    throw new Error('invalid enrollment response')
  if (value.state === 'pending') {
    if (
      !HEX64.test(value.nonce || '') ||
      !Number.isSafeInteger(value.expires_at) ||
      value.expires_at <= Math.floor(Date.now() / 1000)
    )
      throw new Error('invalid enrollment response')
  } else if (
    value.state === 'ready' &&
    (!HEX64.test(value.identity_xonly_pubkey || '') ||
      (value.identity_descriptor != null &&
        !IDENTITY_DESCRIPTOR.test(value.identity_descriptor)) ||
      (expected?.identityXonlyPubkey &&
        value.identity_xonly_pubkey !== expected.identityXonlyPubkey) ||
      (expected?.identityDescriptor &&
        value.identity_descriptor !== expected.identityDescriptor))
  )
    throw new Error('invalid enrollment response')
  else if (value.state !== 'ready')
    throw new Error('invalid enrollment response')
  if (expected?.previous) {
    for (const field of [
      'enrollment_id',
      'network',
      'server_url',
      'server_pubkey'
    ])
      if (value[field] !== expected.previous[field])
        throw new Error('enrollment changed')
  }
  return value
}

const openVault = (): Promise<IDBDatabase> =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () =>
      request.result.createObjectStore(STORE_NAME, {keyPath: 'accountId'})
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error('vault unavailable'))
  })

const readVault = async (accountId: string): Promise<VaultRecord | null> => {
  const db = await openVault()
  return new Promise((resolve, reject) => {
    const request = db
      .transaction(STORE_NAME)
      .objectStore(STORE_NAME)
      .get(accountId)
    request.onsuccess = () => resolve(request.result || null)
    request.onerror = () => reject(new Error('vault unavailable'))
  })
}

const writeVault = async (record: VaultRecord) => {
  const db = await openVault()
  return new Promise<void>((resolve, reject) => {
    const request = db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(record)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(new Error('vault unavailable'))
  })
}

const getIdempotencyKey = async (accountId: string) => {
  const current = await readVault(accountId)
  if (current?.idempotencyKey && HEX32.test(current.idempotencyKey))
    return current.idempotencyKey
  if (current) throw new Error('vault metadata corrupt')
  const idempotencyKey = randomHex(16)
  await writeVault({accountId, idempotencyKey})
  return idempotencyKey
}

const aad = (accountId: string, network: string, xonly: string) =>
  new TextEncoder().encode(
    ['lnbits-arkade-vault-v1', location.origin, accountId, network, xonly].join(
      '\n'
    )
  )

const passwordKey = async (
  password: string,
  salt: ArrayBuffer,
  iterations = PBKDF2_ITERATIONS,
  usages: KeyUsage[] = ['encrypt', 'decrypt']
) => {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    {name: 'PBKDF2', salt, iterations, hash: 'SHA-256'},
    material,
    {name: 'AES-GCM', length: 256},
    false,
    usages
  )
}

const strictRecord = (
  record: VaultRecord | null
): record is Required<
  Pick<
    VaultRecord,
    | 'version'
    | 'kdf'
    | 'iterations'
    | 'salt'
    | 'iv'
    | 'ciphertext'
    | 'tagLength'
    | 'network'
    | 'identityXonlyPubkey'
    | 'idempotencyKey'
  >
> &
  VaultRecord =>
  !!record &&
  Object.keys(record).every(key => RECORD_FIELDS.has(key)) &&
  typeof record.accountId === 'string' &&
  record.version === VAULT_VERSION &&
  record.kdf === 'PBKDF2-HMAC-SHA256' &&
  Number.isInteger(record.iterations) &&
  record.iterations === PBKDF2_ITERATIONS &&
  record.tagLength === 128 &&
  record.salt instanceof ArrayBuffer &&
  record.salt.byteLength >= 16 &&
  record.salt.byteLength <= 64 &&
  record.iv instanceof ArrayBuffer &&
  record.iv.byteLength === 12 &&
  record.ciphertext instanceof ArrayBuffer &&
  record.ciphertext.byteLength >= 17 &&
  record.ciphertext.byteLength <= MAX_CIPHERTEXT_BYTES &&
  typeof record.network === 'string' &&
  NETWORK.test(record.network) &&
  HEX64.test(record.identityXonlyPubkey || '') &&
  HEX32.test(record.idempotencyKey)

const makeIdentity = (mnemonic: string, network: string) => {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('invalid mnemonic')
  return MnemonicIdentity.fromMnemonic(mnemonic, {
    isMainnet: network === 'bitcoin'
  })
}

const encryptVault = async (
  accountId: string,
  mnemonic: string,
  password: string,
  network: string,
  xonly: string,
  idempotencyKey: string
) => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await passwordKey(password, salt.buffer)
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128,
      additionalData: aad(accountId, network, xonly)
    },
    key,
    new TextEncoder().encode(mnemonic)
  )
  await writeVault({
    accountId,
    version: VAULT_VERSION,
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: PBKDF2_ITERATIONS,
    salt: salt.buffer,
    iv: iv.buffer,
    ciphertext,
    tagLength: 128,
    network,
    identityXonlyPubkey: xonly,
    idempotencyKey
  })
}

const decryptVault = async (
  accountId: string,
  password: string,
  record: VaultRecord,
  binding: any
) => {
  if (!strictRecord(record)) throw new Error('invalid vault')
  if (record.accountId !== accountId || !binding?.network)
    throw new Error('vault mismatch')
  if (record.network !== binding.network) throw new Error('vault mismatch')
  const xonly =
    binding.state === 'ready'
      ? binding.identity_xonly_pubkey
      : record.identityXonlyPubkey
  if (!HEX64.test(xonly || '')) throw new Error('vault mismatch')
  if (binding.state === 'ready' && record.identityXonlyPubkey !== xonly)
    throw new Error('vault mismatch')
  const key = await passwordKey(password, record.salt, record.iterations, [
    'decrypt'
  ])
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: record.iv,
      tagLength: 128,
      additionalData: aad(accountId, binding.network, xonly)
    },
    key,
    record.ciphertext
  )
  const mnemonic = new TextDecoder()
    .decode(plaintext)
    .trim()
    .split(/\s+/)
    .join(' ')
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('invalid mnemonic')
  return mnemonic
}

const statement = (challenge: any, xonly: string, descriptor: string) =>
  [
    `action=lnbits-arkade-enrollment-v1`,
    `account_id=${challenge.account_id}`,
    `enrollment_id=${challenge.enrollment_id}`,
    `idempotency_key=${challenge.idempotency_key}`,
    `nonce=${challenge.nonce}`,
    `expires_at=${challenge.expires_at}`,
    `network=${challenge.network}`,
    `server_url=${challenge.server_url}`,
    `server_pubkey=${challenge.server_pubkey}`,
    'identity_kind=mnemonic_hd',
    `identity_descriptor=${descriptor}`,
    `identity_xonly_pubkey=${xonly}`,
    'backup_acknowledged=1'
  ].join('\n')

const digest = async (value: string) =>
  new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  )

const receiveStatement = (mapping: ReceiveMapping): string =>
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

const getAllocationWallet = async (accountId: string, binding: any) => {
  if (!identity || binding?.state !== 'ready')
    throw new Error('wallet is locked')
  const key = JSON.stringify([
    location.origin,
    accountId,
    binding.network,
    binding.server_url
  ])
  if (allocationWallet && allocationWalletKey === key) return allocationWallet
  if (allocationWallet) {
    await allocationWallet.dispose()
    allocationWallet = null
  }
  const repositoryName = `lnbits-arkade-${key}`
  allocationWallet = await Wallet.create({
    identity,
    arkServerUrl: binding.server_url,
    arkServerPublicKey: binding.server_pubkey,
    storage: {
      walletRepository: new IndexedDBWalletRepository(repositoryName),
      contractRepository: new IndexedDBContractRepository(repositoryName)
    },
    walletMode: 'hd',
    settlementConfig: false
  })
  allocationWalletKey = key
  return allocationWallet
}

const outgoingWallet = async (accountId: string, binding: any) => {
  const testWallet = ARKADE_ENROLLMENT_TEST
    ? (window as any).__ARKADE_ENROLLMENT_TEST__?.wallet
    : undefined
  return testWallet || getAllocationWallet(accountId, binding)
}

const requestMatchesMapping = (request: any, mapping: ReceiveMapping) =>
  !!request &&
  request.account_id === mapping.accountId &&
  request.wallet_id === mapping.walletId &&
  request.native_request_id === mapping.nativeRequestId &&
  request.idempotency_key === mapping.idempotencyKey &&
  request.amount_sat === mapping.amountSat &&
  request.network === mapping.network &&
  request.server_url === mapping.serverUrl &&
  request.server_pubkey === mapping.serverPubkey &&
  expirySeconds(request.expires_at) === mapping.expiresAt

const acknowledgementMatchesMapping = (
  response: any,
  mapping: ReceiveMapping
) => {
  try {
    return (
      requestMatchesMapping(response, mapping) &&
      (response.state === 'acknowledged' || response.state === 'settled') &&
      response.index === mapping.index &&
      response.address === mapping.address &&
      response.script === mapping.script &&
      response.child_xonly_pubkey === mapping.childXonlyPubkey
    )
  } catch {
    return false
  }
}

const acknowledgeReceive = async (
  accountId: string,
  mapping: ReceiveMapping
) => {
  const request = (
    await LNbits.api.arkadeReceiveRequest(mapping.nativeRequestId)
  ).data
  if (!requestMatchesMapping(request, mapping))
    throw new Error('receive allocation conflict')
  const response = (
    await LNbits.api.arkadeReceiveAck({
      native_request_id: mapping.nativeRequestId,
      account_id: mapping.accountId,
      wallet_id: mapping.walletId,
      idempotency_key: mapping.idempotencyKey,
      amount_sat: mapping.amountSat,
      index: mapping.index,
      address: mapping.address,
      script: mapping.script,
      child_xonly_pubkey: mapping.childXonlyPubkey,
      network: mapping.network,
      server_url: mapping.serverUrl,
      server_pubkey: mapping.serverPubkey,
      expires_at: mapping.expiresAt,
      signature: mapping.signature,
      exit_tapleaf: mapping.exitTapleaf,
      exit_control_block: mapping.exitControlBlock
    })
  ).data
  if (!acknowledgementMatchesMapping(response, mapping))
    throw new Error('receive acknowledgement conflict')
  return {accountId, mapping}
}

const allocateReceive = async (
  walletId: string,
  payment: any
): Promise<{accountId: string; mapping: ReceiveMapping}> => {
  const accountId = window.g.user.id
  if (!identity || !activeBinding || activeBinding.state !== 'ready')
    throw new Error('wallet is locked')
  if (
    payment?.protocol !== 'arkade' ||
    typeof payment.native_id !== 'string' ||
    !HEX32.test(payment.native_id) ||
    payment.wallet_id !== walletId ||
    !Number.isSafeInteger(payment.amount) ||
    payment.amount < 1000 ||
    payment.amount % 1000 !== 0
  )
    throw new Error('invalid Arkade payment')
  const nativeRequestId = payment.native_id
  const request = (await LNbits.api.arkadeReceiveRequest(nativeRequestId)).data
  const amountSat = payment.amount / 1000
  const expiresAt = request ? expirySeconds(request.expires_at) : -1
  if (
    !request ||
    request.account_id !== accountId ||
    request.wallet_id !== walletId ||
    request.native_request_id !== nativeRequestId ||
    typeof request.idempotency_key !== 'string' ||
    !HEX32.test(request.idempotency_key) ||
    request.amount_sat !== amountSat ||
    request.network !== activeBinding.network ||
    request.server_url !== activeBinding.server_url ||
    request.server_pubkey !== activeBinding.server_pubkey ||
    !Number.isSafeInteger(expiresAt)
  )
    throw new Error('invalid Arkade payment mapping')
  const existing = readReceiveJournal(accountId).find(
    mapping => mapping.nativeRequestId === nativeRequestId
  )
  if (existing) return acknowledgeReceive(accountId, existing)
  if (request.state !== 'pending')
    throw new Error('Arkade payment mapping is no longer pending')
  const wallet = await getAllocationWallet(accountId, activeBinding)
  const [newAddress] = await wallet.getNewAddresses({forceNew: true})
  if (!newAddress?.signingDescriptor || !newAddress.contract)
    throw new Error(
      'SDK allocator did not return a signing descriptor/contract'
    )
  const signingDescriptor = newAddress.signingDescriptor
  const indexMatch = signingDescriptor.match(/\/0\/(\d+)\)?$/)
  if (!indexMatch) throw new Error('unparseable signing descriptor')
  const index = Number(indexMatch[1])
  const childPubkey = deriveDescriptorLeafPubKey(signingDescriptor)
  const script = newAddress.contract.script
  const address = newAddress.address
  const tapscript = new DefaultVtxo.Script({
    ...wallet.offchainTapscript.options,
    pubKey: childPubkey
  })
  if (!script || newAddress.contract.address !== address)
    throw new Error('SDK allocator returned mismatched contract data')
  if (bytesToHex(tapscript.pkScript) !== script)
    throw new Error('SDK allocator returned an unsupported contract')
  const [controlBlock, exitTapleaf] = tapscript.exit()
  if (controlBlock.merklePath.length !== 1)
    throw new Error('SDK allocator returned an unsupported exit path')
  const control = new Uint8Array([
    controlBlock.version,
    ...controlBlock.internalKey,
    ...controlBlock.merklePath[0]
  ])
  const unsignedMapping = {
    action: 'lnbits-arkade-receive-v1' as const,
    accountId,
    walletId,
    nativeRequestId,
    idempotencyKey: request.idempotency_key,
    amountSat,
    index,
    address,
    script,
    childXonlyPubkey: bytesToHex(childPubkey),
    network: request.network,
    serverUrl: request.server_url,
    serverPubkey: request.server_pubkey,
    expiresAt,
    signature: '',
    exitTapleaf: bytesToHex(exitTapleaf),
    exitControlBlock: bytesToHex(control)
  }
  const signer = await wallet.signerForDescriptor(signingDescriptor)
  const signature = bytesToHex(
    await signer.signMessage(
      await digest(receiveStatement(unsignedMapping)),
      'schnorr'
    )
  )
  const mapping = persistReceiveMapping(accountId, {
    ...unsignedMapping,
    signature
  })
  return acknowledgeReceive(accountId, mapping)
}

const outgoingIntentSnapshot = (
  intent: any,
  intentId: string,
  walletId: string,
  accountId: string,
  binding: any
) => {
  if (
    !intent ||
    intent.intent_id !== intentId ||
    intent.account_id !== accountId ||
    intent.wallet_id !== walletId ||
    intent.network !== binding.network ||
    intent.server_url !== binding.server_url ||
    intent.server_pubkey !== binding.server_pubkey ||
    !Number.isSafeInteger(intent.amount_msat) ||
    intent.amount_msat <= 0 ||
    intent.amount_msat % 1000 !== 0 ||
    intent.max_fee_msat !== 0 ||
    typeof intent.destination !== 'string' ||
    !intent.destination
  )
    throw new Error('Arkade outgoing intent changed')
  const expiresAt = expirySeconds(intent.expires_at)
  const status = intent.status
  if (status !== 'reserved' && status !== 'submitted')
    throw new Error('Arkade outgoing intent is not submit-ready')
  if (status === 'reserved' && expiresAt <= Math.floor(Date.now() / 1000))
    throw new Error('Arkade outgoing intent expired')
  let decoded: ArkAddress
  try {
    decoded = ArkAddress.decode(intent.destination)
  } catch {
    throw new Error('Arkade outgoing destination is invalid')
  }
  if (
    decoded.hrp !== (binding.network === 'bitcoin' ? 'ark' : 'tark') ||
    bytesToHex(decoded.serverPubKey) !== binding.server_pubkey.toLowerCase()
  )
    throw new Error('Arkade outgoing destination is not on the bound server')
  const destinationScript = bytesToHex(decoded.pkScript)
  if (
    intent.destination_script &&
    intent.destination_script.toLowerCase() !== destinationScript
  )
    throw new Error('Arkade outgoing destination changed')
  return {
    intent,
    expiresAt,
    amountSat: intent.amount_msat / 1000,
    destinationScript,
    status
  }
}

const outgoingBindingFingerprint = (binding: any) =>
  JSON.stringify([
    binding?.account_id,
    binding?.network,
    binding?.server_url,
    binding?.server_pubkey,
    binding?.identity_xonly_pubkey,
    binding?.identity_descriptor
  ])

const outgoingContextIsLive = (
  accountId: string,
  generation: number,
  bindingFingerprint: string
) =>
  !!identity &&
  generation === unlockGeneration &&
  accountId === window.g.user.id &&
  !!activeBinding &&
  activeBinding.state === 'ready' &&
  bindingFingerprint === outgoingBindingFingerprint(activeBinding)

const outgoingPlanIsLive = (plan: OutgoingPlan) =>
  outgoingContextIsLive(
    plan.accountId,
    plan.generation,
    plan.bindingFingerprint
  )

const outgoingInputSummary = (input: SpendableVtxo) => ({
  txid: input.txid,
  vout: input.vout,
  amount_sat: input.value,
  script: input.script
})

const outgoingChangeCommitment = (
  wallet: ArkadeWallet,
  address: {address: string; signingDescriptor: string; contract: any}
): OutgoingChange => {
  if (
    address.contract?.type !== 'default' ||
    address.contract.address !== address.address ||
    address.contract.metadata?.signingDescriptor !== address.signingDescriptor
  )
    throw new Error('SDK allocator returned mismatched change contract')
  const indexMatch = address.signingDescriptor.match(/\/0\/(\d+)\)?$/)
  if (!indexMatch) throw new Error('unparseable change signing descriptor')
  const index = Number(indexMatch[1])
  if (!Number.isSafeInteger(index)) throw new Error('invalid change index')
  const childPubkey = deriveDescriptorLeafPubKey(address.signingDescriptor)
  const script = address.contract.script
  if (!script) throw new Error('SDK allocator returned no change script')
  const tapscript = new DefaultVtxo.Script({
    ...wallet.offchainTapscript.options,
    pubKey: childPubkey
  })
  if (bytesToHex(tapscript.pkScript) !== script.toLowerCase())
    throw new Error('SDK allocator returned unsupported change contract')
  const [controlBlock, exitTapleaf] = tapscript.exit()
  if (controlBlock.merklePath.length !== 1)
    throw new Error('SDK allocator returned unsupported change exit path')
  return {
    index,
    address: address.address,
    script: script.toLowerCase(),
    child_xonly_pubkey: bytesToHex(childPubkey),
    amount_sat: 0,
    exit_tapleaf: bytesToHex(exitTapleaf),
    exit_control_block: bytesToHex(
      new Uint8Array([
        controlBlock.version,
        ...controlBlock.internalKey,
        ...controlBlock.merklePath[0]
      ])
    )
  }
}

const outgoingPreview = (plan: OutgoingPlan) => {
  const inputs = plan.inputs.map(input => ({
    ...input,
    tapLeafScript: input.forfeitTapLeafScript
  }))
  return buildOffchainTx(inputs, plan.outputs, plan.wallet.serverUnrollScript)
}

const outgoingCommitment = (plan: OutgoingPlan) => {
  const preview = outgoingPreview(plan)
  return JSON.stringify({
    arkTx: bytesToHex(preview.arkTx.toBytes()),
    checkpoints: preview.checkpoints.map(tx => bytesToHex(tx.toBytes()))
  })
}

const outgoingJournalFromPlan = (
  plan: OutgoingPlan,
  phase: OutgoingJournal['phase']
): OutgoingJournal => ({
  version: OUTGOING_JOURNAL_VERSION,
  intentId: plan.intentId,
  accountId: plan.accountId,
  walletId: plan.walletId,
  amountSat: plan.publicPlan.amountSat,
  destination: plan.destination,
  destinationScript: plan.destinationScript,
  inputs: plan.publicPlan.inputs,
  change: plan.change
    ? {
        index: plan.change.index,
        script: plan.change.script,
        amount_sat: plan.change.amount_sat
      }
    : null,
  previewCommitment: plan.previewCommitment,
  network: activeBinding.network,
  serverUrl: activeBinding.server_url,
  serverPubkey: activeBinding.server_pubkey,
  expiresAt: plan.expiresAt,
  phase
})

const outgoingJournalResponseMatches = (
  record: OutgoingJournal,
  response: any,
  binding: any
) => {
  try {
    if (
      !response ||
      response.intent_id !== record.intentId ||
      response.account_id !== record.accountId ||
      response.wallet_id !== record.walletId ||
      response.amount_msat !== record.amountSat * 1000 ||
      response.max_fee_msat !== 0 ||
      response.destination !== record.destination ||
      response.destination_kind !== 'arkade_address' ||
      response.network !== record.network ||
      response.server_url !== record.serverUrl ||
      response.server_pubkey !== record.serverPubkey ||
      !journalMatchesBinding(record, record.accountId, binding) ||
      (response.destination_script?.toLowerCase() ?? null) !==
        record.destinationScript.toLowerCase() ||
      expirySeconds(response.expires_at) !== record.expiresAt ||
      response.change_index !== (record.change?.index ?? null) ||
      (response.change_script?.toLowerCase() ?? null) !==
        (record.change?.script.toLowerCase() ?? null) ||
      response.change_amount_sat !== (record.change?.amount_sat ?? null)
    )
      return false
    const inputs = response.inputs || []
    return (
      inputs.length === record.inputs.length &&
      record.inputs.every(input =>
        inputs.some(
          (item: any) =>
            item.txid === input.txid &&
            item.vout === input.vout &&
            item.amount_sat === input.amount_sat
        )
      )
    )
  } catch {
    return false
  }
}

const outgoingJournalForPlan = (plan: OutgoingPlan) => {
  const journal = outgoingJournalFromPlan(plan, 'prepared')
  if (!journalMatchesBinding(journal, plan.accountId, activeBinding))
    throw new Error('Arkade outgoing binding changed')
  persistOutgoingJournal(journal)
}

const prepareOutgoing = async (
  intentId: string,
  walletId: string
): Promise<OutgoingPrepared> => {
  const accountId = window.g.user.id
  if (!identity || !activeBinding || activeBinding.state !== 'ready')
    throw new Error('wallet is locked')
  const intent = (await LNbits.api.arkadeOutgoingIntent(intentId)).data
  const snapshot = outgoingIntentSnapshot(
    intent,
    intentId,
    walletId,
    accountId,
    activeBinding
  )
  if (snapshot.status !== 'reserved')
    throw new Error('Arkade outgoing intent is already submitted')
  const wallet = await outgoingWallet(accountId, activeBinding)
  const spendable = await wallet.getSpendableVtxos()
  const candidates = spendable.filter(input => input.value > 0)
  if (candidates.some(input => !Number.isSafeInteger(input.value)))
    throw new Error('Arkade outgoing balance is invalid')
  const candidateTotal = candidates.reduce(
    (total, input) => total + input.value,
    0
  )
  if (!Number.isSafeInteger(candidateTotal))
    throw new Error('Arkade outgoing balance is too large')
  const selected = selectVirtualCoins(candidates, snapshot.amountSat)
  const inputs = [...selected.inputs]
  if (!inputs.length || inputs.length > 100)
    throw new Error('Arkade outgoing input count is invalid')
  const changeAmount = Number(selected.changeAmount)
  if (!Number.isSafeInteger(changeAmount) || changeAmount < 0)
    throw new Error('Arkade outgoing change is invalid')
  const info = await wallet.arkProvider.getInfo()
  const dust = BigInt(info.dust)
  if (changeAmount > 0 && BigInt(changeAmount) < dust)
    throw new Error('Arkade outgoing change is below dust')
  let change: OutgoingChange | null = null
  if (changeAmount > 0) {
    const [newAddress] = await wallet.getNewAddresses({forceNew: true})
    if (!newAddress) throw new Error('SDK allocator returned no change address')
    change = outgoingChangeCommitment(wallet, newAddress)
    change = Object.freeze({...change, amount_sat: changeAmount})
  }
  const outputs = [
    {
      script: fromHex(snapshot.destinationScript),
      amount: BigInt(snapshot.amountSat)
    },
    ...(change
      ? [{script: fromHex(change.script), amount: BigInt(change.amount_sat)}]
      : [])
  ]
  const sum = inputs.reduce((total, input) => total + BigInt(input.value), 0n)
  if (sum !== BigInt(snapshot.amountSat) + BigInt(changeAmount))
    throw new Error('Arkade outgoing amount changed')
  const plan: OutgoingPlan = {
    publicPlan: null as unknown as OutgoingPrepared,
    wallet,
    inputs,
    outputs,
    generation: unlockGeneration,
    accountId,
    intentId,
    walletId,
    amountMsat: intent.amount_msat,
    expiresAt: snapshot.expiresAt,
    destination: intent.destination,
    destinationScript: snapshot.destinationScript,
    change,
    previewCommitment: '',
    bindingFingerprint: outgoingBindingFingerprint(activeBinding)
  }
  const publicInputs = Object.freeze(
    inputs.map(input => Object.freeze(outgoingInputSummary(input)))
  )
  const publicChange = change ? Object.freeze({...change}) : null
  plan.previewCommitment = outgoingCommitment(plan)
  const publicPlan: OutgoingPrepared = Object.freeze({
    intentId,
    accountId,
    walletId,
    amountSat: snapshot.amountSat,
    destination: intent.destination,
    destinationScript: snapshot.destinationScript,
    inputs: publicInputs,
    change: publicChange,
    previewCommitment: plan.previewCommitment
  })
  plan.publicPlan = publicPlan
  outgoingJournalForPlan(plan)
  outgoingPlans.set(publicPlan, plan)
  return publicPlan
}

const sameOutgoingInputs = (expected: OutgoingPlan['inputs'], actual: any[]) =>
  expected.length === actual.length &&
  expected.every(input =>
    actual.some(
      item =>
        item.txid === input.txid &&
        item.vout === input.vout &&
        item.amount_sat === input.value
    )
  )

const sameOutgoingPlan = (plan: OutgoingPlan, response: any) =>
  response?.intent_id === plan.intentId &&
  response.account_id === plan.accountId &&
  response.wallet_id === plan.walletId &&
  response.amount_msat === plan.amountMsat &&
  response.max_fee_msat === 0 &&
  response.destination === plan.destination &&
  response.destination_kind === 'arkade_address' &&
  response.network === activeBinding.network &&
  response.server_url === activeBinding.server_url &&
  response.server_pubkey === activeBinding.server_pubkey &&
  response.destination_script === plan.destinationScript &&
  expirySeconds(response.expires_at) === plan.expiresAt &&
  response.change_index === (plan.change?.index ?? null) &&
  response.change_script === (plan.change?.script ?? null) &&
  response.change_amount_sat === (plan.change?.amount_sat ?? null) &&
  sameOutgoingInputs(plan.inputs, response.inputs || [])

const submitOutgoing = async (
  prepared: OutgoingPrepared,
  approval: {approved: true}
) => {
  if (!approval || approval.approved !== true)
    throw new Error('Arkade outgoing approval required')
  const plan = outgoingPlans.get(prepared)
  if (!plan) throw new Error('Arkade outgoing preparation is invalid')
  if (!outgoingPlanIsLive(plan))
    throw new Error('Arkade outgoing preparation is locked')
  const snapshot = outgoingIntentSnapshot(
    (await LNbits.api.arkadeOutgoingIntent(plan.intentId)).data,
    plan.intentId,
    plan.walletId,
    plan.accountId,
    activeBinding
  )
  if (
    snapshot.amountSat * 1000 !== plan.amountMsat ||
    snapshot.destinationScript !== plan.destinationScript ||
    snapshot.intent.destination !== plan.destination ||
    snapshot.expiresAt !== plan.expiresAt ||
    (snapshot.status === 'submitted' &&
      !sameOutgoingPlan(plan, snapshot.intent))
  )
    throw new Error('Arkade outgoing intent changed')
  if (outgoingCommitment(plan) !== plan.previewCommitment)
    throw new Error('Arkade outgoing transaction changed')
  const request = {
    inputs: plan.inputs.map(input => ({
      txid: input.txid,
      vout: input.vout,
      amount_sat: input.value
    })),
    destination_script: plan.destinationScript,
    change: plan.change
  }
  let authorization: any
  try {
    authorization = (
      await LNbits.api.arkadeOutgoingAuthorize(plan.intentId, request)
    ).data
  } catch {
    let afterFailure: any
    try {
      afterFailure = (await LNbits.api.arkadeOutgoingIntent(plan.intentId)).data
    } catch {
      updateOutgoingJournalPhase(
        plan.accountId,
        plan.intentId,
        'authorization_unknown'
      )
      throw new ArkadeOutgoingReconciliationError(
        plan.intentId,
        'authorization_unknown'
      )
    }
    let afterSnapshot
    try {
      afterSnapshot = outgoingIntentSnapshot(
        afterFailure,
        plan.intentId,
        plan.walletId,
        plan.accountId,
        activeBinding
      )
    } catch {
      updateOutgoingJournalPhase(
        plan.accountId,
        plan.intentId,
        'authorization_unknown'
      )
      throw new ArkadeOutgoingReconciliationError(
        plan.intentId,
        'authorization_unknown'
      )
    }
    if (afterSnapshot.status !== 'submitted') {
      updateOutgoingJournalPhase(plan.accountId, plan.intentId, 'prepared')
      throw new Error('Arkade outgoing authorization failed')
    }
    if (!sameOutgoingPlan(plan, afterFailure)) {
      updateOutgoingJournalPhase(
        plan.accountId,
        plan.intentId,
        'authorization_unknown'
      )
      throw new ArkadeOutgoingReconciliationError(
        plan.intentId,
        'authorization_unknown'
      )
    }
    authorization = afterFailure
  }
  if (
    authorization.status !== 'submitted' ||
    !sameOutgoingPlan(plan, authorization)
  ) {
    updateOutgoingJournalPhase(
      plan.accountId,
      plan.intentId,
      'authorization_unknown'
    )
    throw new Error('Arkade outgoing authorization changed')
  }
  if (!outgoingPlanIsLive(plan))
    throw new Error('Arkade outgoing preparation is locked')
  updateOutgoingJournalPhase(plan.accountId, plan.intentId, 'submitted')
  if (outgoingCommitment(plan) !== plan.previewCommitment)
    throw new Error('Arkade outgoing transaction changed')
  if (!outgoingPlanIsLive(plan))
    throw new Error('Arkade outgoing preparation is locked')
  try {
    const result = await plan.wallet.buildAndSubmitOffchainTx(
      plan.inputs,
      plan.outputs,
      plan.wallet.serverUnrollScript
    )
    return {
      status: 'submitted' as const,
      reconciliationRequired: true as const,
      intentId: plan.intentId,
      arkTxid: result.arkTxid
    }
  } catch {
    updateOutgoingJournalPhase(
      plan.accountId,
      plan.intentId,
      'reconciliation_required'
    )
    throw new ArkadeOutgoingReconciliationError(plan.intentId, 'submitted')
  }
}

const outgoingJournalResponseBindingMatches = (
  record: OutgoingJournal,
  response: any,
  binding: any
) => {
  try {
    return (
      response?.intent_id === record.intentId &&
      response.account_id === record.accountId &&
      response.wallet_id === record.walletId &&
      response.amount_msat === record.amountSat * 1000 &&
      response.max_fee_msat === 0 &&
      response.destination === record.destination &&
      response.destination_kind === 'arkade_address' &&
      response.network === record.network &&
      response.server_url === record.serverUrl &&
      response.server_pubkey === record.serverPubkey &&
      journalMatchesBinding(record, record.accountId, binding) &&
      expirySeconds(response.expires_at) === record.expiresAt
    )
  } catch {
    return false
  }
}

const releasedOutgoingJournalMatches = (
  record: OutgoingJournal,
  response: any,
  binding: any
) =>
  record.phase === 'prepared' &&
  response?.status === 'released' &&
  outgoingJournalResponseBindingMatches(record, response, binding) &&
  Array.isArray(response.inputs) &&
  response.inputs.length === 0 &&
  response.destination_script === null &&
  response.change_index === null &&
  response.change_script === null &&
  response.change_amount_sat === null

const exactOutgoingVtxos = (
  vtxos: any[],
  record: OutgoingJournal
): SpendableVtxo[] => {
  const result: SpendableVtxo[] = []
  for (const input of record.inputs) {
    const matches = vtxos.filter(
      item =>
        item.txid === input.txid &&
        item.vout === input.vout &&
        item.value === input.amount_sat &&
        typeof item.script === 'string' &&
        item.script.toLowerCase() === input.script.toLowerCase()
    )
    if (matches.length !== 1)
      throw new Error('Arkade outgoing VTXO unavailable')
    result.push(matches[0])
  }
  return result
}

const fetchExactOutgoingVtxos = async (
  wallet: ArkadeWallet,
  manager: Awaited<ReturnType<ArkadeWallet['getContractManager']>>,
  inputs: ReadonlyArray<{txid: string; vout: number}>
) => {
  const response = await wallet.indexerProvider.getVtxos({
    outpoints: inputs.map(({txid, vout}) => ({txid, vout}))
  })
  if (!response || !Array.isArray(response.vtxos))
    throw new Error('Arkade outgoing recovery unavailable')
  return manager.annotateVtxos(response.vtxos)
}

const outgoingRecoveryPreview = (
  wallet: ArkadeWallet,
  record: OutgoingJournal,
  inputs: SpendableVtxo[]
) => {
  const outputs = [
    {
      script: fromHex(record.destinationScript),
      amount: BigInt(record.amountSat)
    },
    ...(record.change
      ? [
          {
            script: fromHex(record.change.script),
            amount: BigInt(record.change.amount_sat)
          }
        ]
      : [])
  ]
  const preview = buildOffchainTx(
    inputs.map(input => ({
      ...input,
      tapLeafScript: input.forfeitTapLeafScript
    })),
    outputs,
    wallet.serverUnrollScript
  )
  return {
    outputs,
    commitment: JSON.stringify({
      arkTx: bytesToHex(preview.arkTx.toBytes()),
      checkpoints: preview.checkpoints.map(tx => bytesToHex(tx.toBytes()))
    })
  }
}

const outgoingRecoveryArtifacts = (
  wallet: ArkadeWallet,
  record: OutgoingJournal,
  inputs: SpendableVtxo[]
) => {
  if (inputs.some(input => !isSpendable(input)))
    throw new Error('Arkade outgoing VTXO is no longer spendable')
  const {outputs, commitment} = outgoingRecoveryPreview(wallet, record, inputs)
  if (commitment !== record.previewCommitment)
    throw new Error('outgoing journal commitment mismatch')
  return {inputs, outputs}
}

const hydrateOutgoingJournal = async (
  wallet: ArkadeWallet,
  manager: Awaited<ReturnType<ArkadeWallet['getContractManager']>>,
  response: any,
  accountId: string,
  binding: any
) => {
  const snapshot = outgoingIntentSnapshot(
    response,
    response?.intent_id,
    response?.wallet_id,
    accountId,
    binding
  )
  if (snapshot.status !== 'submitted' || !Array.isArray(response.inputs))
    throw new Error('Arkade outgoing intent changed')
  const annotated = await fetchExactOutgoingVtxos(
    wallet,
    manager,
    response.inputs
  )
  const inputs = response.inputs.map((claim: any) => {
    const matches = annotated.filter(
      input =>
        input.txid === claim.txid &&
        input.vout === claim.vout &&
        input.value === claim.amount_sat &&
        typeof input.script === 'string'
    )
    if (matches.length !== 1)
      throw new Error('Arkade outgoing VTXO unavailable')
    return {
      txid: claim.txid,
      vout: claim.vout,
      amount_sat: claim.amount_sat,
      script: matches[0].script
    }
  })
  const base: OutgoingJournal = {
    version: OUTGOING_JOURNAL_VERSION,
    intentId: response.intent_id,
    accountId,
    walletId: response.wallet_id,
    amountSat: snapshot.amountSat,
    destination: response.destination,
    destinationScript: snapshot.destinationScript,
    inputs,
    change:
      response.change_index === null
        ? null
        : {
            index: response.change_index,
            script: response.change_script,
            amount_sat: response.change_amount_sat
          },
    previewCommitment: '',
    network: response.network,
    serverUrl: response.server_url,
    serverPubkey: response.server_pubkey,
    expiresAt: snapshot.expiresAt,
    phase: 'submitted'
  }
  const record = {
    ...base,
    previewCommitment: outgoingRecoveryPreview(
      wallet,
      base,
      exactOutgoingVtxos(annotated, base)
    ).commitment
  }
  if (!outgoingJournalResponseMatches(record, response, binding))
    throw new Error('Arkade outgoing intent changed')
  return persistOutgoingJournal(record)
}

const listOutgoing = async () => {
  const accountId = window.g.user.id
  if (!activeBinding) await probe()
  if (!activeBinding || activeBinding.account_id !== accountId)
    throw new Error('Arkade outgoing binding unavailable')
  let journal = readOutgoingJournal(accountId)
  if (
    journal.some(
      record => !journalMatchesBinding(record, accountId, activeBinding)
    )
  )
    throw new Error('outgoing journal binding changed')
  journal = await reconcileTerminalOutgoing(accountId, journal)
  if (!identity) return journal
  const wallet = await outgoingWallet(accountId, activeBinding)
  const manager = await wallet.getContractManager()
  const responses = (await LNbits.api.arkadeSubmittedOutgoingIntents()).data
  if (!Array.isArray(responses))
    throw new Error('Arkade outgoing recovery unavailable')
  for (const response of responses) {
    const existing = journal.find(item => item.intentId === response?.intent_id)
    if (existing) {
      if (!outgoingJournalResponseMatches(existing, response, activeBinding))
        throw new Error('Arkade outgoing intent changed')
    } else {
      await hydrateOutgoingJournal(
        wallet,
        manager,
        response,
        accountId,
        activeBinding
      )
    }
  }
  journal = readOutgoingJournal(accountId)
  return journal
}

const recoverOutgoing = async (
  intentId: string,
  approval?: {approved: true}
) => {
  const accountId = window.g.user.id
  if (!identity || !activeBinding || activeBinding.state !== 'ready')
    throw new Error('wallet is locked')
  const record = readOutgoingJournal(accountId).find(
    item => item.intentId === intentId
  )
  if (!record || !journalMatchesBinding(record, accountId, activeBinding))
    throw new Error('outgoing journal unavailable')
  const recoveryGeneration = unlockGeneration
  const recoveryBindingFingerprint = outgoingBindingFingerprint(activeBinding)
  const wallet = await outgoingWallet(accountId, activeBinding)
  let manager: Awaited<ReturnType<ArkadeWallet['getContractManager']>>
  try {
    manager = await wallet.getContractManager()
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (
    !manager ||
    typeof manager.refreshVtxos !== 'function' ||
    typeof manager.annotateVtxos !== 'function'
  ) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  const scripts = [
    ...record.inputs.map(input => input.script),
    ...(record.change ? [record.change.script] : [])
  ]
  try {
    await manager.refreshVtxos({scripts: [...new Set(scripts)]})
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  let response: any
  try {
    response = (await LNbits.api.arkadeOutgoingIntent(intentId)).data
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (!outgoingJournalResponseBindingMatches(record, response, activeBinding)) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (response.status === 'reserved')
    return {intentId, status: response.status, phase: record.phase}
  if (response.status === 'released') {
    if (releasedOutgoingJournalMatches(record, response, activeBinding)) {
      removeOutgoingJournal(accountId, intentId)
      return {intentId, status: response.status, reconciliationRequired: false}
    }
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (!outgoingJournalResponseMatches(record, response, activeBinding)) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (response.status === 'settled') {
    removeOutgoingJournal(accountId, intentId)
    return {intentId, status: response.status, reconciliationRequired: false}
  }
  if (response.status === 'disputed') {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {
      intentId,
      status: response.status,
      reconciliationRequired: true
    }
  }
  if (response.status !== 'submitted') {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  let allVtxos: any[]
  let inputs: SpendableVtxo[]
  try {
    allVtxos = await fetchExactOutgoingVtxos(wallet, manager, record.inputs)
    inputs = exactOutgoingVtxos(allVtxos, record)
    if (
      outgoingRecoveryPreview(wallet, record, inputs).commitment !==
      record.previewCommitment
    )
      throw new Error('outgoing journal commitment mismatch')
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (!approval || approval.approved !== true)
    throw new Error('Arkade outgoing recovery approval required')
  if (
    !outgoingContextIsLive(
      accountId,
      recoveryGeneration,
      recoveryBindingFingerprint
    )
  ) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  let finalization: {finalized: string[]; pending: string[]}
  let finalizationError = false
  try {
    finalization = await wallet.finalizePendingTxs(inputs)
  } catch {
    finalizationError = true
    finalization = {finalized: [], pending: []}
  }
  try {
    await manager.refreshVtxos({scripts: [...new Set(scripts)]})
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  try {
    response = (await LNbits.api.arkadeOutgoingIntent(intentId)).data
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (!outgoingJournalResponseMatches(record, response, activeBinding)) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (response.status === 'settled') {
    removeOutgoingJournal(accountId, intentId)
    return {intentId, status: response.status, reconciliationRequired: false}
  }
  if (response.status === 'disputed') {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {
      intentId,
      status: response.status,
      reconciliationRequired: true
    }
  }
  if (
    finalizationError ||
    !Array.isArray(finalization?.finalized) ||
    !Array.isArray(finalization?.pending) ||
    finalization.finalized.length > 0 ||
    finalization.pending.length > 0
  ) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (response.status !== 'submitted') {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  if (
    !outgoingContextIsLive(
      accountId,
      recoveryGeneration,
      recoveryBindingFingerprint
    )
  ) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
  try {
    const refreshed = exactOutgoingVtxos(
      await fetchExactOutgoingVtxos(wallet, manager, record.inputs),
      record
    )
    const {outputs} = outgoingRecoveryArtifacts(wallet, record, refreshed)
    if (
      !outgoingContextIsLive(
        accountId,
        recoveryGeneration,
        recoveryBindingFingerprint
      )
    )
      throw new Error('Arkade outgoing recovery is locked')
    const result = await wallet.buildAndSubmitOffchainTx(
      refreshed,
      outputs,
      wallet.serverUnrollScript
    )
    updateOutgoingJournalPhase(accountId, intentId, 'submitted')
    return {
      status: 'submitted' as const,
      reconciliationRequired: true as const,
      intentId,
      arkTxid: result.arkTxid
    }
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required' as const}
  }
}

const recoverOutgoingSerialized = (
  intentId: string,
  approval?: {approved: true}
) => {
  const key = `${window.g.user.id}:${intentId}`
  const existing = outgoingRecoveries.get(key)
  if (existing) return existing
  const recovery = recoverOutgoing(intentId, approval).finally(() => {
    if (outgoingRecoveries.get(key) === recovery) outgoingRecoveries.delete(key)
  })
  outgoingRecoveries.set(key, recovery)
  return recovery
}

const probe = async () => {
  const accountId = window.g.user.id
  let idempotencyKey: string
  try {
    idempotencyKey = await getIdempotencyKey(accountId)
  } catch {
    return {state: 'recovery_required', record: await readVault(accountId)}
  }
  const response = await LNbits.api.arkadeEnrollmentChallenge(idempotencyKey)
  activeBinding = validateBinding(response.data, accountId, {idempotencyKey})
  const record = await readVault(accountId)
  if (activeBinding.state === 'pending')
    return {state: record?.ciphertext ? 'wallet_locked' : 'pending', record}
  if (!record?.ciphertext) return {state: 'recovery_required', record}
  if (
    !strictRecord(record) ||
    record.accountId !== accountId ||
    record.network !== activeBinding.network ||
    record.identityXonlyPubkey !== activeBinding.identity_xonly_pubkey
  )
    return {state: 'recovery_required', record}
  return {state: 'wallet_locked', record}
}

const finish = async () => {
  if (!identity || !activeBinding || activeBinding.state !== 'pending')
    throw new Error('enrollment unavailable')
  const challenge = (
    await LNbits.api.arkadeEnrollmentChallenge(activeBinding.idempotency_key)
  ).data
  validateBinding(challenge, window.g.user.id, {
    idempotencyKey: activeBinding.idempotency_key,
    previous: activeBinding
  })
  if (challenge.state === 'ready') {
    const xonly = bytesToHex(await identity.xOnlyPublicKey())
    if (
      challenge.identity_xonly_pubkey !== xonly ||
      (challenge.identity_descriptor &&
        challenge.identity_descriptor !== identity.descriptor)
    )
      throw new Error('wallet mismatch')
    activeBinding = challenge
    window.g.arkadeEnrollmentState = 'ready_unlocked'
    return
  }
  if (challenge.state !== 'pending') throw new Error('enrollment changed')
  const xonly = bytesToHex(await identity.xOnlyPublicKey())
  const descriptor = identity.descriptor
  const sig = bytesToHex(
    await identity.signMessage(
      await digest(statement(challenge, xonly, descriptor)),
      'schnorr'
    )
  )
  const result = await LNbits.api.arkadeEnrollmentComplete({
    enrollment_id: challenge.enrollment_id,
    idempotency_key: challenge.idempotency_key,
    identity_xonly_pubkey: xonly,
    identity_descriptor: descriptor,
    signature: sig
  })
  activeBinding = validateBinding(result.data, window.g.user.id, {
    idempotencyKey: challenge.idempotency_key,
    identityXonlyPubkey: xonly,
    identityDescriptor: descriptor,
    previous: challenge
  })
  if (activeBinding.state !== 'ready')
    throw new Error('invalid enrollment response')
  window.g.arkadeEnrollmentState = 'ready_unlocked'
}

const unlock = async (password: string) => {
  const accountId = window.g.user.id
  if (!activeBinding) await probe()
  const record = await readVault(accountId)
  if (!record || !strictRecord(record)) throw new Error('vault unavailable')
  if (Array.from(password).length < PASSWORD_MIN_LENGTH)
    throw new Error('password too short')
  const mnemonic = await decryptVault(
    accountId,
    password,
    record,
    activeBinding
  )
  const next = makeIdentity(mnemonic, activeBinding.network)
  const xonly = bytesToHex(await next.xOnlyPublicKey())
  if (
    xonly !== record.identityXonlyPubkey ||
    (activeBinding?.state === 'ready' &&
      (xonly !== activeBinding.identity_xonly_pubkey ||
        (activeBinding.identity_descriptor &&
          next.descriptor !== activeBinding.identity_descriptor)))
  )
    throw new Error('wallet mismatch')
  identity = next
  unlockGeneration += 1
  window.g.arkadeEnrollmentState =
    activeBinding?.state === 'pending' ? 'pending_unlocked' : 'ready_unlocked'
  resetIdleTimer()
  return activeBinding?.state === 'pending'
}

const lock = () => {
  unlockGeneration += 1
  identity = null
  const wallet = allocationWallet
  allocationWallet = null
  allocationWalletKey = ''
  if (wallet) void wallet.dispose().catch(() => {})
  if (idleTimer) window.clearTimeout(idleTimer)
  idleTimer = undefined
  if (window.g?.user?.installationMode === 'arkade_noncustodial') {
    window.g.arkadeEnrollmentState =
      activeBinding?.state === 'ready' ? 'wallet_locked' : 'pending'
    if (window.location.pathname !== '/arkade/enrollment')
      window.router?.push('/arkade/enrollment')
  }
}

const resetIdleTimer = () => {
  if (!identity) return
  if (idleTimer) window.clearTimeout(idleTimer)
  idleTimer = window.setTimeout(lock, IDLE_TIMEOUT_MS)
}

for (const eventName of ['pointerdown', 'keydown', 'touchstart'])
  window.addEventListener(
    eventName,
    event => event.isTrusted && resetIdleTimer(),
    {passive: true}
  )
window.addEventListener('pagehide', lock)

window.ArkadeEnrollment = {
  lock,
  async inspect() {
    return probe()
  },
  async enroll(mnemonic: string, password: string, acknowledged: boolean) {
    const clean = mnemonic.trim().split(/\s+/).join(' ')
    if (
      !validateMnemonic(clean, wordlist) ||
      Array.from(password).length < PASSWORD_MIN_LENGTH
    )
      throw new Error('invalid wallet details')
    if (!acknowledged) throw new Error('backup acknowledgement required')
    const accountId = window.g.user.id
    const key = await getIdempotencyKey(accountId)
    const challenge = validateBinding(
      (await LNbits.api.arkadeEnrollmentChallenge(key)).data,
      accountId,
      {idempotencyKey: key, previous: activeBinding || undefined}
    )
    const next = makeIdentity(clean, challenge.network)
    const xonly = bytesToHex(await next.xOnlyPublicKey())
    if (challenge.state === 'ready') {
      if (
        xonly !== challenge.identity_xonly_pubkey ||
        (challenge.identity_descriptor &&
          next.descriptor !== challenge.identity_descriptor)
      )
        throw new Error('wallet mismatch')
      await encryptVault(
        accountId,
        clean,
        password,
        challenge.network,
        xonly,
        key
      )
      identity = next
      unlockGeneration += 1
      activeBinding = challenge
      window.g.arkadeEnrollmentState = 'ready_unlocked'
      resetIdleTimer()
      return
    }
    const current = await readVault(accountId)
    if (
      current?.ciphertext &&
      strictRecord(current) &&
      (current.network !== challenge.network ||
        current.identityXonlyPubkey !== xonly)
    )
      throw new Error('wallet mismatch')
    await encryptVault(
      accountId,
      clean,
      password,
      challenge.network,
      xonly,
      key
    )
    identity = next
    unlockGeneration += 1
    activeBinding = challenge
    await finish()
    resetIdleTimer()
  },
  async unlock(password: string) {
    return unlock(password)
  },
  async finish() {
    await finish()
  },
  async allocateReceive(walletId: string, payment: any) {
    return allocateReceive(walletId, payment)
  },
  async prepareOutgoing(intentId: string, walletId: string) {
    return prepareOutgoing(intentId, walletId)
  },
  async submitOutgoing(prepared: OutgoingPrepared, approval: {approved: true}) {
    return submitOutgoing(prepared, approval)
  },
  async listOutgoing() {
    return listOutgoing()
  },
  async recoverOutgoing(intentId: string, approval?: {approved: true}) {
    return recoverOutgoingSerialized(intentId, approval)
  },
  async binding() {
    return activeBinding
  }
}

if (ARKADE_ENROLLMENT_TEST && (window as any).__ARKADE_ENROLLMENT_TEST__) {
  ;(window.ArkadeEnrollment as any).__setTestReady = (
    binding: any,
    wallet: ArkadeWallet
  ) => {
    activeBinding = binding
    identity = {} as MnemonicIdentity
    ;(window as any).__ARKADE_ENROLLMENT_TEST__.wallet = wallet
    unlockGeneration += 1
  }
}

window.PageArkadeEnrollment = {
  template: '#page-arkade-enrollment',
  data() {
    return {
      loading: true,
      working: false,
      state: 'unavailable',
      mode: '',
      mnemonic: '',
      password: '',
      passwordRepeat: '',
      backupAcknowledged: false
    }
  },
  async created() {
    if (this.g.user?.installationMode !== 'arkade_noncustodial')
      return this.$router.replace('/')
    await this.inspect()
  },
  methods: {
    async inspect() {
      this.loading = true
      try {
        this.state = (await window.ArkadeEnrollment.inspect()).state
        this.g.arkadeEnrollmentState = this.state
      } catch {
        this.state = 'unavailable'
      } finally {
        this.loading = false
      }
    },
    startCreate() {
      this.mode = 'create'
      this.mnemonic = generateMnemonic(wordlist, 128)
      this.password = ''
      this.passwordRepeat = ''
      this.backupAcknowledged = false
    },
    startRestore() {
      this.mode = 'restore'
      this.mnemonic = ''
      this.password = ''
      this.passwordRepeat = ''
      this.backupAcknowledged = true
    },
    cancel() {
      this.mode = ''
      this.mnemonic = ''
      this.password = ''
      this.passwordRepeat = ''
      this.backupAcknowledged = false
    },
    async unlock() {
      this.working = true
      try {
        const pending = await window.ArkadeEnrollment.unlock(this.password)
        this.password = ''
        if (pending) {
          this.state = 'pending_unlocked'
          return
        }
        await this.$router.push('/wallet')
      } catch {
        this.password = ''
        this.$q.notify({
          type: 'negative',
          message:
            'Could not unlock this wallet. Check your password or restore your mnemonic.'
        })
      } finally {
        this.working = false
      }
    },
    async finish() {
      this.working = true
      try {
        await window.ArkadeEnrollment.finish()
        await this.$router.push('/wallet')
      } catch {
        this.$q.notify({
          type: 'negative',
          message: 'Wallet setup could not be completed. Try again later.'
        })
      } finally {
        this.working = false
      }
    },
    lock() {
      window.ArkadeEnrollment.lock()
      this.state = 'wallet_locked'
    },
    async submit() {
      this.working = true
      try {
        if (this.password !== this.passwordRepeat)
          throw new Error('password mismatch')
        await window.ArkadeEnrollment.enroll(
          this.mnemonic,
          this.password,
          this.backupAcknowledged
        )
        this.password = ''
        this.passwordRepeat = ''
        this.mnemonic = ''
        this.mode = ''
        await this.$router.push('/wallet')
      } catch (error) {
        const message =
          error instanceof Error && error.message === 'wallet mismatch'
            ? 'That mnemonic belongs to a different wallet.'
            : 'Wallet setup could not be completed. Check your details and try again.'
        this.$q.notify({type: 'negative', message})
      } finally {
        this.working = false
      }
    }
  }
}
