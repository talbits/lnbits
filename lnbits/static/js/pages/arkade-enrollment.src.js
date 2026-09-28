// `ARKADE_ENROLLMENT_TEST` is a build-time flag injected by esbuild
// (`--define:ARKADE_ENROLLMENT_TEST=false` in production, `true` in tests).
// It is not declared here on purpose; the production bundle strips it.
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
import {
  assertFundable,
  arkadeRefunder,
  createRfqSwapRecord,
  lockupContractParams,
  rebuildRfqSwap,
  requestLightningSend,
  RfqSwapManager,
  rfqSecretsProfile,
  rfqSignerOf,
  senderIdentityForSwapRecord,
  verifyLockupAddress
} from '@arkade-os/swap'
import {nostrRfqTransport} from '@arkade-os/swap/nostr'
import {generateMnemonic, validateMnemonic} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'
const DB_NAME = 'lnbits-arkade-vault-v1'
const STORE_NAME = 'vaults'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 6e5
const IDLE_TIMEOUT_MS = 15 * 60 * 1e3
const MUTINYNET_CHECKPOINT_EXIT_DELAY_SECONDS = 512n
const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/
const NETWORK = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/
const IDENTITY_DESCRIPTOR =
  /^tr\(\[[0-9a-f]{8}\/86'\/[01]'\/0'\](?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+\/0\/\*\)$/
const isValidPin = value => value === '' || /^\d{6}$/.test(value)
// Public outgoing codes mirrored from lnbits/core/views/arkade_api.py. Only the
// generic message and a recognised code may reach the UI; never the raw
// response, request, keys, preimages or claim packets.
const OUTGOING_ERROR_CODES = /* @__PURE__ */ new Set([
  'ARKADE_ENROLLMENT_REQUIRED',
  'ARKADE_INTENT_INVALID_TRANSITION',
  'ARKADE_OUTGOING_ACCOUNT_MISMATCH',
  'ARKADE_OUTGOING_AMOUNT_INVALID',
  'ARKADE_OUTGOING_BUSY',
  'ARKADE_OUTGOING_CORRUPT',
  'ARKADE_OUTGOING_EXPIRED',
  'ARKADE_OUTGOING_IDEMPOTENCY_CONFLICT',
  'ARKADE_OUTGOING_INDEXER_INVALID',
  'ARKADE_OUTGOING_INDEXER_UNAVAILABLE',
  'ARKADE_OUTGOING_INPUT_CONFLICT',
  'ARKADE_OUTGOING_INPUT_UNAVAILABLE',
  'ARKADE_OUTGOING_INPUT_UNREGISTERED',
  'ARKADE_OUTGOING_INPUT_VALUE_MISMATCH',
  'ARKADE_OUTGOING_INPUTS_INVALID',
  'ARKADE_OUTGOING_INPUTS_MISSING',
  'ARKADE_OUTGOING_INVALID_REQUEST',
  'ARKADE_OUTGOING_NOT_ALLOWED',
  'ARKADE_OUTGOING_NOT_FOUND',
  'ARKADE_OUTGOING_OUTPUT_CONFLICT',
  'ARKADE_OUTGOING_OUTPUT_INVALID',
  'ARKADE_OUTGOING_UNAVAILABLE',
  'ARKADE_BACKING_DEFICIT',
  'ARKADE_BACKING_RECONCILIATION_REQUIRED',
  'ARKADE_DESCRIPTOR_REENROLLMENT_REQUIRED',
  'ARKADE_INSUFFICIENT_FUNDS',
  'ARKADE_TRANSACTION_ID_INVALID',
  'ARKADE_TRANSFER_AMOUNT_CONFLICT',
  'ARKADE_TRANSFER_CORRUPT',
  'ARKADE_TRANSFER_CROSS_ACCOUNT_REQUIRED',
  'ARKADE_TRANSFER_DESTINATION_NOT_FOUND',
  'ARKADE_TRANSFER_EXPIRED',
  'ARKADE_TRANSFER_MAPPING_NOT_READY',
  'ARKADE_TRANSFER_RECEIVER_INVALID',
  'ARKADE_TRANSFER_RECEIVER_NOT_ALLOWED',
  'ARKADE_TRANSFER_REQUEST_CONSUMED',
  'ARKADE_TRANSFER_SAME_WALLET',
  'ARKADE_WALLET_NOT_OWNED'
])
const outgoingErrorCode = error =>
  error?.response?.data?.detail &&
  OUTGOING_ERROR_CODES.has(error.response.data.detail)
    ? error.response.data.detail
    : ''
const outgoingErrorMessage = error =>
  `payment_error_message (${outgoingErrorCode(error)})`
const enrollmentErrorCode = error => {
  const value = error
  const detail = value?.response?.data?.detail
  return detail === 'ARKADE_ENROLLMENT_MIGRATION_REQUIRED'
    ? detail
    : error instanceof Error &&
        error.message === 'ARKADE_ENROLLMENT_MIGRATION_REQUIRED'
      ? error.message
      : ''
}
const MAX_CIPHERTEXT_BYTES = 1024 * 1024
const RECEIVE_JOURNAL_PREFIX = 'lnbits-arkade-receive-v1'
const OUTGOING_JOURNAL_PREFIX = 'lnbits-arkade-outgoing-v1'
const OUTGOING_JOURNAL_VERSION = 1
const MAX_OUTGOING_JOURNAL_RECORDS = 32
const MAX_OUTGOING_JOURNAL_BYTES = 128 * 1024
const LIGHTNING_JOURNAL_DB_NAME = 'lnbits-arkade-lightning-v1'
const LIGHTNING_JOURNAL_STORE_NAME = 'plans'
// The swap manager's own records live in the same database, one store over.
// Version 2 adds that store; the bump is one-way, like the swap package's own
// repository: an older bundle cannot open a v2 database.
const LIGHTNING_SWAP_STORE_NAME = 'rfqSwaps'
const LIGHTNING_JOURNAL_VERSION = 2
// The stored plan's own schema, which is independent of the database version
// above: a bump there must not invalidate records an earlier bundle wrote.
const LIGHTNING_JOURNAL_RECORD_VERSION = 1
const LIGHTNING_JOURNAL_STATES = /* @__PURE__ */ new Set([
  'quote_ready',
  'funding',
  'funded',
  'submitted',
  'failed'
])
const LIGHTNING_RELAY = 'wss://nostr.arkade.sh'
const LIGHTNING_NETWORK_CONFIG = {
  bitcoin: {
    solverPubkey:
      '66422c952f8dcb96e4d0c3f049cd1e265b8461b916d9913c65c2494b64b4e3ce',
    minQuoteAmountSat: 500,
    maxQuoteAmountSat: 50000
  },
  mutinynet: {
    solverPubkey:
      '3f831510a6d7678d0c90d7d6fbc4057720517e2e30681ef4c87cc57aaf57e8d5',
    minQuoteAmountSat: 1000,
    maxQuoteAmountSat: 25000
  },
  regtest: {
    solverPubkey:
      '66422c952f8dcb96e4d0c3f049cd1e265b8461b916d9913c65c2494b64b4e3ce',
    minQuoteAmountSat: 500,
    maxQuoteAmountSat: 50000
  }
}
const lightningNetworkConfig = network =>
  LIGHTNING_NETWORK_CONFIG[network] || LIGHTNING_NETWORK_CONFIG.bitcoin
const LIGHTNING_QUOTE_PAIR = 'arkade:BTC->lightning:BTC'
const LIGHTNING_FEE_BPS = 30
const LIGHTNING_REFUND_HEADROOM_SECONDS = 10_800
const OUTGOING_PHASES = /* @__PURE__ */ new Set([
  'prepared',
  'authorization_unknown',
  'submitted',
  'reconciliation_required'
])
const RECORD_FIELDS = /* @__PURE__ */ new Set([
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
let identity = null
let activeBinding = null
let idleTimer
let allocationWallet = null
let allocationWalletKey = ''
let unlockGeneration = 0
const outgoingPlans = /* @__PURE__ */ new WeakMap()
const outgoingRecoveries = /* @__PURE__ */ new Map()
const lightningPlans = /* @__PURE__ */ new Map()
class ArkadeOutgoingReconciliationError extends Error {
  reconciliationRequired = true
  status
  constructor(intentId, status) {
    super(`Arkade outgoing ${intentId} requires reconciliation`)
    this.name = 'ArkadeOutgoingReconciliationError'
    this.status = status
  }
}
class ArkadeLightningReconciliationError extends Error {
  reconciliationRequired = true
  retryRequired = true
  status
  constructor(intentId, message = 'requires reconciliation and retry') {
    super(`Arkade Lightning ${intentId} ${message}`)
    this.name = 'ArkadeLightningReconciliationError'
    this.status = 'quote_ready'
  }
}
const bytesToHex = bytes =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
const fromHex = value =>
  Uint8Array.from(value.match(/../g) || [], pair => parseInt(pair, 16))
const randomHex = bytes =>
  bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))
const receiveJournalKey = accountId =>
  `${RECEIVE_JOURNAL_PREFIX}:${location.origin}:${accountId}`
const readReceiveJournal = accountId => {
  const value = localStorage.getItem(receiveJournalKey(accountId))
  if (!value) return []
  const mappings = JSON.parse(value)
  if (!Array.isArray(mappings)) throw new Error('receive journal corrupt')
  return mappings
}
const persistReceiveMapping = (accountId, mapping) => {
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
const outgoingJournalKey = accountId =>
  `${OUTGOING_JOURNAL_PREFIX}:${location.origin}:${accountId}`
const isHex = (value, min = 2, max = 4096) =>
  typeof value === 'string' &&
  value.length >= min &&
  value.length <= max &&
  value.length % 2 === 0 &&
  /^[0-9a-f]+$/i.test(value)
const strictOutgoingJournal = value => {
  if (!Array.isArray(value) || value.length > MAX_OUTGOING_JOURNAL_RECORDS)
    return false
  return value.every(record => {
    if (!record || typeof record !== 'object') return false
    const item = record
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
        input =>
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
      new Set(item.inputs.map(input => `${input.txid}:${input.vout}`)).size !==
      item.inputs.length
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
const readOutgoingJournal = accountId => {
  const value = localStorage.getItem(outgoingJournalKey(accountId))
  if (!value) return []
  if (new TextEncoder().encode(value).byteLength > MAX_OUTGOING_JOURNAL_BYTES)
    throw new Error('outgoing journal too large')
  let journal
  try {
    journal = JSON.parse(value)
  } catch {
    throw new Error('outgoing journal corrupt')
  }
  if (!strictOutgoingJournal(journal))
    throw new Error('outgoing journal corrupt')
  return journal
}
const journalMatchesBinding = (record, accountId, binding) =>
  record.accountId === accountId &&
  binding?.account_id === accountId &&
  record.network === binding?.network &&
  record.serverUrl === binding?.server_url &&
  record.serverPubkey === binding?.server_pubkey
const persistOutgoingJournal = record => {
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
const updateOutgoingJournalPhase = (accountId, intentId, phase) => {
  const journal = readOutgoingJournal(accountId)
  const index = journal.findIndex(item => item.intentId === intentId)
  if (index < 0) throw new Error('outgoing journal entry missing')
  persistOutgoingJournal({...journal[index], phase})
}
const removeOutgoingJournal = (accountId, intentId) => {
  const journal = readOutgoingJournal(accountId).filter(
    item => item.intentId !== intentId
  )
  localStorage.setItem(outgoingJournalKey(accountId), JSON.stringify(journal))
}
const lightningJournalQuoteFields = [
  'amount_msat',
  'lockup_address',
  'max_fee_msat',
  'payment_hash',
  'quote_from_amount_sat',
  'quote_pair',
  'quote_to_amount_sat',
  'quote_valid_until',
  'refund_locktime',
  'solver_pubkey',
  'swap_rfq_id'
]
const lightningJournalStateFields = [
  'accountId',
  'bolt11',
  'fundingArkTxid',
  'fundingState',
  'idempotencyKey',
  'intentExpiresAt',
  'intentId',
  'paymentHash',
  'publicQuote',
  'refundPkScript',
  'senderPubkey',
  'version',
  'walletId'
]
const strictLightningJournalRecord = value => {
  if (!value || typeof value !== 'object') return false
  const record = value
  if (
    Object.keys(record).sort().join(',') !==
    lightningJournalStateFields.slice().sort().join(',')
  )
    return false
  const quote = record.publicQuote
  if (
    !quote ||
    Object.keys(quote).sort().join(',') !==
      lightningJournalQuoteFields.slice().sort().join(',')
  )
    return false
  return (
    record.version === LIGHTNING_JOURNAL_RECORD_VERSION &&
    typeof record.accountId === 'string' &&
    HEX32.test(record.idempotencyKey) &&
    typeof record.bolt11 === 'string' &&
    record.bolt11.length > 0 &&
    HEX64.test(record.paymentHash) &&
    typeof record.walletId === 'string' &&
    record.walletId.length > 0 &&
    HEX64.test(record.senderPubkey) &&
    typeof record.refundPkScript === 'string' &&
    /^[0-9a-f]+$/i.test(record.refundPkScript) &&
    HEX32.test(record.intentId) &&
    Number.isSafeInteger(record.intentExpiresAt) &&
    record.intentExpiresAt >= 0 &&
    LIGHTNING_JOURNAL_STATES.has(record.fundingState) &&
    (record.fundingArkTxid === null || HEX64.test(record.fundingArkTxid)) &&
    quote.payment_hash === record.paymentHash &&
    Number.isSafeInteger(quote.amount_msat) &&
    quote.amount_msat > 0 &&
    Number.isSafeInteger(quote.max_fee_msat) &&
    quote.max_fee_msat > 0 &&
    typeof quote.quote_pair === 'string' &&
    quote.quote_pair === LIGHTNING_QUOTE_PAIR &&
    Number.isSafeInteger(quote.quote_from_amount_sat) &&
    quote.quote_from_amount_sat > 0 &&
    Number.isSafeInteger(quote.quote_to_amount_sat) &&
    quote.quote_to_amount_sat > 0 &&
    Number.isSafeInteger(quote.quote_valid_until) &&
    Number.isSafeInteger(quote.refund_locktime) &&
    HEX64.test(quote.solver_pubkey) &&
    typeof quote.swap_rfq_id === 'string' &&
    quote.swap_rfq_id.length > 0 &&
    typeof quote.lockup_address === 'string' &&
    quote.lockup_address.length > 0 &&
    quote.amount_msat === record.publicQuote.amount_msat
  )
}
const openLightningJournal = () =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(
      LIGHTNING_JOURNAL_DB_NAME,
      LIGHTNING_JOURNAL_VERSION
    )
    request.onupgradeneeded = () => {
      if (
        !request.result.objectStoreNames.contains(LIGHTNING_JOURNAL_STORE_NAME)
      )
        request.result.createObjectStore(LIGHTNING_JOURNAL_STORE_NAME, {
          keyPath: 'intentId'
        })
      if (!request.result.objectStoreNames.contains(LIGHTNING_SWAP_STORE_NAME))
        request.result.createObjectStore(LIGHTNING_SWAP_STORE_NAME, {
          keyPath: 'rfqId'
        })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error('Lightning journal unavailable'))
  })
const lightningJournalTransaction = async (
  mode,
  operation,
  storeName = LIGHTNING_JOURNAL_STORE_NAME
) => {
  const db = await openLightningJournal()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, mode)
    const store = transaction.objectStore(storeName)
    let result
    transaction.oncomplete = () => {
      db.close?.()
      resolve(result)
    }
    transaction.onerror = () => {
      db.close?.()
      reject(new Error('Lightning journal unavailable'))
    }
    transaction.onabort = () => {
      db.close?.()
      reject(new Error('Lightning journal unavailable'))
    }
    try {
      operation(store, value => {
        result = value
      })
    } catch {
      db.close?.()
      reject(new Error('Lightning journal unavailable'))
    }
  })
}
const readLightningJournal = async accountId => {
  const records = await lightningJournalTransaction(
    'readonly',
    (store, set) => {
      const request = store.getAll()
      request.onsuccess = () => set(request.result || [])
      request.onerror = () => request.transaction?.abort?.()
    }
  )
  if (
    !Array.isArray(records) ||
    records.some(record => !strictLightningJournalRecord(record))
  )
    throw new Error('Lightning journal corrupt')
  return records.filter(record => record.accountId === accountId)
}
const persistLightningJournal = record => {
  if (!strictLightningJournalRecord(record))
    throw new Error('Lightning journal record invalid')
  return lightningJournalTransaction('readwrite', (store, set) => {
    const request = store.getAll()
    request.onsuccess = () => {
      const records = request.result || []
      const existing = records.find(item => item.intentId === record.intentId)
      if (existing) {
        const {
          fundingArkTxid: _oldTxid,
          fundingState: _oldState,
          ...oldImmutable
        } = existing
        const {
          fundingArkTxid: _newTxid,
          fundingState: _newState,
          ...newImmutable
        } = record
        if (JSON.stringify(oldImmutable) !== JSON.stringify(newImmutable)) {
          request.transaction?.abort?.()
          return
        }
      } else if (records.length >= MAX_OUTGOING_JOURNAL_RECORDS) {
        request.transaction?.abort?.()
        return
      }
      store.put(record)
      set(record)
    }
    request.onerror = () => request.transaction?.abort?.()
  })
}
const findLightningJournalPlan = async (accountId, facts) => {
  const records = await readLightningJournal(accountId)
  return [...records]
    .reverse()
    .find(
      record =>
        record.bolt11 === facts.raw &&
        record.paymentHash === facts.paymentHash &&
        record.fundingState !== 'failed'
    )
}
const removeLightningJournalRecord = intentId =>
  lightningJournalTransaction('readwrite', (store, set) => {
    store.delete(intentId)
    set(true)
  })
// The four-method record store `RfqSwapManager` persists through. Records are
// plain JSON; the covenant itself is not stored here - it lives in the
// wallet's contract row, which `requestLightningSend` writes before the
// address can be funded and `rebuildRfqSwap` reads back on restore.
const lightningSwapRecords = {
  saveRfqSwap: record =>
    lightningJournalTransaction(
      'readwrite',
      (store, set) => {
        store.put(record)
        set(record)
      },
      LIGHTNING_SWAP_STORE_NAME
    ),
  getRfqSwap: rfqId =>
    lightningJournalTransaction(
      'readonly',
      (store, set) => {
        const request = store.get(rfqId)
        request.onsuccess = () => set(request.result)
        request.onerror = () => request.transaction?.abort?.()
      },
      LIGHTNING_SWAP_STORE_NAME
    ),
  getAllRfqSwaps: () =>
    lightningJournalTransaction(
      'readonly',
      (store, set) => {
        const request = store.getAll()
        request.onsuccess = () => set(request.result || [])
        request.onerror = () => request.transaction?.abort?.()
      },
      LIGHTNING_SWAP_STORE_NAME
    ),
  removeRfqSwap: rfqId =>
    lightningJournalTransaction(
      'readwrite',
      (store, set) => {
        store.delete(rfqId)
        set(true)
      },
      LIGHTNING_SWAP_STORE_NAME
    )
}
let lightningSwapManager = null
let lightningSwapManagerKey = ''
let lightningSwapManagerStarted = false
const stopLightningSwapManager = () => {
  const manager = lightningSwapManager
  lightningSwapManager = null
  lightningSwapManagerKey = ''
  lightningSwapManagerStarted = false
  if (manager) void manager.stop().catch(() => {})
}
// One manager per (account, network, server). The store is per browser, not
// per account, so another LNbits account's records restore here too; they
// rebuild only while their lockup contract row is in this wallet, and a
// foreign descriptor makes the refund callback refuse rather than push.
const lightningSwapManagerFor = async (accountId, wallet) => {
  const key = JSON.stringify([
    accountId,
    activeBinding?.network,
    activeBinding?.server_url
  ])
  if (lightningSwapManager && lightningSwapManagerKey === key)
    return lightningSwapManager
  stopLightningSwapManager()
  const manager = new RfqSwapManager(
    {
      indexer: wallet.indexerProvider,
      contracts: await wallet.getContractManager(),
      repository: lightningSwapRecords
    },
    {
      events: {
        onSwapCompleted: swap => {
          void dropLightningPlanForSwap(accountId, swap.rfqId).catch(() => {})
        },
        onSwapFailed: (swap, error) => {
          // Every thrown action reports here, including ones the manager
          // retries; only the terminal failed swap is a server-visible state.
          if (swap.state !== 'failed') {
            console.error(`Arkade Lightning swap ${swap.rfqId} error`, error)
            return
          }
          void reportLightningSwapFailure(accountId, swap, error).catch(
            reportError => {
              console.error(
                `Arkade Lightning swap ${swap.rfqId} failure report failed`,
                reportError
              )
            }
          )
        }
      }
    }
  )
  manager.setCallbacks({
    refundArkade: arkadeRefunder({
      ark: wallet.arkProvider,
      indexer: wallet.indexerProvider,
      wallet,
      repository: lightningSwapRecords
    }),
    // Readiness is only "can this wallet derive the signer". The deadline is
    // the manager's business.
    canRefundArkade: async swap => {
      const record = await lightningSwapRecords.getRfqSwap(swap.rfqId)
      // A swap admitted in this same pass has no record yet: answer yes and
      // let the push's own signer resolution refuse if it really cannot.
      if (!record) return {ok: true}
      try {
        await senderIdentityForSwapRecord(wallet, rfqSignerOf(record) || {})
        return {ok: true}
      } catch {
        return {ok: false, reason: 'local refund key unavailable'}
      }
    }
  })
  lightningSwapManager = manager
  lightningSwapManagerKey = key
  return manager
}
const ensureLightningSwapManager = async (accountId, wallet) => {
  const manager = await lightningSwapManagerFor(accountId, wallet)
  if (!lightningSwapManagerStarted) {
    // Restore before start, so a swap funded in an earlier session is
    // monitored again - including its refund push, which only the manager
    // makes.
    const restored = await manager.restoreFromRepository()
    await manager.start()
    lightningSwapManagerStarted = true
    for (const failure of restored.failed)
      console.error(
        `Arkade Lightning swap ${failure.rfqId} could not be restored`,
        failure.error
      )
  }
  return manager
}
// Watching the wallet page restores in-flight swaps - including the refund
// push, which only the manager makes. Nothing stored means nothing to watch,
// so the poll timer stays off for a wallet with no Lightning swaps.
const restoreLightningSwaps = async (accountId, wallet) => {
  const records = await lightningSwapRecords.getAllRfqSwaps()
  if (records.length === 0) return null
  return ensureLightningSwapManager(accountId, wallet)
}
const dropLightningPlanForSwap = async (accountId, rfqId) => {
  const record = await lightningPlanForSwap(accountId, rfqId)
  if (record) await removeLightningJournalRecord(record.intentId)
}
const lightningPlanForSwap = async (accountId, rfqId) => {
  const records = await readLightningJournal(accountId)
  return (
    records.find(record => record.publicQuote.swap_rfq_id === rfqId) || null
  )
}
// One report per intent per page, but a failed report is retried: the manager
// re-emits while the swap keeps failing to claim.
const reportedLightningFailures = new Set()
const reportedFailureReason = error => {
  const message = typeof error?.message === 'string' ? error.message : ''
  const cleaned = message
    .replace(/[^A-Za-z0-9_.:\- ]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200)
  return cleaned || 'ARKADE_SWAP_FAILED'
}
const reportLightningSwapFailure = async (accountId, swap, error) => {
  const record = await lightningPlanForSwap(accountId, swap.rfqId)
  if (!record || reportedLightningFailures.has(record.intentId)) return
  reportedLightningFailures.add(record.intentId)
  try {
    await LNbits.api.arkadeLightningFailed(
      record.intentId,
      reportedFailureReason(error)
    )
  } catch (reportError) {
    reportedLightningFailures.delete(record.intentId)
    throw reportError
  }
  await removeLightningJournalRecord(record.intentId)
}
const lightningSwapFromPlan = (plan, now) => ({
  kind: 'lightning_send',
  rfqId: plan.swap.rfqId,
  state: 'pending',
  lockupPkScript: plan.swap.swapPkScript,
  lockup: {script: plan.swap.script, address: plan.swap.address},
  paymentHash: plan.facts.paymentHash,
  refundLocktime: plan.swap.quote.refund_locktime,
  createdAt: now,
  updatedAt: now
})
// Hand a funded lockup to the manager, once. The origin carries what the live
// swap cannot: the corridor, the funded address, the refund signer and the
// funding txid, and it is what lets the manager write this swap's first record.
const trackLightningSwap = async (plan, arkTxid) => {
  const now = Math.floor(Date.now() / 1000)
  const swap = lightningSwapFromPlan(plan, now)
  const manager = await ensureLightningSwapManager(plan.accountId, plan.wallet)
  await manager.addSwap(swap, {
    kind: 'lightning_send',
    lockupAddress: plan.swap.address,
    profile: rfqSecretsProfile(plan.swap.secrets, plan.facts.paymentHash),
    amount: plan.swap.fundAmount,
    fundingArkTxid: arkTxid
  })
}
const reconcileTerminalOutgoing = async (accountId, journal) => {
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
    } catch {}
  }
  return readOutgoingJournal(accountId)
}
const expirySeconds = value => {
  // Backend timestamps are UTC. A bare ISO string would be parsed as local
  // time, and they carry microseconds while `Date.parse` only keeps
  // milliseconds, so round down to the whole second before comparing.
  const text = String(value)
  const utcText = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text) ? text : `${text}Z`
  const seconds = Math.floor(
    typeof value === 'number' ? value : Date.parse(utcText) / 1e3
  )
  if (!Number.isSafeInteger(seconds) || seconds < 0)
    throw new Error('invalid receive expiry')
  return seconds
}
const validateBinding = (value, accountId, expected) => {
  if (
    !value ||
    value.account_id !== accountId ||
    !HEX32.test(value.enrollment_id || '') ||
    !HEX32.test(value.idempotency_key || '') ||
    !NETWORK.test(value.network || '') ||
    typeof value.server_url !== 'string' ||
    !value.server_url ||
    !HEX64.test(value.server_pubkey || '')
  )
    throw new Error('invalid enrollment response')
  if (value.state === 'pending') {
    if (
      !HEX64.test(value.nonce || '') ||
      !Number.isSafeInteger(value.expires_at) ||
      value.expires_at <= Math.floor(Date.now() / 1e3) ||
      (expected?.idempotencyKey &&
        value.idempotency_key !== expected.idempotencyKey)
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
const openVault = () =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () =>
      request.result.createObjectStore(STORE_NAME, {keyPath: 'accountId'})
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error('vault unavailable'))
  })
const readVault = async accountId => {
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
const writeVault = async record => {
  const db = await openVault()
  return new Promise((resolve, reject) => {
    const request = db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(record)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(new Error('vault unavailable'))
  })
}
const getIdempotencyKey = async accountId => {
  const current = await readVault(accountId)
  if (current?.idempotencyKey && HEX32.test(current.idempotencyKey))
    return current.idempotencyKey
  if (current) throw new Error('vault metadata corrupt')
  const idempotencyKey = randomHex(16)
  await writeVault({accountId, idempotencyKey})
  return idempotencyKey
}
const aad = (accountId, network, xonly) =>
  new TextEncoder().encode(
    ['lnbits-arkade-vault-v1', location.origin, accountId, network, xonly].join(
      '\n'
    )
  )
const passwordKey = async (
  password,
  salt,
  iterations = PBKDF2_ITERATIONS,
  usages = ['encrypt', 'decrypt']
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
const strictRecord = record =>
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
const makeIdentity = (mnemonic, network) => {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('invalid mnemonic')
  return MnemonicIdentity.fromMnemonic(mnemonic, {
    isMainnet: network === 'bitcoin'
  })
}
const encryptVault = async (
  accountId,
  mnemonic,
  password,
  network,
  xonly,
  idempotencyKey
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
const decryptVault = async (accountId, password, record, binding) => {
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
const statement = (challenge, xonly, descriptor) =>
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
const digest = async value =>
  new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  )
const receiveStatement = mapping =>
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
const getAllocationWallet = async (accountId, binding) => {
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
    minCheckpointExitDelaySeconds:
      binding.network === 'mutinynet'
        ? MUTINYNET_CHECKPOINT_EXIT_DELAY_SECONDS
        : void 0,
    settlementConfig: false
  })
  allocationWalletKey = key
  return allocationWallet
}
const outgoingWallet = async (accountId, binding) => {
  const testWallet = ARKADE_ENROLLMENT_TEST
    ? window.__ARKADE_ENROLLMENT_TEST__?.wallet
    : void 0
  return testWallet || getAllocationWallet(accountId, binding)
}
const lightningInvoiceFacts = bolt11 => {
  const value = String(bolt11 || '')
    .trim()
    .toLowerCase()
  const decoder = window.decode
  if (!value || typeof decoder !== 'function')
    throw new Error('Arkade Lightning invoice decoder unavailable')
  let decoded
  try {
    decoded = decoder(value)
  } catch {
    throw new Error('Arkade Lightning invoice is invalid')
  }
  const amountMsat = decoded?.human_readable_part?.amount
  const timestamp = decoded?.data?.time_stamp
  const tags = Array.isArray(decoded?.data?.tags) ? decoded.data.tags : []
  const paymentHash = tags.find(
    tag => tag?.description === 'payment_hash'
  )?.value
  const expiry = tags.find(tag => tag?.description === 'expiry')?.value ?? 3600
  const expiresAt = timestamp + expiry
  if (
    !Number.isSafeInteger(amountMsat) ||
    amountMsat <= 0 ||
    amountMsat % 1000 !== 0 ||
    !Number.isSafeInteger(timestamp) ||
    !Number.isSafeInteger(expiresAt) ||
    !HEX64.test(paymentHash || '')
  )
    throw new Error('Arkade Lightning invoice is invalid')
  return {
    raw: value,
    paymentHash: paymentHash.toLowerCase(),
    amountMsat,
    amountSats: amountMsat / 1000,
    expiresAt
  }
}
// The card charges its spread on the funded amount, not the net invoice.
const lightningMaxFeeSat = amountSats =>
  Math.ceil((amountSats * LIGHTNING_FEE_BPS) / (10_000 - LIGHTNING_FEE_BPS))
const lightningMaxFeeMsat = amountSats => lightningMaxFeeSat(amountSats) * 1000
const lightningPublicQuote = (facts, swap) => {
  const quote = swap?.quote
  if (
    !quote ||
    quote.v !== 1 ||
    quote.type !== 'rfq_quote' ||
    quote.pair !== LIGHTNING_QUOTE_PAIR ||
    !Number.isSafeInteger(quote.from_amount) ||
    !Number.isSafeInteger(quote.to_amount) ||
    !Number.isSafeInteger(quote.valid_until) ||
    !Number.isSafeInteger(quote.refund_locktime) ||
    !HEX64.test(quote.solver_pubkey || '') ||
    typeof quote.rfq_id !== 'string' ||
    !quote.rfq_id ||
    quote.rfq_id !== swap.rfqId
  )
    throw new Error('Arkade Lightning quote binding changed')
  if (
    quote.solver_pubkey !==
    lightningNetworkConfig(activeBinding?.network).solverPubkey
  )
    throw new Error('Arkade Lightning solver is not approved')
  if (
    quote.to_amount !== facts.amountSats ||
    quote.from_amount < quote.to_amount
  )
    throw new Error('Arkade Lightning quote amount changed')
  const now = Math.floor(Date.now() / 1000)
  if (quote.refund_locktime < now + LIGHTNING_REFUND_HEADROOM_SECONDS)
    throw new Error('Arkade Lightning refund window is too short')
  assertFundable({
    quote,
    invoiceExpiresAt: facts.expiresAt,
    now,
    maxFee: {sats: lightningMaxFeeSat(facts.amountSats)}
  })
  if (
    !Number.isSafeInteger(swap.fundAmount) ||
    typeof swap.address !== 'string' ||
    !swap.address ||
    swap.fundAmount !== quote.from_amount
  )
    throw new Error('Arkade Lightning lockup changed')
  try {
    const testVerifier =
      ARKADE_ENROLLMENT_TEST &&
      window.__ARKADE_ENROLLMENT_TEST__?.verifyLockupAddress
    const verifier =
      typeof testVerifier === 'function' ? testVerifier : verifyLockupAddress
    verifier(quote, swap.address)
  } catch {
    throw new Error('Arkade Lightning lockup changed')
  }
  return {
    payment_hash: facts.paymentHash,
    amount_msat: facts.amountMsat,
    max_fee_msat: lightningMaxFeeMsat(facts.amountSats),
    quote_pair: quote.pair,
    quote_from_amount_sat: quote.from_amount,
    quote_to_amount_sat: quote.to_amount,
    quote_valid_until: quote.valid_until,
    refund_locktime: quote.refund_locktime,
    solver_pubkey: quote.solver_pubkey,
    swap_rfq_id: quote.rfq_id,
    lockup_address: swap.address
  }
}
const sameLightningBinding = (
  intent,
  facts,
  sdkQuote,
  swap,
  publicQuote,
  expectedBinding
) => {
  try {
    return (
      intent?.status === 'quote_ready' &&
      intent.account_id === expectedBinding.accountId &&
      intent.wallet_id === expectedBinding.walletId &&
      expirySeconds(intent.expires_at) === expectedBinding.expiresAt &&
      intent.destination_kind === 'lightning' &&
      intent.destination === facts.raw &&
      intent.bolt11 === facts.raw &&
      intent.payment_hash === facts.paymentHash &&
      intent.amount_msat === facts.amountMsat &&
      intent.max_fee_msat === publicQuote.max_fee_msat &&
      intent.quote_pair === publicQuote.quote_pair &&
      intent.quote_from_amount_sat === publicQuote.quote_from_amount_sat &&
      intent.quote_to_amount_sat === publicQuote.quote_to_amount_sat &&
      expirySeconds(intent.quote_valid_until) === sdkQuote.valid_until &&
      intent.refund_locktime === sdkQuote.refund_locktime &&
      intent.solver_pubkey ===
        lightningNetworkConfig(activeBinding?.network).solverPubkey &&
      intent.solver_pubkey === sdkQuote.solver_pubkey &&
      intent.swap_rfq_id === sdkQuote.rfq_id &&
      intent.swap_rfq_id === swap.rfqId &&
      intent.lockup_address === swap.address &&
      publicQuote.lockup_address === swap.address &&
      swap.fundAmount === intent.quote_from_amount_sat &&
      swap.quote.to_amount === intent.quote_to_amount_sat &&
      swap.quote.from_amount === intent.quote_from_amount_sat &&
      swap.quote.pair === intent.quote_pair &&
      swap.quote.valid_until === sdkQuote.valid_until &&
      swap.quote.refund_locktime === sdkQuote.refund_locktime
    )
  } catch {
    return false
  }
}
const lightningApprovalSummary = (facts, intent, swap, quote) =>
  Object.freeze({
    status: 'quote_ready',
    intentId: intent.intent_id,
    bolt11: facts.raw,
    paymentHash: facts.paymentHash,
    amountMsat: facts.amountMsat,
    amountSat: facts.amountSats,
    invoiceExpiresAt: facts.expiresAt,
    intentExpiresAt: intent.expires_at,
    maxFeeMsat: quote.max_fee_msat,
    maxFeeSat: quote.max_fee_msat / 1000,
    feeMsat: (quote.quote_from_amount_sat - quote.quote_to_amount_sat) * 1000,
    feeSat: quote.quote_from_amount_sat - quote.quote_to_amount_sat,
    quotePair: quote.quote_pair,
    quoteFromAmountSat: quote.quote_from_amount_sat,
    quoteToAmountSat: quote.quote_to_amount_sat,
    quoteValidUntil: quote.quote_valid_until,
    refundLocktime: quote.refund_locktime,
    solverPubkey: quote.solver_pubkey,
    swapRfqId: quote.swap_rfq_id,
    lockupAddress: quote.lockup_address,
    fundAmount: swap.fundAmount
  })
const lightningSdkQuote = publicQuote => ({
  v: 1,
  type: 'rfq_quote',
  rfq_id: publicQuote.swap_rfq_id,
  pair: publicQuote.quote_pair,
  from_amount: publicQuote.quote_from_amount_sat,
  to_amount: publicQuote.quote_to_amount_sat,
  solver_pubkey: publicQuote.solver_pubkey,
  valid_until: publicQuote.quote_valid_until,
  refund_locktime: publicQuote.refund_locktime
})
const lightningIntentFromJournal = record => ({
  intent_id: record.intentId,
  account_id: record.accountId,
  wallet_id: record.walletId,
  amount_msat: record.publicQuote.amount_msat,
  max_fee_msat: record.publicQuote.max_fee_msat,
  destination: record.bolt11,
  bolt11: record.bolt11,
  payment_hash: record.paymentHash,
  quote_pair: record.publicQuote.quote_pair,
  quote_from_amount_sat: record.publicQuote.quote_from_amount_sat,
  quote_to_amount_sat: record.publicQuote.quote_to_amount_sat,
  quote_valid_until: new Date(
    record.publicQuote.quote_valid_until * 1000
  ).toISOString(),
  refund_locktime: record.publicQuote.refund_locktime,
  solver_pubkey: record.publicQuote.solver_pubkey,
  swap_rfq_id: record.publicQuote.swap_rfq_id,
  lockup_address: record.publicQuote.lockup_address,
  destination_kind: 'lightning',
  expires_at: new Date(record.intentExpiresAt * 1000).toISOString(),
  status: 'quote_ready',
  arkade_txid:
    record.fundingState === 'submitted' ? record.fundingArkTxid : null
})
const restoreLightningSwap = async (wallet, record) => {
  const manager = await wallet.getContractManager()
  const restored = rebuildRfqSwap(
    {
      kind: 'lightning_send',
      rfqId: record.publicQuote.swap_rfq_id,
      lockupAddress: record.publicQuote.lockup_address,
      profile: {hashlock: {paymentHash: record.paymentHash}},
      state: 'pending',
      createdAt: 0,
      updatedAt: 0
    },
    await lockupContractParams(manager, record.publicQuote.lockup_address)
  )
  return {
    ...restored,
    quote: lightningSdkQuote(record.publicQuote),
    rfqId: record.publicQuote.swap_rfq_id,
    address: record.publicQuote.lockup_address,
    fundAmount: record.publicQuote.quote_from_amount_sat
  }
}
const lightningJournalFromPlan = plan => ({
  // IndexedDB stores only public intent/quote and funding state. The live
  // swap's secrets are reconstructed from the wallet's registered contract.
  version: LIGHTNING_JOURNAL_RECORD_VERSION,
  accountId: plan.accountId,
  walletId: plan.intent.wallet_id,
  idempotencyKey: plan.idempotencyKey,
  bolt11: plan.facts.raw,
  paymentHash: plan.facts.paymentHash,
  intentId: plan.intent.intent_id,
  intentExpiresAt: expirySeconds(plan.intent.expires_at),
  publicQuote: plan.publicQuote,
  senderPubkey: bytesToHex(plan.swap.senderPubkey),
  refundPkScript: bytesToHex(plan.swap.secrets.pkScript),
  fundingState: plan.fundingState,
  fundingArkTxid: plan.fundingArkTxid
})
const persistLightningPlanState = async (plan, state, arkTxid = null) => {
  plan.fundingState = state
  plan.fundingArkTxid = arkTxid
  await persistLightningJournal(lightningJournalFromPlan(plan))
}
const lightningPlanFromRecord = async (record, wallet, current) => {
  const facts = lightningInvoiceFacts(record.bolt11)
  const swap = {
    ...(await restoreLightningSwap(wallet, record)),
    senderPubkey: fromHex(record.senderPubkey),
    secrets: {pkScript: fromHex(record.refundPkScript)}
  }
  const intent = current || lightningIntentFromJournal(record)
  if (
    !sameLightningBinding(intent, facts, swap.quote, swap, record.publicQuote, {
      accountId: record.accountId,
      walletId: record.walletId,
      expiresAt: record.intentExpiresAt
    })
  )
    throw new Error('Arkade Lightning intent changed')
  return {
    accountId: record.accountId,
    idempotencyKey: record.idempotencyKey,
    facts,
    wallet,
    swap,
    publicQuote: record.publicQuote,
    intent,
    summary: lightningApprovalSummary(facts, intent, swap, record.publicQuote),
    generation: unlockGeneration,
    bindingFingerprint: outgoingBindingFingerprint(activeBinding),
    fundingPromise: null,
    fundingState: record.fundingState,
    fundingArkTxid: record.fundingArkTxid
  }
}
const prepareLightningSend = async bolt11 => {
  const accountId = window.g.user.id
  if (!identity || !activeBinding || activeBinding.state !== 'ready')
    throw new Error('wallet is locked')
  const facts = lightningInvoiceFacts(bolt11)
  const networkConfig = lightningNetworkConfig(activeBinding.network)
  if (
    facts.amountSats < networkConfig.minQuoteAmountSat ||
    facts.amountSats > networkConfig.maxQuoteAmountSat
  )
    throw new Error(
      'Arkade Lightning invoice amount is outside the solver range'
    )
  const wallet = await outgoingWallet(accountId, activeBinding)
  const persisted = await findLightningJournalPlan(accountId, facts)
  if (persisted) {
    const current = (await LNbits.api.arkadeOutgoingIntent(persisted.intentId))
      .data
    if (current.status !== 'quote_ready')
      throw new ArkadeLightningReconciliationError(
        persisted.intentId,
        'cannot resume this non-quote-ready intent'
      )
    const plan = await lightningPlanFromRecord(persisted, wallet, current)
    lightningPlans.set(persisted.intentId, plan)
    return plan.summary
  }
  let swap
  let transport
  try {
    const testRequest =
      ARKADE_ENROLLMENT_TEST &&
      window.__ARKADE_ENROLLMENT_TEST__?.requestLightningSend
    if (typeof testRequest === 'function') {
      swap = await testRequest(wallet, activeBinding.server_url, facts)
    } else {
      transport = nostrRfqTransport({
        relays: [LIGHTNING_RELAY],
        solverPubkey: networkConfig.solverPubkey
      })
      swap = await requestLightningSend(
        wallet,
        activeBinding.server_url,
        transport,
        {invoice: facts}
      )
    }
  } catch (error) {
    console.error('Arkade Lightning quote request failed', error)
    throw new Error('Arkade Lightning quote request failed')
  } finally {
    await transport?.close?.()
  }
  const publicQuote = lightningPublicQuote(facts, swap)
  const apiWallet = window.g.wallet || window.g.user?.wallets?.[0]
  if (!apiWallet?.adminkey)
    throw new Error('Arkade Lightning wallet unavailable')
  const idempotencyKey = randomHex(16)
  let response
  try {
    response = (
      await LNbits.api.payArkadeLightning(
        apiWallet,
        {bolt11: facts.raw, quote: publicQuote},
        idempotencyKey
      )
    ).data
  } catch (error) {
    throw new Error(outgoingErrorMessage(error))
  }
  const intent = response?.intent
  if (
    !intent?.wallet_id ||
    !sameLightningBinding(intent, facts, swap.quote, swap, publicQuote, {
      accountId,
      walletId: intent.wallet_id,
      expiresAt: expirySeconds(intent.expires_at)
    })
  )
    throw new Error('Arkade Lightning reservation changed')
  const summary = lightningApprovalSummary(facts, intent, swap, publicQuote)
  const plan = {
    accountId,
    idempotencyKey,
    facts,
    wallet,
    swap,
    publicQuote,
    intent,
    summary,
    generation: unlockGeneration,
    bindingFingerprint: outgoingBindingFingerprint(activeBinding),
    fundingPromise: null,
    fundingState: 'quote_ready',
    fundingArkTxid: null
  }
  await persistLightningJournal(lightningJournalFromPlan(plan))
  lightningPlans.set(intent.intent_id, plan)
  return summary
}
const submitLightningSend = async (intentId, approval) => {
  if (!approval || approval.approved !== true)
    throw new Error('Arkade Lightning approval required')
  const plan = lightningPlans.get(intentId)
  if (!plan) throw new Error('Arkade Lightning preparation is invalid')
  if (
    !outgoingContextIsLive(
      plan.accountId,
      plan.generation,
      plan.bindingFingerprint
    )
  )
    throw new Error('Arkade Lightning preparation is locked')
  const current = (await LNbits.api.arkadeOutgoingIntent(intentId)).data
  if (current.status === 'submitted') {
    if (!HEX64.test(current.arkade_txid || ''))
      throw new Error('Arkade Lightning funding changed')
    if (plan.fundingArkTxid && current.arkade_txid !== plan.fundingArkTxid)
      throw new Error('Arkade Lightning funding changed')
    await persistLightningPlanState(plan, 'submitted', current.arkade_txid)
    return {status: 'submitted', intentId, arkTxid: current.arkade_txid}
  }
  if (plan.fundingState === 'failed')
    throw new ArkadeLightningReconciliationError(intentId)
  if (
    !sameLightningBinding(
      current,
      plan.facts,
      plan.swap.quote,
      plan.swap,
      plan.publicQuote,
      {
        accountId: plan.accountId,
        walletId: plan.intent.wallet_id,
        expiresAt: expirySeconds(plan.intent.expires_at)
      }
    )
  )
    throw new Error('Arkade Lightning intent changed')
  // The quote's window is a FUNDING gate. A swap that is already funded must
  // still be submittable after it: the money is at the lockup, and refusing
  // here strands the intent - funded, unreported and unresumable.
  if (plan.fundingState === 'quote_ready') {
    try {
      lightningPublicQuote(plan.facts, plan.swap)
    } catch {
      throw new Error('Arkade Lightning quote is no longer fundable')
    }
  }
  if (plan.fundingState === 'funding' && !plan.fundingPromise)
    throw new ArkadeLightningReconciliationError(intentId)
  if (
    !plan.fundingPromise &&
    plan.fundingState === 'funded' &&
    plan.fundingArkTxid
  ) {
    // A funded swap from an earlier session, or a hand-off that failed before
    // the tab closed: re-admitting it is idempotent and restores monitoring.
    try {
      await trackLightningSwap(plan, plan.fundingArkTxid)
    } catch (error) {
      console.error('Arkade Lightning swap tracking failed', error)
    }
  }
  if (
    plan.fundingState !== 'quote_ready' &&
    plan.fundingState !== 'funded' &&
    plan.fundingState !== 'submitted' &&
    plan.fundingState !== 'funding'
  )
    throw new ArkadeLightningReconciliationError(
      intentId,
      'funding state requires reconciliation'
    )
  if (!plan.fundingPromise && plan.fundingState === 'quote_ready') {
    plan.fundingPromise = (async () => {
      try {
        await persistLightningPlanState(plan, 'funding')
        if (
          !outgoingContextIsLive(
            plan.accountId,
            plan.generation,
            plan.bindingFingerprint
          )
        )
          throw new Error('Arkade Lightning preparation is locked')
        const arkTxid = await plan.wallet.send({
          address: plan.swap.address,
          amount: plan.swap.fundAmount
        })
        if (typeof arkTxid !== 'string' || !/^[0-9a-f]{64}$/.test(arkTxid))
          throw new Error('Arkade Lightning funding result invalid')
        await persistLightningPlanState(plan, 'funded', arkTxid)
        // The manager owns the swap from here: contract registration, refund
        // push and terminal classification. A store failure leaves the
        // payment committed and unmonitored, so it is reported, not raised.
        try {
          await trackLightningSwap(plan, arkTxid)
        } catch (error) {
          console.error('Arkade Lightning swap tracking failed', error)
        }
        return arkTxid
      } catch {
        try {
          await persistLightningPlanState(
            plan,
            'failed',
            plan.fundingArkTxid || null
          )
        } catch {}
        throw new Error('Arkade Lightning funding failed')
      }
    })()
  }
  const arkTxid = plan.fundingPromise
    ? await plan.fundingPromise
    : plan.fundingArkTxid
  if (!HEX64.test(arkTxid || ''))
    throw new ArkadeLightningReconciliationError(intentId)
  const submitted = (
    await LNbits.api.arkadeLightningSubmitted(intentId, {
      ark_txid: arkTxid,
      lockup_address: plan.swap.address,
      swap_rfq_id: plan.swap.rfqId,
      solver_pubkey: plan.swap.quote.solver_pubkey,
      sender_pubkey: bytesToHex(plan.swap.senderPubkey),
      refund_pk_script: bytesToHex(plan.swap.secrets.pkScript)
    })
  ).data
  if (submitted.status !== 'submitted' || submitted.arkade_txid !== arkTxid)
    throw new Error('Arkade Lightning submission changed')
  await persistLightningPlanState(plan, 'submitted', arkTxid)
  return {status: 'submitted', intentId, arkTxid}
}
const requestMatchesMapping = (request, mapping) =>
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
const acknowledgementMatchesMapping = (response, mapping) => {
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
const acknowledgeReceive = async (accountId, mapping) => {
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
const allocateReceive = async (walletId, payment) => {
  const accountId = window.g.user.id
  if (!identity || !activeBinding || activeBinding.state !== 'ready')
    throw new Error('wallet is locked')
  if (
    payment?.protocol !== 'arkade' ||
    typeof payment.native_id !== 'string' ||
    !HEX32.test(payment.native_id) ||
    payment.wallet_id !== walletId ||
    !Number.isSafeInteger(payment.amount) ||
    payment.amount < 1e3 ||
    payment.amount % 1e3 !== 0
  )
    throw new Error('invalid Arkade payment')
  const nativeRequestId = payment.native_id
  const request = (await LNbits.api.arkadeReceiveRequest(nativeRequestId)).data
  const amountSat = payment.amount / 1e3
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
    mapping2 => mapping2.nativeRequestId === nativeRequestId
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
    action: 'lnbits-arkade-receive-v1',
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
  intent,
  intentId,
  walletId,
  accountId,
  binding
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
    intent.amount_msat % 1e3 !== 0 ||
    intent.max_fee_msat !== 0 ||
    typeof intent.destination !== 'string' ||
    !intent.destination
  )
    throw new Error('Arkade outgoing intent changed')
  const expiresAt = expirySeconds(intent.expires_at)
  const status = intent.status
  if (status !== 'reserved' && status !== 'submitted')
    throw new Error('Arkade outgoing intent is not submit-ready')
  if (status === 'reserved' && expiresAt <= Math.floor(Date.now() / 1e3))
    throw new Error('Arkade outgoing intent expired')
  let decoded
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
    amountSat: intent.amount_msat / 1e3,
    destinationScript,
    status
  }
}
const outgoingBindingFingerprint = binding =>
  JSON.stringify([
    binding?.account_id,
    binding?.network,
    binding?.server_url,
    binding?.server_pubkey,
    binding?.identity_xonly_pubkey,
    binding?.identity_descriptor
  ])
const outgoingContextIsLive = (accountId, generation, bindingFingerprint) =>
  !!identity &&
  generation === unlockGeneration &&
  accountId === window.g.user.id &&
  !!activeBinding &&
  activeBinding.state === 'ready' &&
  bindingFingerprint === outgoingBindingFingerprint(activeBinding)
const outgoingPlanIsLive = plan =>
  outgoingContextIsLive(
    plan.accountId,
    plan.generation,
    plan.bindingFingerprint
  )
const outgoingInputSummary = input => ({
  txid: input.txid,
  vout: input.vout,
  amount_sat: input.value,
  script: input.script
})
const outgoingChangeCommitment = (wallet, address) => {
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
const outgoingPreview = plan => {
  const inputs = plan.inputs.map(input => ({
    ...input,
    tapLeafScript: input.forfeitTapLeafScript
  }))
  return buildOffchainTx(inputs, plan.outputs, plan.wallet.serverUnrollScript)
}
const outgoingCommitment = plan => {
  const preview = outgoingPreview(plan)
  return JSON.stringify({
    arkTx: bytesToHex(preview.arkTx.toBytes()),
    checkpoints: preview.checkpoints.map(tx => bytesToHex(tx.toBytes()))
  })
}
const outgoingJournalFromPlan = (plan, phase) => ({
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
const outgoingJournalResponseMatches = (record, response, binding) => {
  try {
    if (
      !response ||
      response.intent_id !== record.intentId ||
      response.account_id !== record.accountId ||
      response.wallet_id !== record.walletId ||
      response.amount_msat !== record.amountSat * 1e3 ||
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
          item =>
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
const outgoingJournalForPlan = plan => {
  const journal = outgoingJournalFromPlan(plan, 'prepared')
  if (!journalMatchesBinding(journal, plan.accountId, activeBinding))
    throw new Error('Arkade outgoing binding changed')
  persistOutgoingJournal(journal)
}
const prepareOutgoing = async (intentId, walletId) => {
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
  let change = null
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
  const plan = {
    publicPlan: null,
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
  const publicPlan = Object.freeze({
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
const sameOutgoingInputs = (expected, actual) =>
  expected.length === actual.length &&
  expected.every(input =>
    actual.some(
      item =>
        item.txid === input.txid &&
        item.vout === input.vout &&
        item.amount_sat === input.value
    )
  )
const sameOutgoingPlan = (plan, response) =>
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
const submitOutgoing = async (prepared, approval) => {
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
    snapshot.amountSat * 1e3 !== plan.amountMsat ||
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
  let authorization
  try {
    authorization = (
      await LNbits.api.arkadeOutgoingAuthorize(plan.intentId, request)
    ).data
  } catch {
    let afterFailure
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
      status: 'submitted',
      reconciliationRequired: true,
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
const outgoingJournalResponseBindingMatches = (record, response, binding) => {
  try {
    return (
      response?.intent_id === record.intentId &&
      response.account_id === record.accountId &&
      response.wallet_id === record.walletId &&
      response.amount_msat === record.amountSat * 1e3 &&
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
const releasedOutgoingJournalMatches = (record, response, binding) =>
  record.phase === 'prepared' &&
  response?.status === 'released' &&
  outgoingJournalResponseBindingMatches(record, response, binding) &&
  Array.isArray(response.inputs) &&
  response.inputs.length === 0 &&
  response.destination_script === null &&
  response.change_index === null &&
  response.change_script === null &&
  response.change_amount_sat === null
const exactOutgoingVtxos = (vtxos, record) => {
  const result = []
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
const fetchExactOutgoingVtxos = async (wallet, manager, inputs) => {
  const response = await wallet.indexerProvider.getVtxos({
    outpoints: inputs.map(({txid, vout}) => ({txid, vout}))
  })
  if (!response || !Array.isArray(response.vtxos))
    throw new Error('Arkade outgoing recovery unavailable')
  return manager.annotateVtxos(response.vtxos)
}
const outgoingRecoveryPreview = (wallet, record, inputs) => {
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
const outgoingRecoveryArtifacts = (wallet, record, inputs) => {
  if (inputs.some(input => !isSpendable(input)))
    throw new Error('Arkade outgoing VTXO is no longer spendable')
  const {outputs, commitment} = outgoingRecoveryPreview(wallet, record, inputs)
  if (commitment !== record.previewCommitment)
    throw new Error('outgoing journal commitment mismatch')
  return {inputs, outputs}
}
const hydrateOutgoingJournal = async (
  wallet,
  manager,
  response,
  accountId,
  binding
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
  const inputs = response.inputs.map(claim => {
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
  const base = {
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
  try {
    await restoreLightningSwaps(accountId, wallet)
  } catch (error) {
    console.error('Arkade Lightning swap manager unavailable', error)
  }
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
const recoverOutgoing = async (intentId, approval) => {
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
  let manager
  try {
    manager = await wallet.getContractManager()
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  if (
    !manager ||
    typeof manager.refreshVtxos !== 'function' ||
    typeof manager.annotateVtxos !== 'function'
  ) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  const scripts = [
    ...record.inputs.map(input => input.script),
    ...(record.change ? [record.change.script] : [])
  ]
  try {
    await manager.refreshVtxos({scripts: [...new Set(scripts)]})
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  let response
  try {
    response = (await LNbits.api.arkadeOutgoingIntent(intentId)).data
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  if (!outgoingJournalResponseBindingMatches(record, response, activeBinding)) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  if (response.status === 'reserved')
    return {intentId, status: response.status, phase: record.phase}
  if (response.status === 'released') {
    if (releasedOutgoingJournalMatches(record, response, activeBinding)) {
      removeOutgoingJournal(accountId, intentId)
      return {intentId, status: response.status, reconciliationRequired: false}
    }
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  if (!outgoingJournalResponseMatches(record, response, activeBinding)) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
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
    return {intentId, phase: 'reconciliation_required'}
  }
  let allVtxos
  let inputs
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
    return {intentId, phase: 'reconciliation_required'}
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
    return {intentId, phase: 'reconciliation_required'}
  }
  let finalization
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
    return {intentId, phase: 'reconciliation_required'}
  }
  try {
    response = (await LNbits.api.arkadeOutgoingIntent(intentId)).data
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  if (!outgoingJournalResponseMatches(record, response, activeBinding)) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
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
    return {intentId, phase: 'reconciliation_required'}
  }
  if (response.status !== 'submitted') {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
  if (
    !outgoingContextIsLive(
      accountId,
      recoveryGeneration,
      recoveryBindingFingerprint
    )
  ) {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
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
      status: 'submitted',
      reconciliationRequired: true,
      intentId,
      arkTxid: result.arkTxid
    }
  } catch {
    updateOutgoingJournalPhase(accountId, intentId, 'reconciliation_required')
    return {intentId, phase: 'reconciliation_required'}
  }
}
const recoverOutgoingSerialized = (intentId, approval) => {
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
  let idempotencyKey
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
    const xonly2 = bytesToHex(await identity.xOnlyPublicKey())
    if (
      challenge.identity_xonly_pubkey !== xonly2 ||
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
const unlock = async password => {
  const accountId = window.g.user.id
  if (!activeBinding) await probe()
  const record = await readVault(accountId)
  if (!record || !strictRecord(record)) throw new Error('vault unavailable')
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
  // The manager polls through the wallet below; both go together.
  stopLightningSwapManager()
  const wallet = allocationWallet
  allocationWallet = null
  allocationWalletKey = ''
  if (wallet) void wallet.dispose().catch(() => {})
  if (idleTimer) window.clearTimeout(idleTimer)
  idleTimer = void 0
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
  async enroll(mnemonic, password, acknowledged) {
    const clean = mnemonic.trim().split(/\s+/).join(' ')
    if (!validateMnemonic(clean, wordlist) || !isValidPin(password))
      throw new Error('invalid wallet details')
    if (!acknowledged) throw new Error('backup acknowledgement required')
    const accountId = window.g.user.id
    const key = await getIdempotencyKey(accountId)
    const challenge = validateBinding(
      (await LNbits.api.arkadeEnrollmentChallenge(key)).data,
      accountId,
      {idempotencyKey: key, previous: activeBinding || void 0}
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
  async unlock(password) {
    return unlock(password)
  },
  async finish() {
    await finish()
  },
  async allocateReceive(walletId, payment) {
    return allocateReceive(walletId, payment)
  },
  async prepareOutgoing(intentId, walletId) {
    return prepareOutgoing(intentId, walletId)
  },
  async submitOutgoing(prepared, approval) {
    return submitOutgoing(prepared, approval)
  },
  async prepareLightningSend(bolt11) {
    return prepareLightningSend(bolt11)
  },
  async submitLightningSend(intentId, approval) {
    return submitLightningSend(intentId, approval)
  },
  async listOutgoing() {
    return listOutgoing()
  },
  async recoverOutgoing(intentId, approval) {
    return recoverOutgoingSerialized(intentId, approval)
  },
  async binding() {
    return activeBinding
  }
}
if (ARKADE_ENROLLMENT_TEST && window.__ARKADE_ENROLLMENT_TEST__) {
  window.ArkadeEnrollment.__setTestReady = (binding, wallet) => {
    activeBinding = binding
    identity = {}
    window.__ARKADE_ENROLLMENT_TEST__.wallet = wallet
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
      mnemonicWords: Array(12).fill(''),
      password: '',
      passwordRepeat: '',
      backupAcknowledged: false,
      backup: {
        step: 1,
        visible: false,
        challenge: [],
        answers: {},
        error: ''
      }
    }
  },
  computed: {
    seedWords() {
      return this.mnemonic
        .split(/\s+/)
        .filter(Boolean)
        .map((word, index) => ({index, word}))
    }
  },
  async created() {
    if (this.g.user?.installationMode !== 'arkade_noncustodial')
      return this.$router.replace('/')
    await this.inspect()
  },
  methods: {
    async goToWallet() {
      const {data} = await LNbits.api.request(
        'GET',
        '/api/v1/wallet/paginated',
        null
      )
      const walletId = data.data?.[0]?.id
      await this.$router.push(walletId ? `/wallet/${walletId}` : '/wallet')
    },
    prepareChallenge() {
      const words = this.mnemonic.split(/\s+/).filter(Boolean)
      const count = Math.min(4, words.length)
      const indexes = _.shuffle([...Array(words.length).keys()]).slice(0, count)
      this.backup.challenge = indexes
        .sort((a, b) => a - b)
        .map(index => ({index, word: words[index]}))
      this.backup.answers = {}
      this.backup.error = ''
      this.backup.step = 2
    },
    submitChallenge() {
      const isValid =
        this.backup.challenge.length > 0 &&
        this.backup.challenge.every(({index, word}) => {
          const answer = this.backup.answers[index] || ''
          return answer.trim().toLowerCase() === word.toLowerCase()
        })
      if (!isValid) {
        this.backup.error =
          'One or more words are incorrect. Check your backup and try again.'
        return
      }
      this.backupAcknowledged = true
      this.backup.visible = false
    },
    async inspect() {
      this.loading = true
      try {
        this.state = (await window.ArkadeEnrollment.inspect()).state
        this.g.arkadeEnrollmentState = this.state
        if (this.state === 'wallet_locked') {
          try {
            const pending = await window.ArkadeEnrollment.unlock('')
            this.state = pending ? 'pending_unlocked' : 'ready_unlocked'
            this.g.arkadeEnrollmentState = this.state
            if (!pending) await this.goToWallet()
          } catch {}
        }
      } catch (error) {
        this.state =
          enrollmentErrorCode(error) === 'ARKADE_ENROLLMENT_MIGRATION_REQUIRED'
            ? 'migration_required'
            : 'unavailable'
      } finally {
        this.loading = false
      }
    },
    startCreate() {
      this.mode = 'create'
      this.mnemonic = generateMnemonic(wordlist, 128)
      this.mnemonicWords = Array(12).fill('')
      this.password = ''
      this.passwordRepeat = ''
      this.backupAcknowledged = false
      this.backup = {
        step: 1,
        visible: false,
        challenge: [],
        answers: {},
        error: ''
      }
    },
    pasteMnemonic(event, index) {
      const words =
        event.clipboardData?.getData('text').trim().split(/\s+/) || []
      if (words.length <= 1) return
      event.preventDefault()
      this.mnemonicWords.splice(
        index,
        words.length,
        ...words.slice(0, 12 - index)
      )
    },
    startRestore() {
      this.mode = 'restore'
      this.mnemonic = ''
      this.mnemonicWords = Array(12).fill('')
      this.password = ''
      this.passwordRepeat = ''
      this.backupAcknowledged = true
    },
    cancel() {
      this.mode = ''
      this.mnemonic = ''
      this.mnemonicWords = Array(12).fill('')
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
        await this.goToWallet()
      } catch {
        this.password = ''
        this.$q.notify({
          type: 'negative',
          message: 'Could not unlock this wallet. Check your password.'
        })
      } finally {
        this.working = false
      }
    },
    async finish() {
      this.working = true
      try {
        await window.ArkadeEnrollment.finish()
        await this.goToWallet()
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
        const mnemonic =
          this.mode === 'restore'
            ? this.mnemonicWords.join(' ').trim()
            : this.mnemonic
        await window.ArkadeEnrollment.enroll(
          mnemonic,
          this.password,
          this.backupAcknowledged
        )
        this.password = ''
        this.passwordRepeat = ''
        this.mnemonic = ''
        this.mode = ''
        await this.goToWallet()
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
