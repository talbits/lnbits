import {MnemonicIdentity} from '@arkade-os/sdk'
import {generateMnemonic, validateMnemonic} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'

const DB_NAME = 'lnbits-arkade-vault-v1'
const STORE_NAME = 'vaults'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600_000
const IDLE_TIMEOUT_MS = 15 * 60 * 1000
const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/
const NETWORK = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/
const PASSWORD_MIN_LENGTH = 12
const MAX_CIPHERTEXT_BYTES = 1024 * 1024
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

const bytesToHex = (bytes: Uint8Array) =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

const randomHex = (bytes: number) =>
  bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))

const validateBinding = (
  value: any,
  accountId: string,
  expected?: {
    idempotencyKey?: string
    identityXonlyPubkey?: string
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
      (expected?.identityXonlyPubkey &&
        value.identity_xonly_pubkey !== expected.identityXonlyPubkey))
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
    isMainnet: network === 'mainnet'
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

const statement = (challenge: any, xonly: string) =>
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
    `identity_xonly_pubkey=${xonly}`,
    'backup_acknowledged=1'
  ].join('\n')

const digest = async (value: string) =>
  new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  )

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
    if (challenge.identity_xonly_pubkey !== xonly)
      throw new Error('wallet mismatch')
    activeBinding = challenge
    window.g.arkadeEnrollmentState = 'ready_unlocked'
    return
  }
  if (challenge.state !== 'pending') throw new Error('enrollment changed')
  const xonly = bytesToHex(await identity.xOnlyPublicKey())
  const sig = bytesToHex(
    await identity.signMessage(
      await digest(statement(challenge, xonly)),
      'schnorr'
    )
  )
  const result = await LNbits.api.arkadeEnrollmentComplete({
    enrollment_id: challenge.enrollment_id,
    idempotency_key: challenge.idempotency_key,
    identity_xonly_pubkey: xonly,
    signature: sig
  })
  activeBinding = validateBinding(result.data, window.g.user.id, {
    idempotencyKey: challenge.idempotency_key,
    identityXonlyPubkey: xonly,
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
      xonly !== activeBinding.identity_xonly_pubkey)
  )
    throw new Error('wallet mismatch')
  identity = next
  window.g.arkadeEnrollmentState =
    activeBinding?.state === 'pending' ? 'pending_unlocked' : 'ready_unlocked'
  resetIdleTimer()
  return activeBinding?.state === 'pending'
}

const lock = () => {
  identity = null
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
      if (xonly !== challenge.identity_xonly_pubkey)
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
  async binding() {
    return activeBinding
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
