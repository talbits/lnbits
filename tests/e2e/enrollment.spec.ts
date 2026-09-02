import {test, expect} from '@playwright/test'
import {readFile} from 'node:fs/promises'
import {resolve} from 'node:path'
import {createHash} from 'node:crypto'
import {schnorr} from '@noble/curves/secp256k1.js'

const modulePath = resolve(
  __dirname,
  '../../lnbits/static/js/pages/arkade-enrollment.js'
)
const accountId = '0123456789abcdef0123456789abcdef'
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const differentMnemonic =
  'legal winner thank year wave sausage worth useful legal winner thank yellow'
const hexBytes = (value: string) =>
  Uint8Array.from(value.match(/.{2}/g) || [], pair => parseInt(pair, 16))

test('browser enrollment signs only the public proof and unlocks after reload', async ({
  page
}) => {
  const logs: string[] = []
  page.on('console', message => logs.push(message.text()))
  page.on('pageerror', error => logs.push(error.message))
  const script = await readFile(modulePath, 'utf8')
  const source = await readFile(
    resolve(__dirname, '../../lnbits/static/js/pages/arkade-enrollment.ts'),
    'utf8'
  )
  expect(source).not.toContain('ServiceWorkerWallet')
  expect(source).not.toContain('postMessage')
  expect(source).not.toContain('WebSocket')
  await page.addInitScript(script)
  await page.route('http://127.0.0.1/enrollment-test', route =>
    route.fulfill({contentType: 'text/html', body: '<!doctype html>'})
  )
  await page.goto('http://127.0.0.1/enrollment-test')
  await page.evaluate(id => {
    const challenge = {
      account_id: id,
      state: 'pending',
      enrollment_id: 'abcdefabcdefabcdefabcdefabcdefab',
      idempotency_key: '11111111111111111111111111111111',
      nonce: '2222222222222222222222222222222222222222222222222222222222222222',
      expires_at: Math.floor(Date.now() / 1000) + 600,
      network: 'regtest',
      server_url: 'http://localhost:7070',
      server_pubkey:
        '3333333333333333333333333333333333333333333333333333333333333333'
    }
    const requests: unknown[] = []
    let state = 'pending'
    window.g = {user: {id}, arkadeEnrollmentState: null}
    window.LNbits = {
      api: {
        arkadeEnrollmentChallenge: async (requestedKey: string) => {
          const response = {
            ...challenge,
            state,
            idempotency_key: requestedKey
          }
          window.__challenge = response
          return {data: response}
        },
        arkadeEnrollmentComplete: async data => {
          requests.push(data)
          state = 'ready'
          return {
            data: {
              ...challenge,
              state: 'ready',
              idempotency_key: data.idempotency_key,
              identity_xonly_pubkey: data.identity_xonly_pubkey
            }
          }
        }
      }
    }
    window.__enrollmentRequests = requests
  }, accountId)

  const canceled = await page.evaluate(phrase => {
    const model = {
      mode: 'create',
      mnemonic: phrase,
      password: 'correct horse battery',
      passwordRepeat: 'correct horse battery',
      backupAcknowledged: true
    }
    window.PageArkadeEnrollment.methods.cancel.call(model)
    return model
  }, mnemonic)
  expect(canceled.mnemonic).toBe('')
  expect(canceled.password).toBe('')
  expect(canceled.passwordRepeat).toBe('')
  expect(canceled.backupAcknowledged).toBe(false)
  expect(canceled.mode).toBe('')
  expect(await page.evaluate(() => window.__enrollmentRequests)).toHaveLength(0)

  await page.evaluate(async phrase => {
    await window.ArkadeEnrollment.enroll(phrase, 'correct horse battery', true)
  }, mnemonic)

  const result = await page.evaluate(async id => {
    const requests = window.__enrollmentRequests as Array<
      Record<string, unknown>
    >
    const record = await new Promise<any>(resolve => {
      const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () => resolve(request.result)
      }
    })
    return {
      requests,
      record,
      state: window.g.arkadeEnrollmentState,
      challenge: window.__challenge
    }
  }, accountId)
  expect(result.state).toBe('ready_unlocked')
  expect(result.requests).toHaveLength(1)
  expect(JSON.stringify(result.requests[0])).not.toContain(mnemonic)
  expect(JSON.stringify(result.requests[0])).not.toContain(
    'correct horse battery'
  )
  expect(result.record.ciphertext).toBeTruthy()
  expect(JSON.stringify(result.record)).not.toContain(mnemonic)

  const proof = result.requests[0] as Record<string, string | number>
  const canonical = [
    'action=lnbits-arkade-enrollment-v1',
    `account_id=${result.challenge.account_id}`,
    `enrollment_id=${result.challenge.enrollment_id}`,
    `idempotency_key=${result.challenge.idempotency_key}`,
    `nonce=${result.challenge.nonce}`,
    `expires_at=${result.challenge.expires_at}`,
    `network=${result.challenge.network}`,
    `server_url=${result.challenge.server_url}`,
    `server_pubkey=${result.challenge.server_pubkey}`,
    'identity_kind=mnemonic_hd',
    `identity_xonly_pubkey=${proof.identity_xonly_pubkey}`,
    'backup_acknowledged=1'
  ].join('\n')
  const proofDigest = createHash('sha256').update(canonical).digest()
  expect(
    await schnorr.verify(
      hexBytes(proof.signature as string),
      proofDigest,
      hexBytes(proof.identity_xonly_pubkey as string)
    )
  ).toBe(true)

  await page.reload()
  await page.evaluate(id => {
    window.g = {user: {id}, arkadeEnrollmentState: null}
    window.__completionCount = 0
    window.LNbits = {
      api: {
        arkadeEnrollmentChallenge: async (requestedKey: string) => ({
          data: {
            account_id: id,
            state: 'ready',
            enrollment_id: 'abcdefabcdefabcdefabcdefabcdefab',
            idempotency_key: requestedKey,
            network: 'regtest',
            server_url: 'http://localhost:7070',
            server_pubkey:
              '3333333333333333333333333333333333333333333333333333333333333333',
            identity_xonly_pubkey: ''
          }
        })
      }
    }
  }, accountId)
  // The real binding key is returned by the server; use the persisted public key.
  const bindingKey = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<string>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () => resolve(request.result.identityXonlyPubkey)
      }
    })
  }, accountId)
  await page.evaluate(bindingKey => {
    const original = window.LNbits.api.arkadeEnrollmentChallenge
    window.LNbits.api.arkadeEnrollmentChallenge = async requestedKey => {
      const result = await original(requestedKey)
      result.data.identity_xonly_pubkey = bindingKey
      return result
    }
  }, bindingKey)
  await expect(
    page.evaluate(() => window.ArkadeEnrollment.unlock('wrong password'))
  ).rejects.toThrow()
  await page.evaluate(() =>
    window.ArkadeEnrollment.unlock('correct horse battery')
  )
  expect(await page.evaluate(() => window.g.arkadeEnrollmentState)).toBe(
    'ready_unlocked'
  )

  const beforeDuplicate = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<any>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () =>
          resolve({
            salt: Array.from(new Uint8Array(request.result.salt)),
            iv: Array.from(new Uint8Array(request.result.iv))
          })
      }
    })
  }, accountId)
  await page.evaluate(async phrase => {
    await window.ArkadeEnrollment.enroll(phrase, 'another local password', true)
  }, mnemonic)
  const afterDuplicate = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<any>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () =>
          resolve({
            salt: Array.from(new Uint8Array(request.result.salt)),
            iv: Array.from(new Uint8Array(request.result.iv))
          })
      }
    })
  }, accountId)
  expect(afterDuplicate.salt).not.toEqual(beforeDuplicate.salt)
  expect(afterDuplicate.iv).not.toEqual(beforeDuplicate.iv)
  expect(await page.evaluate(() => window.__completionCount)).toBe(0)

  const surfaces = await page.evaluate(async () => {
    const cacheNames = await caches.keys()
    const cacheEntries = await Promise.all(
      cacheNames.map(async name => {
        const cache = await caches.open(name)
        return {
          name,
          urls: (await cache.keys()).map(request => request.url),
          responses: await Promise.all(
            (await cache.keys()).map(async request =>
              (await cache.match(request))?.text()
            )
          )
        }
      })
    )
    return {
      url: location.href,
      cookies: document.cookie,
      local: JSON.stringify(localStorage),
      session: JSON.stringify(sessionStorage),
      cacheNames,
      cacheEntries
    }
  })
  expect(JSON.stringify(surfaces)).not.toContain(mnemonic)
  expect(JSON.stringify(surfaces)).not.toContain('correct horse battery')
  expect(logs).toEqual([])
})

test('generated module rejects vault tampering and restores a lost ready vault', async ({
  page
}) => {
  const logs: string[] = []
  page.on('console', message => logs.push(message.text()))
  page.on('pageerror', error => logs.push(error.message))
  const script = await readFile(modulePath, 'utf8')
  await page.addInitScript(script)
  await page.route('http://127.0.0.1/enrollment-test', route =>
    route.fulfill({contentType: 'text/html', body: '<!doctype html>'})
  )
  await page.goto('http://127.0.0.1/enrollment-test')
  await page.evaluate(id => {
    const base = {
      account_id: id,
      enrollment_id: 'abcdefabcdefabcdefabcdefabcdefab',
      idempotency_key: '11111111111111111111111111111111',
      nonce: '2222222222222222222222222222222222222222222222222222222222222222',
      expires_at: Math.floor(Date.now() / 1000) + 600,
      network: 'regtest',
      server_url: 'http://localhost:7070',
      server_pubkey:
        '3333333333333333333333333333333333333333333333333333333333333333'
    }
    let state = 'pending'
    let identityKey = ''
    let challengeCalls = 0
    let mutateServerOnCall = 0
    let mutateIdempotencyOnCall = 0
    let failCompletion = false
    let completionCount = 0
    window.g = {user: {id}, arkadeEnrollmentState: null}
    window.LNbits = {
      api: {
        arkadeEnrollmentChallenge: async (requestedKey: string) => {
          challengeCalls += 1
          return {
            data: {
              ...base,
              state,
              idempotency_key:
                challengeCalls === mutateIdempotencyOnCall
                  ? '44444444444444444444444444444444'
                  : requestedKey,
              identity_xonly_pubkey: identityKey,
              ...(challengeCalls === mutateServerOnCall
                ? {server_url: 'http://other.example:7070'}
                : {})
            }
          }
        },
        arkadeEnrollmentComplete: async data => {
          completionCount += 1
          if (failCompletion) throw new Error('temporary completion failure')
          state = 'ready'
          identityKey = data.identity_xonly_pubkey
          return {
            data: {
              ...base,
              state,
              idempotency_key: data.idempotency_key,
              identity_xonly_pubkey: identityKey
            }
          }
        }
      }
    }
    window.__enrollmentCounters = {
      get challengeCalls() {
        return challengeCalls
      },
      get completionCount() {
        return completionCount
      }
    }
    window.__enrollmentTestControl = {
      get mutateServerOnCall() {
        return mutateServerOnCall
      },
      set mutateServerOnCall(value) {
        mutateServerOnCall = value
      },
      get mutateIdempotencyOnCall() {
        return mutateIdempotencyOnCall
      },
      set mutateIdempotencyOnCall(value) {
        mutateIdempotencyOnCall = value
      },
      get failCompletion() {
        return failCompletion
      },
      set failCompletion(value) {
        failCompletion = value
      }
    }
  }, accountId)
  await expect(
    page.evaluate(async phrase => {
      window.__enrollmentTestControl.mutateServerOnCall = 2
      return window.ArkadeEnrollment.enroll(
        phrase,
        'correct horse battery',
        true
      )
    }, mnemonic)
  ).rejects.toThrow()
  await page.evaluate(() => {
    window.__enrollmentTestControl.mutateServerOnCall = 0
    window.__enrollmentTestControl.failCompletion = true
    window.ArkadeEnrollment.lock()
  })
  await page.evaluate(() =>
    window.ArkadeEnrollment.unlock('correct horse battery')
  )
  await expect(
    page.evaluate(() => window.ArkadeEnrollment.finish())
  ).rejects.toThrow()
  await page.evaluate(() => {
    window.__enrollmentTestControl.failCompletion = false
  })
  await page.evaluate(() => window.ArkadeEnrollment.finish())

  const original = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<any>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () => resolve(request.result)
      }
    })
  }, accountId)
  const duplicateBefore = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<any>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () =>
          resolve({
            salt: Array.from(new Uint8Array(request.result.salt)),
            iv: Array.from(new Uint8Array(request.result.iv))
          })
      }
    })
  }, accountId)
  await page.evaluate(async phrase => {
    await window.ArkadeEnrollment.enroll(phrase, 'another local password', true)
  }, mnemonic)
  const duplicateAfter = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<any>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () =>
          resolve({
            salt: Array.from(new Uint8Array(request.result.salt)),
            iv: Array.from(new Uint8Array(request.result.iv))
          })
      }
    })
  }, accountId)
  expect(duplicateAfter.salt).not.toEqual(duplicateBefore.salt)
  expect(duplicateAfter.iv).not.toEqual(duplicateBefore.iv)
  expect(
    await page.evaluate(() => window.__enrollmentCounters.completionCount)
  ).toBe(2)
  await page.evaluate(() => {
    window.__enrollmentTestControl.mutateIdempotencyOnCall =
      window.__enrollmentCounters.challengeCalls + 1
  })
  await expect(
    page.evaluate(
      async phrase =>
        window.ArkadeEnrollment.enroll(phrase, 'another local password', true),
      mnemonic
    )
  ).rejects.toThrow()
  await page.evaluate(() => {
    window.__enrollmentTestControl.mutateIdempotencyOnCall = 0
  })
  const tamper = async (changes: Record<string, unknown>) => {
    await page.evaluate(
      async ({id, changes}) => {
        const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
        await new Promise<void>(resolve => {
          open.onsuccess = () => {
            const tx = open.result.transaction('vaults', 'readwrite')
            const store = tx.objectStore('vaults')
            const request = store.get(id)
            request.onsuccess = () => store.put({...request.result, ...changes})
            tx.oncomplete = () => resolve()
          }
        })
      },
      {id: accountId, changes}
    )
    await page.evaluate(() => window.ArkadeEnrollment.lock())
    await expect(
      page.evaluate(() =>
        window.ArkadeEnrollment.unlock('correct horse battery')
      )
    ).rejects.toThrow()
    await page.evaluate(
      async ({id, envelope}) => {
        const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
        await new Promise<void>(resolve => {
          open.onsuccess = () => {
            const tx = open.result.transaction('vaults', 'readwrite')
            tx.objectStore('vaults').put(envelope)
            tx.oncomplete = () => resolve()
          }
        })
      },
      {id: accountId, envelope: original}
    )
  }
  await tamper({version: 2})
  await tamper({iterations: 1})
  await tamper({network: 'mainnet'})
  await tamper({unknown: true})
  const corrupt = new Uint8Array(original.ciphertext)
  corrupt[0] ^= 1
  await tamper({ciphertext: corrupt.buffer})

  await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    await new Promise<void>(resolve => {
      open.onsuccess = () => {
        const tx = open.result.transaction('vaults', 'readwrite')
        const store = tx.objectStore('vaults')
        const request = store.get(id)
        request.onsuccess = () =>
          store.put({...request.result, idempotencyKey: 'bad'})
        tx.oncomplete = () => resolve()
      }
    })
    window.ArkadeEnrollment.lock()
  }, accountId)
  expect(
    await page.evaluate(() => window.ArkadeEnrollment.inspect())
  ).toMatchObject({state: 'recovery_required'})
  const preserved = await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    return new Promise<boolean>(resolve => {
      open.onsuccess = () => {
        const request = open.result
          .transaction('vaults')
          .objectStore('vaults')
          .get(id)
        request.onsuccess = () => resolve(Boolean(request.result.ciphertext))
      }
    })
  }, accountId)
  expect(preserved).toBe(true)

  await page.evaluate(async id => {
    const open = indexedDB.open('lnbits-arkade-vault-v1', 1)
    await new Promise<void>(resolve => {
      open.onsuccess = () => {
        const tx = open.result.transaction('vaults', 'readwrite')
        tx.objectStore('vaults').delete(id)
        tx.oncomplete = () => resolve()
      }
    })
  }, accountId)
  // A missing vault is recoverable only with the same root, not a rebind.
  await page.evaluate(
    async phrase =>
      window.ArkadeEnrollment.enroll(phrase, 'new correct horse', true),
    mnemonic
  )
  await page.evaluate(() => window.ArkadeEnrollment.lock())
  await expect(
    page.evaluate(
      phrase =>
        window.ArkadeEnrollment.enroll(phrase, 'new correct horse', true),
      differentMnemonic
    )
  ).rejects.toThrow()
  const surfaces = await page.evaluate(async () => {
    const cacheNames = await caches.keys()
    const cacheEntries = await Promise.all(
      cacheNames.map(async name => {
        const cache = await caches.open(name)
        const requests = await cache.keys()
        return {
          name,
          urls: requests.map(request => request.url),
          responses: await Promise.all(
            requests.map(async request => (await cache.match(request))?.text())
          )
        }
      })
    )
    return {
      url: location.href,
      cookies: document.cookie,
      local: JSON.stringify(localStorage),
      session: JSON.stringify(sessionStorage),
      cacheNames,
      cacheEntries
    }
  })
  expect(JSON.stringify(surfaces)).not.toContain(mnemonic)
  expect(JSON.stringify(surfaces)).not.toContain('correct horse battery')
  expect(JSON.stringify(surfaces)).not.toContain('new correct horse')
  expect(logs).toEqual([])
})

test('browser receive allocation retries the journaled mapping without reallocating', async ({
  page
}) => {
  const script = await readFile(modulePath, 'utf8')
  await page.addInitScript(script)
  await page.route('http://127.0.0.1/receive-test', route =>
    route.fulfill({contentType: 'text/html', body: '<!doctype html>'})
  )
  await page.goto('http://127.0.0.1/receive-test')
  await page.evaluate(id => {
    const binding = {
      account_id: id,
      enrollment_id: 'abcdefabcdefabcdefabcdefabcdefab',
      idempotency_key: '11111111111111111111111111111111',
      network: 'regtest',
      server_url: 'http://localhost:7070',
      server_pubkey:
        '3333333333333333333333333333333333333333333333333333333333333333'
    }
    let ready = false
    const request = {
      account_id: id,
      wallet_id: 'wallet-1',
      native_request_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      idempotency_key: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      amount_sat: 21,
      ...binding,
      expires_at: Math.floor(Date.now() / 1000) + 600
    }
    const acks: unknown[] = []
    let mismatchAck = false
    window.g = {user: {id}, arkadeEnrollmentState: null}
    window.LNbits = {
      api: {
        arkadeEnrollmentChallenge: async (requestedKey: string) => ({
          data: {
            ...binding,
            state: ready ? 'ready' : 'pending',
            idempotency_key: requestedKey,
            ...(ready
              ? {}
              : {
                  nonce:
                    '2222222222222222222222222222222222222222222222222222222222222222',
                  expires_at: Math.floor(Date.now() / 1000) + 600
                }),
            ...(ready ? {identity_xonly_pubkey: ''} : {})
          }
        }),
        arkadeEnrollmentComplete: async data => {
          ready = true
          return {
            data: {
              ...binding,
              state: 'ready',
              idempotency_key: data.idempotency_key,
              identity_xonly_pubkey: data.identity_xonly_pubkey
            }
          }
        },
        arkadeReceiveRequest: async () => ({data: request}),
        arkadeReceiveAck: async (data: unknown) => {
          acks.push(data)
          const payload = data as Record<string, unknown>
          return {
            data: {
              ...request,
              state: 'acknowledged',
              index: payload.index,
              address: mismatchAck ? 'ark1wrongaddress' : payload.address,
              script: payload.script,
              child_xonly_pubkey: payload.child_xonly_pubkey
            }
          }
        }
      }
    }
    window.__receiveRequest = request
    window.__receiveAcks = acks
    window.__receiveControl = {
      set mismatch(value: boolean) {
        mismatchAck = value
      }
    }
  }, accountId)

  await page.evaluate(async phrase => {
    await window.ArkadeEnrollment.enroll(phrase, 'correct horse battery', true)
  }, mnemonic)
  await page.evaluate(() => {
    const request = window.__receiveRequest as Record<string, unknown>
    const mapping = {
      action: 'lnbits-arkade-receive-v1',
      accountId: request.account_id,
      walletId: request.wallet_id,
      nativeRequestId: request.native_request_id,
      idempotencyKey: request.idempotency_key,
      amountSat: request.amount_sat,
      index: 7,
      address: 'ark1receiveaddress',
      script: '5120' + '11'.repeat(32),
      childXonlyPubkey: '22'.repeat(32),
      network: request.network,
      serverUrl: request.server_url,
      serverPubkey: request.server_pubkey,
      expiresAt: request.expires_at,
      signature: '33'.repeat(64),
      exitTapleaf: '51c0',
      exitControlBlock: 'c0' + '44'.repeat(64)
    }
    localStorage.setItem(
      `lnbits-arkade-receive-v1:${location.origin}:${request.account_id}`,
      JSON.stringify([mapping])
    )
    return window.ArkadeEnrollment.allocateReceive('wallet-1', {
      protocol: 'arkade',
      native_id: request.native_request_id,
      wallet_id: 'wallet-1',
      amount: 21000
    }).then(async first => {
      const second = await window.ArkadeEnrollment.allocateReceive('wallet-1', {
        protocol: 'arkade',
        native_id: request.native_request_id,
        wallet_id: 'wallet-1',
        amount: 21000
      })
      return {first, second, acks: window.__receiveAcks}
    })
  })
  const result = await page.evaluate(
    id => ({
      acks: window.__receiveAcks,
      journal: JSON.parse(
        localStorage.getItem(
          `lnbits-arkade-receive-v1:${location.origin}:${id}`
        ) || '[]'
      )
    }),
    accountId
  )
  expect(result.acks).toHaveLength(2)
  expect(result.journal).toHaveLength(1)
  expect((result.acks[0] as Record<string, unknown>).address).toBe(
    'ark1receiveaddress'
  )
  expect(result.acks[1]).toEqual(result.acks[0])
  await page.evaluate(() => {
    window.__receiveControl.mismatch = true
  })
  await expect(
    page.evaluate(() =>
      window.ArkadeEnrollment.allocateReceive('wallet-1', {
        protocol: 'arkade',
        native_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        wallet_id: 'wallet-1',
        amount: 21000
      })
    )
  ).rejects.toThrow('receive acknowledgement conflict')
})
