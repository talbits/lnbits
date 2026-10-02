const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')

global.window = {}
global._ = require('underscore')
global.moment = require('moment')
global.Quasar = {LocalStorage: {getItem() {}}, Notify: {create() {}}}
const keys = []
const releases = []
const prepares = []
const submits = []
const recoveries = []
const dialogMessages = []
const notifications = []
let attempts = 0
let prepareFails = false
let cancelApproval = false
let preparedAmount = 42
let terminalResponse = false
let recoveryRecords = []
let recoveryResult = {
  status: 'reconciliation_required',
  reconciliationRequired: true
}
let outgoingJournalCount = 0
let listOutgoingCalls = 0
global.LNbits = {
  api: {
    async payArkade(_wallet, _address, _amount, key) {
      keys.push(key)
      if (terminalResponse)
        return {data: {browser_required: false, status: 'success'}}
      if (attempts++ === 0) throw new Error('response lost')
      return {data: {browser_required: true, intent_id: '11'.repeat(16)}}
    },
    async arkadeOutgoingRelease(intentId) {
      releases.push(intentId)
    },
    async arkadeOutgoingIntent() {
      return {data: {status: 'released'}}
    }
  },
  utils: {notifyApiError() {}, formatSat: String}
}
window.ArkadeEnrollment = {
  async prepareOutgoing(...args) {
    prepares.push(args)
    outgoingJournalCount += 1
    if (prepareFails) throw new Error('prepare failed')
    return {
      amountSat: preparedAmount,
      destination: 'tark1qqqqqq',
      inputs: [{amount_sat: 50}],
      change: {amount_sat: 8}
    }
  },
  async submitOutgoing(_prepared, approval) {
    submits.push(approval)
    assert.deepEqual(approval, {approved: true})
  },
  async listOutgoing() {
    listOutgoingCalls += 1
    if (outgoingJournalCount >= 32) outgoingJournalCount = 0
    return recoveryRecords
  },
  async recoverOutgoing(intentId, approval) {
    recoveries.push({intentId, approval})
    assert.deepEqual(approval, {approved: true})
    if (recoveryResult.status === 'settled') recoveryRecords = []
    return recoveryResult
  }
}
vm.runInThisContext(
  fs.readFileSync('lnbits/static/js/pages/wallet.js', 'utf8'),
  {filename: 'wallet.js'}
)

const component = window.PageWallet
const page = {
  ...component.data(),
  g: {
    wallet: {id: 'wallet', sat: 100, adminkey: 'admin'},
    updatePayments: false,
    user: {installationMode: 'arkade_noncustodial'}
  },
  canPay: true,
  $t: value => value,
  $q: {
    dialog() {
      const dialog = arguments[0]
      dialogMessages.push(dialog)
      return {
        onOk(callback) {
          if (!cancelApproval) callback()
          return this
        },
        onCancel(callback) {
          if (cancelApproval) callback()
          return this
        }
      }
    },
    notify(value) {
      notifications.push(value)
    }
  }
}
for (const [name, method] of Object.entries(component.methods))
  page[name] = method.bind(page)

// Exercise decoding independently of the SDK and live solver.
Quasar.date = {formatDate: value => value.toISOString()}
const now = Math.floor(Date.now() / 1000)
global.decode = request => {
  if (request !== 'ln-invoice') throw new Error('invalid invoice')
  return {
    human_readable_part: {amount: 2100000},
    data: {
      time_stamp: now,
      tags: [{description: 'expiry', value: 3600}]
    }
  }
}
const address = 'tark1qqqqqq'
for (const [request, amount] of [
  [address, null],
  [`bitcoin:?ark=${address}`, null],
  [`bitcoin:?ark=${address}&amount=0.000021`, 2100],
  [`bitcoin:btc?ark=${address}&lightning=ln-invoice&amount=0.000021`, 2100],
  [
    `BITCOIN:?ARK=${address.toUpperCase()}&LIGHTNING=ln-invoice&AMOUNT=0.000021`,
    2100
  ],
  [arkadeReceiveBip21(address, 2100000), 2100]
]) {
  page.parse.data.request = request
  assert.doesNotThrow(() => page.decodeRequest())
  assert.equal(page.parse.arkade?.address, address)
  assert.equal(page.parse.arkade.amount, amount)
  assert.equal(page.parse.invoice, null)
}
for (const request of [
  'bitcoin:?lightning=ln-invoice',
  'BITCOIN:?LIGHTNING=ln-invoice',
  'lightning:ln-invoice'
]) {
  page.parse.data.request = request
  assert.doesNotThrow(() => page.decodeRequest())
  assert.equal(page.parse.arkade, null)
  assert.equal(page.parse.invoice.bolt11, 'ln-invoice')
  assert.equal(page.parse.invoice.expired, false)
}
let scans = 0
page.lnurlScan = () => {
  scans++
}
for (const request of [
  'bitcoin:?LIGHTNING=LNURL1TEST',
  'lnurl:LNURL1TEST',
  'lightning:LNURL1TEST'
]) {
  page.parse.data.request = request
  page.decodeRequest()
  assert.equal(page.parse.arkade, null)
  assert.equal(page.parse.invoice, null)
}
assert.equal(scans, 3)
for (const request of [
  'bitcoin:?ark=invalid',
  'bitcoin:?ark=tark1qqqqqq&amount=0.000000001',
  'bitcoin:?ark=tark1qqqqqq&amount=90071993',
  'bitcoin:?ark=tark1qqqqqq&amount=-1',
  'bitcoin:?ark=%ZZ',
  'bitcoin:?lightning=',
  'bitcoin:?ark=tark1qqqqqq&ARK=tark1pppppp'
]) {
  page.parse.data.request = request
  assert.doesNotThrow(() => page.decodeRequest())
  assert.equal(page.parse.arkade, null)
  assert.equal(page.parse.invoice, null)
  assert.equal(page.parse.show, false)
}
// Copied from the upstream wallet fixture; unified requests prefer Arkade.
const upstreamUnified =
  'bitcoin:bcrt1pj7fdvrpdsn0cl6722tmcvwcw4yqpe46020g43nhgzl90qq4aqjrs33du9f?ark=tark1qplnj2gett9j483fchy6chaxn4y52c4g7n5djh9xua3ywdxw0ldatc3e9xcj9xpx0r5tmr0dgvu2f4s352muklg0tcxx0scnnkraajy9jgz4xl&lightning=lnbcrt21u1p5tqtaypp56yzglgfgwsm5pd49996jqvtmpf8fqdk7cq2znnjw5c2j5t8ua38qdql2djkuepqw3hjqs2jfvsxzerywfjhxuccqz95xqztfsp586s5vpsdxt05rm7hr6ycwq5ffmnx2gngv820seugky6j6z2wxqwq9qxpqysgqepuxr82pvlp8lgj7nqu8yp2f5q32323jxddx9qgtjhfhsyzvftgkwx8qv4772fzz46pwyw5ex3u7lf7na8a8403ur3gyeu22gv29rpspefzz2y&amount=0.000021'
page.parse.data.request = upstreamUnified
page.decodeRequest()
assert.equal(
  page.parse.arkade.address,
  'tark1qplnj2gett9j483fchy6chaxn4y52c4g7n5djh9xua3ywdxw0ldatc3e9xcj9xpx0r5tmr0dgvu2f4s352muklg0tcxx0scnnkraajy9jgz4xl'
)
assert.equal(page.parse.arkade.amount, 2100)
assert.equal(page.parse.invoice, null)
// Check the real BOLT11 decoder as well as the deterministic table above.
const stubDecode = global.decode
vm.runInThisContext(
  fs.readFileSync('lnbits/static/js/bolt11-decoder.js', 'utf8')
)
page.parse.data.request =
  'BITCOIN:?LIGHTNING=' +
  new URLSearchParams(upstreamUnified.split('?')[1]).get('lightning')
page.decodeRequest()
assert.equal(page.parse.arkade, null)
assert.ok(page.parse.invoice)
assert.equal(page.parse.invoice.expired, true)
global.decode = stubDecode
const freshDecode = global.decode
global.decode = request => {
  const invoice = freshDecode(request)
  invoice.data.time_stamp = now - 3601
  return invoice
}
page.parse.data.request = 'ln-invoice'
page.decodeRequest()
assert.equal(page.parse.invoice.expired, true)
global.decode = freshDecode
page.parse.invoice = null

page.parse.show = true
page.parse.data.request = 'tark1qqqqqq'
page.decodeRequest()
page.parse.arkade.amount = 42

;(async () => {
  await page.payArkade()
  await page.payArkade()
  assert.equal(keys.length, 2)
  assert.match(keys[0], /^[0-9a-f]{32}$/)
  assert.equal(keys[0], keys[1])
  assert.equal(releases.length, 0)

  page.parse.data.request = 'tark1qqqqqq'
  page.decodeRequest()
  page.parse.arkade.amount = 42
  prepareFails = true
  await page.payArkade()
  assert.deepEqual(releases, ['11'.repeat(16)])

  prepareFails = false
  const dialogsBeforePay = dialogMessages.length
  await page.payArkade()
  assert.equal(releases.length, 1)
  assert.notEqual(keys[2], keys[3])
  assert.equal(dialogMessages.length, dialogsBeforePay)
  assert.equal(page.parse.sending, false)

  // Editing the amount binds a new key; retries of the same request reuse it.
  page.parse.arkade.amount = 43
  preparedAmount = 43
  await page.payArkade()
  assert.notEqual(keys[3], keys[4])
  await page.payArkade()
  assert.equal(keys[4], keys[5])
  preparedAmount = 42
  page.parse.arkade.amount = 42

  // A backend/prepared mismatch must never be approved or signed.
  const submitsBeforeMismatch = submits.length
  preparedAmount = 41
  await page.payArkade()
  assert.equal(submits.length, submitsBeforeMismatch)
  assert.equal(page.parse.sending, false)
  preparedAmount = 42

  const originalSubmit = window.ArkadeEnrollment.submitOutgoing
  window.ArkadeEnrollment.submitOutgoing = async () => {
    throw Object.assign(new Error('unknown outcome'), {
      reconciliationRequired: true
    })
  }
  page.parse.show = true
  await page.payArkade()
  assert.equal(page.parse.sending, false)
  assert.equal(page.parse.show, false)
  assert.match(notifications.at(-1).message, /before retrying/)
  window.ArkadeEnrollment.submitOutgoing = originalSubmit

  terminalResponse = true
  page.parse.show = true
  const preparesBeforeTerminal = prepares.length
  const submitsBeforeTerminal = submits.length
  const releasesBeforeTerminal = releases.length
  const updatesBeforeTerminal = page.g.updatePayments
  const recoveryCallsBeforeTerminal = listOutgoingCalls
  await page.payArkade()
  assert.equal(page.parse.show, false)
  assert.equal(page.g.updatePayments, !updatesBeforeTerminal)
  assert.equal(releases.length, releasesBeforeTerminal)
  assert.equal(prepares.length, preparesBeforeTerminal)
  assert.equal(submits.length, submitsBeforeTerminal)
  assert.ok(listOutgoingCalls >= recoveryCallsBeforeTerminal)
  assert.deepEqual(notifications.at(-1), {
    type: 'positive',
    message: 'payment_successful'
  })

  terminalResponse = false
  recoveryRecords = []
  outgoingJournalCount = 0
  for (let index = 0; index < 33; index++) {
    page.parse.show = true
    page.parse.data.request = 'tark1qqqqqq'
    page.decodeRequest()
    page.parse.arkade.amount = 42
    await page.payArkade()
  }
  assert.ok(outgoingJournalCount < 32)
  assert.ok(listOutgoingCalls >= 33)

  recoveryRecords = [
    {
      intentId: '22'.repeat(16),
      phase: 'authorization_unknown',
      amountSat: 42,
      destination: 'tark1qqqqqq'
    }
  ]
  await page.refreshArkadeRecovery()
  assert.equal(page.arkadeRecovery.length, 1)
  const originalList = window.ArkadeEnrollment.listOutgoing
  window.ArkadeEnrollment.listOutgoing = async () => {
    throw new Error('offline')
  }
  await page.refreshArkadeRecovery()
  assert.equal(page.arkadeRecovery.length, 1)
  window.ArkadeEnrollment.listOutgoing = originalList
  recoveryResult = {status: 'submitted', reconciliationRequired: true}
  await page.recoverArkadeOutgoing(page.arkadeRecovery[0])
  assert.match(dialogMessages.at(-1).message, /42 sat to tark1qqqqqq/)
  assert.equal(page.arkadeRecovery.length, 1)
  assert.deepEqual(notifications.at(-1), {
    type: 'info',
    message: 'Arkade payment submitted.'
  })
  recoveryResult = {
    status: 'reconciliation_required',
    reconciliationRequired: true
  }
  await page.recoverArkadeOutgoing(page.arkadeRecovery[0])
  assert.deepEqual(notifications.at(-1), {
    type: 'warning',
    message: 'Arkade payment still requires reconciliation.'
  })
  recoveryResult = {status: 'settled', reconciliationRequired: false}
  await page.recoverArkadeOutgoing(page.arkadeRecovery[0])
  assert.deepEqual(recoveries, [
    {intentId: '22'.repeat(16), approval: {approved: true}},
    {intentId: '22'.repeat(16), approval: {approved: true}},
    {intentId: '22'.repeat(16), approval: {approved: true}}
  ])
  assert.equal(page.arkadeRecovery.length, 0)

  const dialogsBeforeLightningSend = dialogMessages.length
  const lightningInvoices = []
  const lightningSubmits = []
  const apiRequests = []
  let fundingFails = false
  window.ArkadeEnrollment.prepareLightningSend = async (invoice, maxFeeSat) => {
    assert.equal(maxFeeSat, 100)
    lightningInvoices.push(invoice)
    return {
      intentId: 'lightning',
      bolt11: invoice,
      amountSat: 1000,
      feeSat: 4,
      fundAmount: 1004
    }
  }
  window.ArkadeEnrollment.submitLightningSend = async (intentId, approval) => {
    lightningSubmits.push({intentId, approval})
    if (fundingFails) throw new Error('funding response lost')
  }
  LNbits.api.request = async (...args) => {
    apiRequests.push(args)
    return {data: {payment_request: 'ln-invoice-from-lnurl'}}
  }
  LNbits.api.payInvoice = async () => {
    throw new Error('Arkade must use browser approval before funding')
  }
  page.parse.data.request = 'ln-direct-invoice'
  page.parse.show = true
  await page.payInvoice()
  assert.equal(lightningSubmits.length, 0)
  assert.equal(page.parse.lightningQuote.feeSat, 4)
  page.parse.lightningFeeCap = 3
  await page.payInvoice()
  assert.equal(lightningSubmits.length, 0)
  assert.match(notifications.at(-1).caption, /fee exceeds/)
  page.parse.lightningFeeCap = 100
  await page.payInvoice()
  assert.deepEqual(lightningInvoices, ['ln-direct-invoice'])
  assert.deepEqual(lightningSubmits, [
    {intentId: 'lightning', approval: {approved: true}}
  ])
  assert.equal(apiRequests.length, 0)
  assert.equal(page.parse.sending, false)
  assert.equal(page.parse.show, false)
  // PAY pays: the Arkade path funds the prepared swap with no second dialog.
  assert.equal(dialogMessages.length, dialogsBeforeLightningSend)

  page.parse.data.request = 'user@example.com'
  page.parse.data.amount = 1000
  await page.payLnurl()
  assert.equal(apiRequests[0][1], '/api/v1/payments/lnurl/prepare')
  assert.equal(apiRequests[0][2], 'admin')
  assert.equal(apiRequests[0][3].amount, 1000000)
  assert.equal(lightningInvoices.at(-1), 'ln-invoice-from-lnurl')
  assert.equal(lightningSubmits.length, 1)
  await page.payInvoice()
  assert.equal(lightningSubmits.length, 2)
  assert.equal(page.parse.sending, false)

  // A second PAY funds again; nothing is released because nothing was cancelled.
  const releasesBeforeSecondSend = releases.length
  await page.payInvoice()
  await page.payInvoice()
  assert.equal(lightningSubmits.length, 3)
  assert.equal(releases.length, releasesBeforeSecondSend)
  const releasesBeforeFunding = releases.length
  fundingFails = true
  notifications.length = 0
  await page.payInvoice()
  await page.payInvoice()
  assert.equal(releases.length, releasesBeforeFunding)
  assert.equal(page.parse.sending, false)
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].message, 'payment_error_message')
  assert.match(notifications[0].caption, /Check the Lightning journal/)
  fundingFails = false

  // A refused reservation surfaces the localized message plus the backend's
  // stable code, never the raw response or a masked generic failure.
  page.parse.lightningQuote = null
  notifications.length = 0
  window.ArkadeEnrollment.prepareLightningSend = async () => {
    throw new Error('payment_error_message (ARKADE_BACKING_DEFICIT)')
  }
  const submitsBeforeRefusal = lightningSubmits.length
  await page.payInvoice()
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].message, 'payment_error_message')
  assert.equal(notifications[0].caption, 'ARKADE_BACKING_DEFICIT')
  assert.equal(lightningSubmits.length, submitsBeforeRefusal)
  assert.equal(page.parse.sending, false)

  // Unknown errors have safe guidance and never leak the raw failure.
  notifications.length = 0
  window.ArkadeEnrollment.prepareLightningSend = async () => {
    throw new Error('some internal failure')
  }
  await page.payInvoice()
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].message, 'payment_error_message')
  assert.match(notifications[0].caption, /Payment preparation failed/)
  window.ArkadeEnrollment.prepareLightningSend = async invoice => {
    lightningInvoices.push(invoice)
    return {
      intentId: 'lightning',
      bolt11: invoice,
      amountSat: 1000,
      feeSat: 4,
      fundAmount: 1004
    }
  }

  for (const reason of [
    'invoice_expired',
    'quote_expired',
    'insufficient_headroom',
    'non_positive_amount',
    'max_fee_unbounded',
    'max_fee_out_of_range',
    'fee_gate_unavailable',
    'fee_too_high'
  ]) {
    window.ArkadeEnrollment.prepareLightningSend = async () => {
      throw Object.assign(new Error('private SDK response'), {reason})
    }
    await page.payInvoice()
    assert.ok(notifications.at(-1).caption)
    assert.doesNotMatch(notifications.at(-1).caption, /private SDK response/)
  }
  for (const message of [
    'wallet is locked',
    'Arkade Lightning invoice is invalid',
    'Arkade Lightning invoice is expired',
    'Arkade Lightning invoice decoder unavailable',
    'Arkade Lightning invoice amount is outside the solver range',
    'Arkade Lightning quote request failed',
    'Arkade Lightning wallet unavailable',
    'Arkade Lightning reservation changed'
  ]) {
    window.ArkadeEnrollment.prepareLightningSend = async () => {
      throw new Error(message)
    }
    await page.payInvoice()
    assert.ok(notifications.at(-1).caption)
    assert.doesNotMatch(
      notifications.at(-1).caption,
      /Payment preparation failed/
    )
  }
  window.ArkadeEnrollment.prepareLightningSend = async () => {
    throw Object.assign(new Error('private intent ID'), {
      reconciliationRequired: true
    })
  }
  await page.payInvoice()
  assert.match(notifications.at(-1).caption, /reconciliation/)
  const savedEnrollment = window.ArkadeEnrollment
  delete window.ArkadeEnrollment
  await page.payInvoice()
  assert.match(notifications.at(-1).caption, /wallet is unavailable/)
  window.ArkadeEnrollment = savedEnrollment

  // The unified scan uses the native send, and never calls the solver.
  page.parse.data.request = `bitcoin:?ark=${address}&lightning=ln-invoice&amount=0.00000042`
  page.decodeRequest()
  terminalResponse = true
  const lightningCallsBeforeUnified = lightningInvoices.length
  await page.payArkade()
  assert.equal(lightningInvoices.length, lightningCallsBeforeUnified)
  assert.equal(page.parse.show, false)

  // Recheck expiry at PAY, including a QR that expires while the dialog is open.
  page.parse.data.request = 'ln-invoice'
  page.decodeRequest()
  page.parse.invoice = {...page.parse.invoice, expiresAt: 0}
  const submitsBeforeExpired = lightningSubmits.length
  await page.payInvoice()
  assert.match(notifications.at(-1).message, /Invoice has expired/)
  assert.equal(lightningSubmits.length, submitsBeforeExpired)
  page.parse.invoice = null

  await paymentDetailsChecks()

  // Custodial sends keep their existing API and never ask for Arkade approval.
  page.g.user.installationMode = 'custodial'
  let custodialCalls = 0
  LNbits.api.payInvoice = async () => {
    custodialCalls += 1
    return {data: {status: 'pending'}}
  }
  Quasar.Notify.create = () => () => {}
  const lightningBeforeCustodial = lightningInvoices.length
  page.payInvoice()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(custodialCalls, 1)
  assert.equal(lightningInvoices.length, lightningBeforeCustodial)
})().catch(error => {
  console.error(error)
  process.exitCode = 1
})

async function paymentDetailsChecks() {
  const Vue = require('vue')
  const {renderToString} = require('vue/server-renderer')
  const components = {}
  window.app = {
    component: (name, value) => {
      components[name] = value
    }
  }
  global.QrcodeVue = {}
  vm.runInThisContext(fs.readFileSync('lnbits/static/js/components.js', 'utf8'))
  vm.runInThisContext(
    fs.readFileSync(
      'lnbits/static/js/components/lnbits-payment-list.js',
      'utf8'
    )
  )
  const map = components['lnbits-payment-list'].methods.mapPayment.bind({
    utils: {formatDate: String, formatDateFrom: String, formatSat: String}
  })
  const template = fs
    .readFileSync('lnbits/templates/components.vue', 'utf8')
    .split('<template id="lnbits-payment-details">')[1]
    .split('<template id="lnbits-dynamic-fields">')[0]
    .replace(/<\/template>\s*$/, '')
  const render = Vue.compile(template)
  for (const arkade of [true, false]) {
    const payment = map({
      amount: 42000,
      fee: 0,
      status: 'success',
      memo: 'test',
      payment_hash: arkade ? null : 'ab'.repeat(32),
      bolt11: arkade ? null : 'ln-invoice',
      native_id: arkade ? 'cd'.repeat(32) : null,
      arkade_address: arkade ? address : null
    })
    const app = Vue.createSSRApp(
      {...components['lnbits-payment-details'], template: undefined, render},
      {payment}
    )
    app.config.globalProperties.$t = value => value
    app.config.globalProperties.g = {denomination: 'sat'}
    app.config.globalProperties.utils = {copyText() {}}
    app.config.compilerOptions.isCustomElement = name => name.startsWith('q-')
    // Quasar's presentational tags are inert for this render regression.
    app.config.warnHandler = () => {}
    const html = await renderToString(app)
    assert.equal(html.includes(address), arkade)
    assert.equal(html.includes('payment_hash'), !arkade)
    assert.equal(html.includes('ln-invoice'), !arkade)
    if (arkade) {
      assert.equal(payment.native_id, 'cd'.repeat(32))
      const methods = components['lnbits-payment-list'].methods
      assert.notEqual(
        methods.paymentTableRowKey(payment),
        methods.paymentTableRowKey({...payment, native_id: 'ef'.repeat(32)})
      )
      const requests = []
      const originalRequest = LNbits.api.request
      LNbits.api.request = async (...args) => {
        requests.push(args)
      }
      await methods.savePaymentLabels.call(
        {
          selectedPayment: payment,
          payments: [payment],
          wallet: {adminkey: 'admin'},
          $t: value => value
        },
        ['test']
      )
      assert.equal(
        requests[0][1],
        `/api/v1/payments/${payment.native_id}/labels`
      )
      assert.deepEqual(payment.labels, ['test'])
      LNbits.api.request = originalRequest
    }
  }
  const users = fs.readFileSync('lnbits/templates/pages/users.vue', 'utf8')
  const face = users.match(/<q-btn[^>]+icon="face"[^>]*>[\s\S]*?<\/q-btn>/)[0]
  for (const installationMode of ['arkade_noncustodial', 'custodial']) {
    const app = Vue.createSSRApp({
      render: Vue.compile(face),
      data: () => ({
        g: {user: {installationMode}},
        props: {row: {id: 'user'}},
        impersonateUser() {}
      })
    })
    app.config.globalProperties.$t = value => value
    app.config.warnHandler = () => {}
    const html = await renderToString(app)
    assert.equal(html.includes('face'), installationMode === 'custodial')
  }
  const funding = fs
    .readFileSync('lnbits/templates/components/admin/funding.vue', 'utf8')
    .replace(/^<template[^>]+>/, '')
    .replace(/<\/template>\s*$/, '')
  const fundingRender = Vue.compile(funding)
  vm.runInThisContext(
    fs.readFileSync(
      'lnbits/static/js/components/admin/lnbits-admin-funding.js',
      'utf8'
    )
  )
  for (const installationMode of ['arkade_noncustodial', 'custodial']) {
    const app = Vue.createSSRApp({
      render: fundingRender,
      data: () => ({
        g: {user: {installationMode}, settings: {}},
        settings: {},
        formData: {},
        auditData: {},
        isSuperUser: true
      })
    })
    app.config.globalProperties.$t = value => value
    app.config.warnHandler = () => {}
    const html = await renderToString(app)
    assert.equal(
      html.includes('lnbits-admin-funding-sources'),
      installationMode === 'custodial'
    )
    assert.equal(
      html.includes('A custodial Lightning funding source is not used'),
      installationMode === 'arkade_noncustodial'
    )
    let calls = 0
    const oldRequest = LNbits.api.request
    LNbits.api.request = () => {
      calls++
      return Promise.resolve({data: {}})
    }
    components['lnbits-admin-funding'].methods.getAudit.call({
      g: {user: {installationMode, wallets: [{adminkey: 'test'}]}}
    })
    assert.equal(calls, installationMode === 'custodial' ? 1 : 0)
    LNbits.api.request = oldRequest
  }
  const list = fs.readFileSync(
    'lnbits/templates/components/lnbits-payment-list.vue',
    'utf8'
  )
  const check = list.match(
    /<q-btn[^>]+@click="checkPayment\(props.row.payment_hash\)"[^>]*>/
  )[0]
  assert.match(check, /v-if="props.row.payment_hash"/)
}
