const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')

global.window = {}
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
  utils: {notifyApiError() {}}
}
window.ArkadeEnrollment = {
  async prepareOutgoing(...args) {
    prepares.push(args)
    outgoingJournalCount += 1
    if (prepareFails) throw new Error('prepare failed')
    return {
      amountSat: 42,
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
  cancelApproval = true
  await page.payArkade()
  assert.deepEqual(releases, ['11'.repeat(16), '11'.repeat(16)])
  assert.notEqual(keys[2], keys[3])

  cancelApproval = false
  await page.payArkade()
  assert.equal(releases.length, 2)
  assert.notEqual(keys[3], keys[4])

  terminalResponse = true
  page.parse.show = true
  const preparesBeforeTerminal = prepares.length
  const submitsBeforeTerminal = submits.length
  const releasesBeforeTerminal = releases.length
  const updatesBeforeTerminal = page.g.updatePayments
  await page.payArkade()
  assert.equal(page.parse.show, false)
  assert.equal(page.g.updatePayments, !updatesBeforeTerminal)
  assert.equal(releases.length, releasesBeforeTerminal)
  assert.equal(prepares.length, preparesBeforeTerminal)
  assert.equal(submits.length, submitsBeforeTerminal)
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
  assert.equal(outgoingJournalCount, 1)
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
  window.ArkadeEnrollment.prepareLightningSend = async invoice => {
    lightningInvoices.push(invoice)
    return {intentId: 'lightning', amountSat: 1000, feeSat: 4, fundAmount: 1004}
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
  assert.equal(lightningSubmits.length, 2)
  assert.equal(page.parse.sending, false)

  // A second PAY funds again; nothing is released because nothing was cancelled.
  const releasesBeforeSecondSend = releases.length
  await page.payInvoice()
  assert.equal(lightningSubmits.length, 3)
  assert.equal(releases.length, releasesBeforeSecondSend)
  const releasesBeforeFunding = releases.length
  fundingFails = true
  notifications.length = 0
  await page.payInvoice()
  assert.equal(releases.length, releasesBeforeFunding)
  assert.equal(page.parse.sending, false)
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].message, 'payment_error_message')
  assert.equal(notifications[0].caption, null)
  fundingFails = false

  // A refused reservation surfaces the localized message plus the backend's
  // stable code, never the raw response or a masked generic failure.
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

  // An unrecognised failure keeps the safe generic message and no caption.
  notifications.length = 0
  window.ArkadeEnrollment.prepareLightningSend = async () => {
    throw new Error('some internal failure')
  }
  await page.payInvoice()
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].message, 'payment_error_message')
  assert.equal(notifications[0].caption, null)
  window.ArkadeEnrollment.prepareLightningSend = async invoice => {
    lightningInvoices.push(invoice)
    return {intentId: 'lightning', amountSat: 1000, feeSat: 4, fundAmount: 1004}
  }

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
