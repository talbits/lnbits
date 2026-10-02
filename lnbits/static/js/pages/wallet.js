const arkadeReceiveBip21 = (address, amountMsat) => {
  if (
    typeof address !== 'string' ||
    !address ||
    !Number.isSafeInteger(amountMsat) ||
    amountMsat < 1000 ||
    amountMsat % 1000 !== 0
  )
    return ''

  const satoshis = BigInt(amountMsat) / 1000n
  const whole = satoshis / 100_000_000n
  const fraction = (satoshis % 100_000_000n)
    .toString()
    .padStart(8, '0')
    .replace(/0+$/, '')
  return `bitcoin:?ark=${address}&amount=${whole}${fraction ? `.${fraction}` : ''}`
}

// Follow the upstream wallet's case-insensitive BIP21 keys and Arkade priority.
const arkadeDecodeBip21 = uri => {
  const query = uri.slice(8).split('?')[1] || ''
  const params = new Map()
  for (const [key, value] of new URLSearchParams(query)) {
    const name = key.toLowerCase()
    if (params.has(name) || name.startsWith('req-') || name === 'assetid')
      throw new Error('Unsupported payment URI')
    params.set(name, value)
  }
  let amount = null
  if (params.has('amount')) {
    const decimal = params.get('amount')
    if (!/^\d+(\.\d{1,8})?$/.test(decimal))
      throw new Error('Invalid payment amount')
    const [whole, fraction = ''] = decimal.split('.')
    const sats = BigInt(whole) * 100_000_000n + BigInt(fraction.padEnd(8, '0'))
    if (sats > 2_100_000_000_000_000n) throw new Error('Invalid payment amount')
    amount = Number(sats)
  }
  const ark = params.get('ark')?.trim().toLowerCase()
  if (params.has('ark') && !/^(t?ark)1[023456789ac-hj-np-z]+$/.test(ark || ''))
    throw new Error('Invalid Arkade address')
  const request = ark || params.get('lightning')?.trim()
  if (!request) throw new Error('Unsupported payment URI')
  return {request, amount}
}

const arkadeLightningErrorCaption = (error, stage) => {
  if (
    error?.reason === 'fee_too_high' &&
    Number.isSafeInteger(error.feeSat) &&
    Number.isSafeInteger(error.maxFeeSat)
  )
    return `Solver fee: ${error.feeSat} sats. Your limit: ${error.maxFeeSat} sats.`
  const gates = {
    invoice_expired: 'Invoice has expired. Request a new invoice.',
    quote_expired: 'The solver quote has expired. Request a fresh quote.',
    insufficient_headroom: 'The refund deadline is too close to fund safely.',
    non_positive_amount: 'The solver quote amount is invalid.',
    max_fee_unbounded: 'The fee limit is missing.',
    max_fee_out_of_range: 'The fee limit is invalid.',
    fee_gate_unavailable:
      'The solver quote cannot be checked against the fee limit.',
    fee_too_high: 'The solver fee exceeds the allowed limit.'
  }
  if (Object.hasOwn(gates, error?.reason)) return gates[error.reason]
  if (error?.reconciliationRequired)
    return 'A previous payment needs reconciliation. Check the Lightning journal.'
  const clients = {
    'wallet is locked': 'Unlock your Arkade wallet before paying.',
    'Arkade Lightning preparation is locked':
      'Unlock your Arkade wallet before paying.',
    'Arkade Lightning invoice is expired':
      'Invoice has expired. Request a new invoice.',
    'Arkade Lightning invoice is invalid': 'The Lightning invoice is invalid.',
    'Arkade Lightning invoice decoder unavailable':
      'The invoice decoder is unavailable. Reload the page.',
    'Arkade Lightning invoice amount is outside the solver range':
      'The invoice amount is outside the solver range.',
    'Arkade Lightning quote request failed':
      'The solver quote request failed. Check relay connectivity and try again.',
    'Arkade Lightning wallet unavailable':
      'Your Arkade wallet is unavailable. Unlock it and retry.',
    'Arkade Lightning reservation changed':
      'The payment reservation changed. Check the Lightning journal.',
    'Arkade Lightning intent changed':
      'The payment intent changed. Check the Lightning journal.',
    'Arkade Lightning funding changed':
      'The funding state changed. Check the Lightning journal.'
  }
  if (Object.hasOwn(clients, error?.message)) return clients[error.message]
  if (/^payment_error_message \(ARKADE_[A-Z_]+\)$/.test(error?.message || ''))
    return error.message.replace(/^.*\((.*)\)$/, '$1')
  return stage === 'funding'
    ? 'Funding could not be confirmed. Check the Lightning journal before retrying.'
    : 'Payment preparation failed. Check your wallet connection and retry.'
}

window.PageWallet = {
  template: '#page-wallet',
  data() {
    return {
      parse: {
        show: false,
        invoice: null,
        lightningQuote: null,
        lightningFeeCap: 100,
        arkade: null,
        lnurlpay: null,
        lnurlauth: null,
        sending: false,
        data: {
          request: '',
          amount: 0,
          comment: '',
          internalMemo: null,
          unit: 'sat'
        },
        paymentChecker: null,
        copy: {
          show: false
        },
        camera: {
          show: false,
          camera: 'auto'
        }
      },
      receive: {
        show: false,
        status: 'pending',
        paymentReq: null,
        protocol: null,
        paymentHash: null,
        amountMsat: null,
        fiatPaymentReq: null,
        minMax: [0, 2100000000000000],
        lnurl: null,
        units: [],
        unit: 'sat',
        fiatProvider: '',
        data: {
          amount: null,
          memo: '',
          internalMemo: null,
          payment_hash: null
        }
      },
      update: {
        name: null,
        currency: null
      },
      hasNfc: false,
      nfcReaderAbortController: null,
      arkadeRecovery: [],
      arkadeRecoveryBusy: false,
      arkadeBacking: null,
      arkadeBackingDialog: false,
      arkadeBackingError: '',
      arkadeMaintenanceBusy: false,
      arkadeAutoRenew: false,
      arkadeBackingTimer: null,
      formattedFiatAmount: 0,
      totalBreakdown: {
        show: false,
        loading: false,
        rows: [],
        selectedTypes: ['bitcoin', 'fiat'],
        selectedTags: []
      },
      paymentFilter: {
        'status[ne]': 'failed'
      },
      chartConfig: Quasar.LocalStorage.getItem(
        'lnbits.wallets.chartConfig'
      ) || {
        showPaymentInOutChart: true,
        showBalanceChart: true,
        showBalanceInOutChart: true
      }
    }
  },
  computed: {
    isFiatWallet() {
      return this.g.wallet.walletType === 'fiat'
    },
    isCashPayment() {
      return this.isFiatWallet && this.receive.fiatProvider === 'cash'
    },
    canPay() {
      if (this.parse.arkade) {
        return (
          Number.isSafeInteger(Number(this.parse.arkade.amount)) &&
          Number(this.parse.arkade.amount) > 0 &&
          Number(this.parse.arkade.amount) <= this.g.wallet.sat
        )
      }
      if (!this.parse.invoice) return false
      if (this.parse.invoice.expired) {
        Quasar.Notify.create({
          message: 'Invoice has expired',
          color: 'negative'
        })
        return false
      }
      return this.parse.invoice.sat <= this.g.wallet.sat
    },
    lnurlpayInfo() {
      // parse.lnurlpay is posted back to the api verbatim when paying, and the
      // model there forbids unknown fields, so the details the dialog shows are
      // derived here instead of being mixed into it
      const data = this.parse.lnurlpay
      if (!data) return {}
      const info = {
        domain: data.callback.split('/')[2],
        fixed: data.minSendable === data.maxSendable
      }
      try {
        JSON.parse(data.metadata).forEach(([kind, value]) => {
          if (kind === 'text/plain') {
            info.description = value
          } else if (
            kind === 'image/png;base64' ||
            kind === 'image/jpeg;base64'
          ) {
            info.image = `data:${kind},${value}`
          } else if (kind === 'text/identifier' || kind === 'text/email') {
            info.targetUser = value
          }
        })
      } catch {
        // malformed metadata only costs the extra detail shown in the dialog
      }
      return info
    },
    formattedAmount() {
      if (this.isFiatWallet) {
        return LNbits.utils.formatCurrency(
          this.receive.data.amount,
          this.receive.unit
        )
      }
      if (this.receive.unit != 'sat' || !this.g.isSatsDenomination) {
        return LNbits.utils.formatCurrency(
          Number(this.receive.data.amount).toFixed(2),
          !this.g.isSatsDenomination ? this.g.denomination : this.receive.unit
        )
      } else {
        return LNbits.utils.formatMsat(this.receive.amountMsat) + ' sat'
      }
    },
    formattedSatAmount() {
      return LNbits.utils.formatMsat(this.receive.amountMsat) + ' sat'
    },
    arkadeReceivePayload() {
      return arkadeReceiveBip21(
        this.receive.paymentReq,
        this.receive.amountMsat
      )
    },
    totalBreakdownTags() {
      const tags = this.totalBreakdown.rows.map(row => row.tag || null)
      return [...new Set(tags)].sort((a, b) =>
        this.totalBreakdownTagLabel(a).localeCompare(
          this.totalBreakdownTagLabel(b)
        )
      )
    },
    hasFiatTotalBreakdown() {
      return this.totalBreakdown.rows.some(row => row.is_fiat)
    },
    selectedTotalBreakdownRows() {
      return this.totalBreakdown.rows.filter(row => {
        const type = row.is_fiat ? 'fiat' : 'bitcoin'
        return (
          this.totalBreakdown.selectedTypes.includes(type) &&
          this.totalBreakdown.selectedTags.includes(
            this.totalBreakdownTagKey(row.tag)
          )
        )
      })
    },
    selectedTotalBreakdownMsat() {
      return this.selectedTotalBreakdownRows.reduce(
        (total, row) => total + row.total,
        0
      )
    },
    selectedTotalBreakdownSat() {
      return Math.round(this.selectedTotalBreakdownMsat / 1000)
    },
    selectedTotalBreakdownCount() {
      return this.selectedTotalBreakdownRows.reduce(
        (total, row) => total + row.payments_count,
        0
      )
    },
    formattedTotalBreakdown() {
      return this.utils.formatBalance(
        this.selectedTotalBreakdownSat,
        this.g.denomination
      )
    },
    formattedTotalBreakdownFiat() {
      if (!this.g.fiatTracking) return null
      const amount =
        (this.selectedTotalBreakdownSat / 100000000) * this.g.exchangeRate
      return LNbits.utils.formatCurrency(amount, this.g.wallet.currency)
    },
    primaryTotalBreakdownValue() {
      if (this.g.isFiatPriority && this.g.fiatTracking) {
        return this.formattedTotalBreakdownFiat || this.formattedTotalBreakdown
      }
      return this.formattedTotalBreakdown
    },
    secondaryTotalBreakdownValue() {
      if (!this.g.fiatTracking) return null
      if (this.g.isFiatPriority) {
        return this.formattedTotalBreakdown
      }
      return this.formattedTotalBreakdownFiat
    },
    arkadeBackingLedgerSat() {
      return Math.floor((this.arkadeBacking?.ledger_msat ?? 0) / 1000)
    }
  },
  methods: {
    async refreshArkadeBacking() {
      if (this.g.user?.installationMode !== 'arkade_noncustodial') return
      try {
        this.arkadeBacking = (
          await LNbits.api.request('GET', '/api/v1/arkade/backing')
        ).data
        this.arkadeBackingError = ''
        if (
          this.arkadeAutoRenew &&
          this.arkadeBacking.expiring_sat > 0 &&
          !this.arkadeBacking.maintenance &&
          !this.arkadeMaintenanceBusy
        )
          await this.maintainArkadeVtxos(true)
      } catch {
        this.arkadeBackingError =
          'Backing could not be verified. Refresh before paying.'
      }
    },
    async enableArkadeAutoRenew(value) {
      if (value) {
        const approved = await new Promise(resolve => {
          this.$q
            .dialog({
              title: 'Automatic VTXO renewal',
              message:
                'Allow this browser to sign zero-fee renewals while your wallet is unlocked? Keep it open to renew before expiry. This cannot renew funds while the browser is closed.',
              cancel: true,
              persistent: true
            })
            .onOk(() => resolve(true))
            .onCancel(() => resolve(false))
        })
        if (!approved) return
      }
      this.arkadeAutoRenew = value
      this.$q.localStorage.set(
        `lnbits.arkade.autoRenew.${this.g.user.id}`,
        value
      )
      if (value) void this.refreshArkadeBacking()
    },
    async maintainArkadeVtxos(automatic = false) {
      if (this.arkadeMaintenanceBusy) return
      if (!automatic) {
        const approved = await new Promise(resolve => {
          this.$q
            .dialog({
              title: 'Recover / renew Arkade funds',
              message:
                'Sign a zero-fee batch settlement back to your own wallet? This restores or extends VTXO backing without changing your recorded balance. Settlement can take several minutes.',
              cancel: true,
              persistent: true
            })
            .onOk(() => resolve(true))
            .onCancel(() => resolve(false))
        })
        if (!approved) return
      }
      this.arkadeMaintenanceBusy = true
      try {
        this.arkadeBacking = await window.ArkadeEnrollment.maintainVtxos({
          approved: true
        })
        this.arkadeBackingError = ''
        this.$q.notify({
          type: 'info',
          message: this.arkadeBacking.maintenance
            ? 'Settlement submitted; awaiting backing verification.'
            : 'Arkade backing refreshed.'
        })
      } catch (error) {
        this.arkadeBackingError =
          error?.response?.data?.detail ||
          error.message ||
          'Recovery needs another attempt.'
      } finally {
        this.arkadeMaintenanceBusy = false
      }
    },
    showWalletTotalBreakdown() {
      this.totalBreakdown.show = true
      if (!this.totalBreakdown.rows.length) {
        this.fetchTotalBreakdown()
      }
    },
    fetchTotalBreakdown() {
      this.totalBreakdown.loading = true
      LNbits.api
        .getPaymentTotalBreakdown(this.g.wallet)
        .then(response => {
          this.totalBreakdown.rows = response.data
          this.totalBreakdown.selectedTypes = ['bitcoin', 'fiat']
          this.totalBreakdown.selectedTags = this.totalBreakdownTags.map(
            this.totalBreakdownTagKey
          )
          this.totalBreakdown.loading = false
        })
        .catch(err => {
          this.totalBreakdown.loading = false
          LNbits.utils.notifyApiError(err)
        })
    },
    totalBreakdownTagLabel(tag) {
      return tag || 'No tag'
    },
    totalBreakdownTagKey(tag) {
      return tag || '__untagged__'
    },
    totalBreakdownTagCount(tag) {
      return this.totalBreakdown.rows
        .filter(row => (row.tag || null) === tag)
        .reduce((total, row) => total + row.payments_count, 0)
    },
    totalBreakdownTagMsat(tag) {
      return this.totalBreakdown.rows
        .filter(row => (row.tag || null) === tag)
        .reduce((total, row) => total + row.total, 0)
    },
    formatTotalBreakdownMsat(msat) {
      return this.utils.formatBalance(
        Math.round(msat / 1000),
        this.g.denomination
      )
    },
    handleSendLnurl(lnurl) {
      this.parse.data.request = lnurl
      this.parse.show = true
      this.lnurlScan()
    },
    async refreshArkadeRecovery() {
      if (
        this.g.user?.installationMode !== 'arkade_noncustodial' ||
        !window.ArkadeEnrollment?.listOutgoing
      )
        return
      try {
        const records = await window.ArkadeEnrollment.listOutgoing()
        this.arkadeRecovery = records.filter(record =>
          [
            'prepared',
            'authorization_unknown',
            'submitted',
            'reconciliation_required'
          ].includes(record.phase)
        )
      } catch {
        // Keep previously discovered attempts visible during a network failure.
      }
    },
    async recoverArkadeOutgoing(record) {
      if (this.arkadeRecoveryBusy) return
      const approved = await new Promise(resolve => {
        this.$q
          .dialog({
            title: 'Recover Arkade payment',
            message:
              `Recover ${record.amountSat} sat to ${record.destination.slice(0, 12)}…${record.destination.slice(-8)}? ` +
              'Refresh the wallet and continue this outgoing payment?',
            cancel: true,
            persistent: true
          })
          .onOk(() => resolve(true))
          .onCancel(() => resolve(false))
      })
      if (!approved) return
      this.arkadeRecoveryBusy = true
      try {
        const result = await window.ArkadeEnrollment.recoverOutgoing(
          record.intentId,
          {
            approved: true
          }
        )
        await this.refreshArkadeRecovery()
        this.g.updatePayments = !this.g.updatePayments
        if (result?.phase === 'reconciliation_required') {
          this.$q.notify({
            type: 'warning',
            message: 'Arkade payment still requires reconciliation.'
          })
        } else if (result?.status === 'submitted') {
          this.$q.notify({
            type: 'info',
            message: 'Arkade payment submitted.'
          })
        } else if (result?.reconciliationRequired) {
          this.$q.notify({
            type: 'warning',
            message: 'Arkade payment still requires reconciliation.'
          })
        } else if (result?.status === 'settled') {
          this.$q.notify({
            type: 'positive',
            message: 'Arkade payment recovery complete.'
          })
        } else {
          this.$q.notify({
            type: 'warning',
            message: 'Arkade payment status needs review.'
          })
        }
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      } finally {
        this.arkadeRecoveryBusy = false
      }
    },
    msatoshiFormat(value) {
      return LNbits.utils.formatSat(value / 1000)
    },
    showReceiveDialog() {
      this.receive.show = true
      this.receive.status = 'pending'
      this.receive.paymentReq = null
      this.receive.protocol = null
      this.receive.paymentHash = null
      this.receive.fiatPaymentReq = null
      this.receive.fiatProvider = this.isFiatWallet ? 'cash' : ''
      this.receive.data.amount = null
      this.receive.data.memo = null
      this.receive.data.internalMemo = null
      this.receive.data.payment_hash = null
      this.receive.units = [
        ...(this.isFiatWallet ? [] : ['sat']),
        ...(this.g.allowedCurrencies.length > 0
          ? this.g.allowedCurrencies
          : this.g.currencies)
      ]
      this.receive.unit = this.g.isFiatPriority
        ? this.g.wallet.currency || 'sat'
        : 'sat'
      if (this.isFiatWallet) {
        this.receive.unit = this.receive.units.includes(this.g.wallet.currency)
          ? this.g.wallet.currency
          : this.receive.units[0]
      }
      this.receive.minMax = [0, 2100000000000000]
      this.receive.lnurl = null
      this.receive.lnurlWithdraw = null
    },
    onReceiveDialogHide() {
      if (this.hasNfc) {
        this.nfcReaderAbortController?.abort()
      }
    },
    showParseDialog() {
      this.parse.show = true
      this.parse.invoice = null
      this.parse.arkade = null
      this.parse.lnurlpay = null
      this.parse.lnurlauth = null
      this.parse.copy.show =
        window.isSecureContext && navigator.clipboard?.readText !== undefined
      this.parse.data.request = ''
      this.parse.data.comment = ''
      this.parse.data.internalMemo = null
      this.parse.sending = false
      this.parse.data.paymentChecker = null
      this.parse.camera.show = false
    },
    closeParseDialog() {
      setTimeout(() => {
        clearInterval(this.parse.paymentChecker)
      }, 10000)
    },
    handleBalanceUpdate(value) {
      this.g.wallet.sat = this.g.wallet.sat + value
    },
    createInvoice() {
      if (this.receive.status === 'loading') return
      this.receive.status = 'loading'
      if (!this.isFiatWallet && !this.g.isSatsDenomination) {
        this.receive.data.amount = this.receive.data.amount * 100
      }

      const cash = this.isCashPayment
      const request = cash
        ? LNbits.api.request(
            'POST',
            '/api/v1/fiat/cash',
            this.g.wallet.adminkey,
            {
              amount: this.receive.data.amount,
              unit: this.receive.unit,
              memo: this.receive.data.memo,
              internal_memo: this.receive.data.internalMemo
            }
          )
        : LNbits.api.createInvoice(
            this.g.wallet,
            this.receive.data.amount,
            this.receive.data.memo,
            this.receive.unit,
            this.receive.lnurlWithdraw,
            this.receive.fiatProvider,
            this.receive.data.internalMemo,
            this.receive.data.payment_hash
          )
      request
        .then(async response => {
          if (cash) {
            this.g.updatePayments = !this.g.updatePayments
            this.receive.status = 'success'
            this.receive.show = false
            Quasar.Notify.create({
              type: 'positive',
              message: 'Cash payment validated.'
            })
            return
          }
          if (
            response.data.protocol === 'arkade' &&
            response.data.browser_required
          ) {
            const allocateReceive = window.ArkadeEnrollment?.allocateReceive
            if (!allocateReceive)
              throw new Error('Arkade wallet is unavailable')
            const result = await allocateReceive(
              this.g.wallet.id,
              response.data
            )
            this.g.updatePayments = !this.g.updatePayments
            this.receive.status = 'success'
            this.receive.protocol = 'arkade'
            this.receive.paymentReq = result.mapping.address
            this.receive.fiatPaymentReq = null
            this.receive.amountMsat = response.data.amount
            this.receive.paymentHash = null
            return
          }
          this.g.updatePayments = !this.g.updatePayments
          this.receive.status = 'success'
          this.receive.protocol = response.data.protocol || 'lightning'
          this.receive.paymentReq = response.data.bolt11
          this.receive.fiatPaymentReq =
            response.data.extra?.fiat_payment_request
          this.receive.amountMsat = response.data.amount
          this.receive.paymentHash = response.data.payment_hash
          if (!this.isFiatWallet && !this.receive.lnurl) {
            this.readNfcTag()
          }
          // WITHDRAW
          if (
            this.receive.lnurl &&
            response.data.extra?.lnurl_response !== null
          ) {
            if (response.data.extra.lnurl_response === false) {
              response.data.extra.lnurl_response = `Unable to connect`
            }
            const domain = this.receive.lnurl.callback.split('/')[2]
            if (typeof response.data.extra.lnurl_response === 'string') {
              // failure
              Quasar.Notify.create({
                timeout: 5000,
                type: 'warning',
                message: `${domain} lnurl-withdraw call failed.`,
                caption: response.data.extra.lnurl_response
              })
              return
            } else if (response.data.extra.lnurl_response === true) {
              // success
              Quasar.Notify.create({
                timeout: 3000,
                message: `Invoice sent to ${domain}!`,
                spinner: true
              })
            }
          }
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
          this.receive.status = 'pending'
        })
    },
    lnurlScan() {
      LNbits.api
        .request('POST', '/api/v1/lnurlscan', this.g.wallet.adminkey, {
          lnurl: this.parse.data.request
        })
        .then(response => {
          const data = response.data
          if (data.status === 'ERROR') {
            Quasar.Notify.create({
              timeout: 5000,
              type: 'warning',
              message: `lnurl scan failed.`,
              caption: data.reason
            })
            return
          }

          if (data.tag === 'payRequest') {
            this.parse.lnurlpay = Object.freeze(data)
            this.parse.data.amount = data.minSendable / 1000
            this.receive.units = [
              'sats',
              ...(this.g.allowedCurrencies.length > 0
                ? this.g.allowedCurrencies
                : this.g.currencies)
            ]
          } else if (data.tag === 'login') {
            this.parse.lnurlauth = Object.freeze(data)
          } else if (data.tag === 'withdrawRequest') {
            this.parse.show = false
            this.receive.show = true
            this.receive.lnurlWithdraw = Object.freeze(data)
            this.receive.status = 'pending'
            this.receive.paymentReq = null
            this.receive.paymentHash = null
            this.receive.data.amount = data.maxWithdrawable / 1000
            this.receive.data.memo = data.defaultDescription
            this.receive.minMax = [
              data.minWithdrawable / 1000,
              data.maxWithdrawable / 1000
            ]
            const domain = data.callback.split('/')[2]
            this.receive.lnurl = {
              domain: domain,
              callback: data.callback,
              fixed: data.fixed
            }
          }
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    decodeQR(val) {
      this.parse.data.request = val
      this.decodeRequest()
      this.parse.camera.show = false
    },
    isLnurl(req) {
      return (
        req.toLowerCase().startsWith('lnurl1') ||
        req.startsWith('lnurlp://') ||
        req.startsWith('lnurlw://') ||
        req.startsWith('lnurlauth://') ||
        req.match(/[\w.+-~_]+@[\w.+-~_]/)
      )
    },
    decodeRequest() {
      this.parse.show = true
      this.parse.invoice = null
      this.parse.arkade = null
      this.parse.lnurlpay = null
      this.parse.lnurlauth = null
      let request = this.parse.data.request.trim()
      let amount = null
      try {
        if (request.toLowerCase().startsWith('bitcoin:')) {
          const bip21 = arkadeDecodeBip21(request)
          request = bip21.request
          amount = bip21.amount
        }
      } catch {
        Quasar.Notify.create({
          type: 'warning',
          message: 'Invalid or unsupported payment URI.',
          caption: '400 BAD REQUEST'
        })
        this.parse.show = false
        return
      }
      if (/^lightning:/i.test(request)) request = request.slice(10)
      else if (/^lnurl:/i.test(request)) request = request.slice(6)
      this.parse.data.request = request
      if (this.isLnurl(request)) {
        this.lnurlScan()
        return
      }
      if (/^(t?ark)1[023456789ac-hj-np-z]+$/i.test(request)) {
        this.parse.data.request = request.toLowerCase()
        this.parse.arkade = {
          address: this.parse.data.request,
          amount,
          idempotencyKey: this.newArkadeIdempotencyKey()
        }
        return
      }

      let invoice
      try {
        invoice = decode(this.parse.data.request)
      } catch (error) {
        Quasar.Notify.create({
          timeout: 3000,
          type: 'warning',
          message: error + '.',
          caption: '400 BAD REQUEST'
        })
        this.parse.show = false
        return
      }

      let cleanInvoice = {
        msat: invoice.human_readable_part.amount,
        sat: invoice.human_readable_part.amount / 1000,
        fsat: LNbits.utils.formatSat(invoice.human_readable_part.amount / 1000),
        bolt11: this.parse.data.request,
        expiresAt: (invoice.data.time_stamp + 3600) * 1000,
        expired: Date.now() >= (invoice.data.time_stamp + 3600) * 1000
      }

      _.each(invoice.data.tags, tag => {
        if (_.isObject(tag) && _.has(tag, 'description')) {
          if (tag.description === 'payment_hash') {
            cleanInvoice.hash = tag.value
          } else if (tag.description === 'description') {
            cleanInvoice.description = tag.value
          } else if (tag.description === 'expiry') {
            const expireDate = new Date(
              (invoice.data.time_stamp + tag.value) * 1000
            )
            const createdDate = new Date(invoice.data.time_stamp * 1000)
            cleanInvoice.expireDate = Quasar.date.formatDate(
              expireDate,
              'YYYY-MM-DDTHH:mm:ss.SSSZ'
            )
            cleanInvoice.createdDate = Quasar.date.formatDate(
              createdDate,
              'YYYY-MM-DDTHH:mm:ss.SSSZ'
            )
            cleanInvoice.expireDateFrom = moment
              .utc(expireDate)
              .local()
              .fromNow()
            cleanInvoice.createdDateFrom = moment
              .utc(createdDate)
              .local()
              .fromNow()

            cleanInvoice.expiresAt = expireDate.getTime()
            cleanInvoice.expired = Date.now() >= cleanInvoice.expiresAt
          }
        }
      })

      if (this.g.wallet.currency) {
        cleanInvoice.fiatAmount = LNbits.utils.formatCurrency(
          ((cleanInvoice.sat / 1e8) * this.g.exchangeRate).toFixed(2),
          this.g.wallet.currency
        )
      }

      this.parse.lightningQuote = null
      this.parse.lightningFeeCap = 100
      this.parse.invoice = Object.freeze(cleanInvoice)
    },
    newArkadeIdempotencyKey() {
      return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte =>
        byte.toString(16).padStart(2, '0')
      ).join('')
    },
    async payArkade() {
      if (this.parse.sending || !this.canPay) return
      const form = this.parse.arkade
      const wallet = this.g.wallet
      const address = form.address
      const amount = Number(form.amount)
      const request = JSON.stringify([wallet.id, address, amount])
      if (form.paymentRequest && form.paymentRequest !== request)
        form.idempotencyKey = this.newArkadeIdempotencyKey()
      form.paymentRequest = request
      this.parse.sending = true
      try {
        const response = await LNbits.api.payArkade(
          wallet,
          address,
          amount,
          form.idempotencyKey
        )
        if (response.data.browser_required === false) {
          this.g.updatePayments = !this.g.updatePayments
          this.parse.show = false
          this.$q.notify({
            type: 'positive',
            message: this.$t('payment_successful')
          })
          return
        }
        void this.refreshArkadeRecovery()
        if (!response.data.intent_id)
          throw new Error('Arkade browser approval is unavailable')
        let prepared
        try {
          prepared = await window.ArkadeEnrollment.prepareOutgoing(
            response.data.intent_id,
            wallet.id
          )
          if (prepared.amountSat !== amount || prepared.destination !== address)
            throw new Error('Arkade payment request changed')
        } catch (error) {
          await LNbits.api.arkadeOutgoingRelease(response.data.intent_id)
          void this.refreshArkadeRecovery()
          form.idempotencyKey = this.newArkadeIdempotencyKey()
          throw error
        }
        // The PAY click approves this exact amount and destination.
        await window.ArkadeEnrollment.submitOutgoing(prepared, {approved: true})
        this.g.updatePayments = !this.g.updatePayments
        this.parse.show = false
        this.$q.notify({type: 'info', message: this.$t('payment_pending')})
      } catch (error) {
        if (error?.reconciliationRequired) {
          this.parse.show = false
          this.$q.notify({
            type: 'warning',
            message:
              'Payment outcome is not confirmed. Check outgoing recovery before retrying.'
          })
        } else if (error?.response) LNbits.utils.notifyApiError(error)
        else
          this.$q.notify({
            type: 'warning',
            message:
              'Arkade payment could not be started. Check outgoing recovery before retrying.',
            closeBtn: true
          })
      } finally {
        this.parse.sending = false
        void this.refreshArkadeRecovery()
      }
    },
    async payArkadeLightning(bolt11) {
      let prepared = this.parse.lightningQuote
      if (prepared?.bolt11 !== bolt11) prepared = null
      try {
        if (!window.ArkadeEnrollment?.prepareLightningSend)
          throw new Error('Arkade Lightning wallet unavailable')
        if (!prepared) {
          prepared = await window.ArkadeEnrollment.prepareLightningSend(
            bolt11,
            Number(this.parse.lightningFeeCap)
          )
          this.parse.lightningQuote = prepared
          return
        }
        if (prepared.feeSat > Number(this.parse.lightningFeeCap))
          throw Object.assign(
            new Error('Arkade Lightning fee limit exceeded'),
            {reason: 'fee_too_high'}
          )
      } catch (error) {
        this.$q.notify({
          type: 'warning',
          message: this.$t('payment_error_message'),
          caption: arkadeLightningErrorCaption(error, 'prepare'),
          closeBtn: true
        })
        return
      }
      // PAY pays, like the custodial flow: no separate confirmation dialog.
      try {
        await window.ArkadeEnrollment.submitLightningSend(prepared.intentId, {
          approved: true
        })
      } catch (error) {
        // Funding problems are client-side and carry no response, so surface
        // them instead of failing silently with the send form still open.
        this.$q.notify({
          type: 'warning',
          message: this.$t('payment_error_message'),
          caption: arkadeLightningErrorCaption(error, 'funding'),
          closeBtn: true
        })
        return
      }
      this.parse.show = false
      this.parse.lightningQuote = null
      this.g.updatePayments = !this.g.updatePayments
      Quasar.Notify.create({type: 'info', message: this.$t('payment_pending')})
    },
    payInvoice() {
      if (this.parse.sending) return
      if (
        this.parse.invoice &&
        (this.parse.invoice.expired ||
          Date.now() >= this.parse.invoice.expiresAt)
      ) {
        this.$q.notify({
          type: 'warning',
          message: 'Invoice has expired. Request a new invoice.'
        })
        return
      }

      if (this.g.user?.installationMode === 'arkade_noncustodial') {
        this.parse.sending = true
        return this.payArkadeLightning(this.parse.data.request)
          .catch(err => {
            // Preparation failures already surfaced their own notice.
            if (err?.response) LNbits.utils.notifyApiError(err)
          })
          .finally(() => {
            this.parse.sending = false
          })
      }

      this.parse.sending = true
      const dismissPaymentMsg = Quasar.Notify.create({
        timeout: 0,
        message: this.$t('payment_processing')
      })

      LNbits.api
        .payInvoice(
          this.g.wallet,
          this.parse.data.request,
          this.parse.data.internalMemo
        )
        .then(response => {
          this.parse.sending = false
          dismissPaymentMsg()
          this.g.updatePayments = !this.g.updatePayments
          this.parse.show = false
          if (response.data.status == 'success') {
            Quasar.Notify.create({
              type: 'positive',
              message: this.$t('payment_successful')
            })
          }
          if (response.data.status == 'pending') {
            Quasar.Notify.create({
              type: 'info',
              message: this.$t('payment_pending')
            })
          }
        })
        .catch(err => {
          this.parse.sending = false
          dismissPaymentMsg()
          LNbits.utils.notifyApiError(err)
          this.g.updatePayments = !this.g.updatePayments
        })
    },
    payLnurl() {
      if (this.parse.sending) return

      this.parse.sending = true
      if (this.g.user?.installationMode === 'arkade_noncustodial') {
        return LNbits.api
          .request(
            'post',
            '/api/v1/payments/lnurl/prepare',
            this.g.wallet.adminkey,
            {
              res: this.parse.lnurlpay,
              lnurl: this.parse.data.request,
              unit: this.parse.data.unit,
              amount: this.parse.data.amount * 1000,
              comment: this.parse.data.comment,
              internalMemo: this.parse.data.internalMemo
            }
          )
          .then(response => {
            this.parse.data.request = response.data.payment_request
            this.decodeRequest()
            return this.payArkadeLightning(response.data.payment_request)
          })
          .catch(err => {
            // Arkade preparation failures already surfaced their own notice.
            if (err?.response) LNbits.utils.notifyApiError(err)
          })
          .finally(() => {
            this.parse.sending = false
          })
      }
      LNbits.api
        .request('post', '/api/v1/payments/lnurl', this.g.wallet.adminkey, {
          res: this.parse.lnurlpay,
          lnurl: this.parse.data.request,
          unit: this.parse.data.unit,
          amount: this.parse.data.amount * 1000,
          comment: this.parse.data.comment,
          internalMemo: this.parse.data.internalMemo
        })
        .then(response => {
          this.parse.sending = false
          this.parse.show = false
          if (response.data.extra.success_action) {
            const action = JSON.parse(response.data.extra.success_action)
            switch (action.tag) {
              case 'url':
                Quasar.Notify.create({
                  message: action.url,
                  caption: action.description,
                  html: false,
                  type: 'positive',
                  timeout: 0,
                  closeBtn: true,
                  actions: [
                    {
                      label: 'Open link',
                      color: 'white',
                      handler: () => this.utils.openUrlInNewTab(action.url)
                    }
                  ]
                })
                break
              case 'message':
                Quasar.Notify.create({
                  message: action.message,
                  type: 'positive',
                  timeout: 0,
                  closeBtn: true
                })
                break
              case 'aes':
                this.utils
                  .decryptLnurlPayAES(action, response.data.preimage)
                  .then(value => {
                    Quasar.Notify.create({
                      message: value,
                      caption: action.description,
                      html: false,
                      type: 'positive',
                      timeout: 0,
                      closeBtn: true
                    })
                  })
                  .catch(error => {
                    Quasar.Notify.create({
                      message: action.description || 'Payment successful.',
                      caption: 'Could not decrypt success action.',
                      html: false,
                      type: 'warning',
                      timeout: 0,
                      closeBtn: true
                    })
                  })
                break
            }
          }
        })
        .catch(err => {
          this.parse.sending = false
          LNbits.utils.notifyApiError(err)
        })
    },
    authLnurl() {
      const dismissAuthMsg = Quasar.Notify.create({
        timeout: 10,
        message: 'Performing authentication...'
      })
      LNbits.api
        .request(
          'post',
          '/api/v1/lnurlauth',
          wallet.adminkey,
          this.parse.lnurlauth
        )
        .then(_ => {
          dismissAuthMsg()
          Quasar.Notify.create({
            message: `Authentication successful.`,
            type: 'positive',
            timeout: 3500
          })
          this.parse.show = false
        })
        .catch(err => {
          if (err.response.data.reason) {
            Quasar.Notify.create({
              message: `Authentication failed. ${this.parse.lnurlauth.callback} says:`,
              caption: err.response.data.reason,
              type: 'warning',
              timeout: 5000
            })
          } else {
            LNbits.utils.notifyApiError(err)
          }
        })
    },
    updateWallet(data) {
      LNbits.api
        .request('PATCH', '/api/v1/wallet', this.g.wallet.adminkey, data)
        .then(response => {
          const walletData = {...response.data}
          if (walletData.lightning_address) {
            walletData.lightningAddress = walletData.lightning_address
            walletData.lightningAddressFull = `${walletData.lightning_address}@${window.location.host}`
          }
          this.g.wallet = {...this.g.wallet, ...walletData}
          const walletIndex = this.g.user.wallets.findIndex(
            wallet => wallet.id === response.data.id
          )
          if (walletIndex !== -1) {
            this.g.user.wallets[walletIndex] = {
              ...this.g.user.wallets[walletIndex],
              ...walletData
            }
          }
          Quasar.Notify.create({
            message: 'Wallet updated.',
            type: 'positive',
            timeout: 3500
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    pasteToTextArea() {
      this.$refs.textArea.focus()
      navigator.clipboard.readText().then(text => {
        this.parse.data.request = text.trim()
      })
    },
    readNfcTag() {
      try {
        if (typeof NDEFReader == 'undefined') {
          console.debug('NFC not supported on this device or browser.')
          return
        }

        const ndef = new NDEFReader()

        this.nfcReaderAbortController = new AbortController()
        this.nfcReaderAbortController.signal.onabort = event => {
          console.debug('All NFC Read operations have been aborted.')
        }

        this.hasNfc = true
        const dismissNfcTapMsg = Quasar.Notify.create({
          message: 'Tap your NFC tag to pay this invoice with LNURLw.'
        })

        return ndef
          .scan({signal: this.nfcReaderAbortController.signal})
          .then(() => {
            ndef.onreadingerror = () => {
              Quasar.Notify.create({
                type: 'negative',
                message: 'There was an error reading this NFC tag.'
              })
            }

            ndef.onreading = ({message}) => {
              //Decode NDEF data from tag
              const textDecoder = new TextDecoder('utf-8')

              const record = message.records.find(el => {
                const payload = textDecoder.decode(el.data)
                return payload.toUpperCase().indexOf('LNURLW') !== -1
              })

              if (record) {
                dismissNfcTapMsg()
                Quasar.Notify.create({
                  type: 'positive',
                  message: 'NFC tag read successfully.'
                })
                const lnurl = textDecoder.decode(record.data)
                this.payInvoiceWithNfc(lnurl)
              } else {
                Quasar.Notify.create({
                  type: 'warning',
                  message: 'NFC tag does not have LNURLw record.'
                })
              }
            }
          })
      } catch (error) {
        Quasar.Notify.create({
          type: 'negative',
          message: error
            ? error.toString()
            : 'An unexpected error has occurred.'
        })
      }
    },
    payInvoiceWithNfc(lnurl) {
      const dismissPaymentMsg = Quasar.Notify.create({
        timeout: 0,
        spinner: true,
        message: this.$t('payment_processing')
      })

      LNbits.api
        .request(
          'POST',
          `/api/v1/payments/${this.receive.paymentReq}/pay-with-nfc`,
          this.g.wallet.adminkey,
          {lnurl_w: lnurl}
        )
        .then(response => {
          dismissPaymentMsg()
          if (response.data.success) {
            Quasar.Notify.create({
              type: 'positive',
              message: 'Payment successful'
            })
          } else {
            Quasar.Notify.create({
              type: 'negative',
              message: response.data.detail || 'Payment failed'
            })
          }
        })
        .catch(err => {
          dismissPaymentMsg()
          LNbits.utils.notifyApiError(err)
        })
    }
  },
  created() {
    const urlParams = new URLSearchParams(window.location.search)
    const wallet = this.g.user.wallets.find(w => w.id === this.$route.params.id)
    if (wallet) {
      this.g.wallet = wallet
      this.g.lastActiveWallet = wallet.id
      this.$q.localStorage.setItem('lnbits.lastActiveWallet', wallet.id)
      if (this.g.user.installationMode === 'arkade_noncustodial') {
        void this.refreshArkadeRecovery()
        this.arkadeAutoRenew =
          this.$q.localStorage.getItem(
            `lnbits.arkade.autoRenew.${this.g.user.id}`
          ) === true
        void this.refreshArkadeBacking()
        this.arkadeBackingTimer = setInterval(
          () => void this.refreshArkadeBacking(),
          30000
        )
      }
      // the dialog needs the wallet, and a dialog opened while this navigation
      // is still in flight gets torn down by it, so handle the payment request
      // only once the url rewrite has settled
      this.$router.replace(`/wallet/${wallet.id}`).then(() => {
        if (urlParams.has('lightning') || urlParams.has('lnurl')) {
          this.parse.data.request =
            urlParams.get('lightning') || urlParams.get('lnurl')
          this.decodeRequest()
          this.parse.show = true
        }
      })
    } else {
      this.g.errorCode = 404
      this.g.errorMessage = 'Wallet not found.'
      this.$router.push('/error')
    }
  },
  beforeUnmount() {
    clearInterval(this.arkadeBackingTimer)
  },
  watch: {
    'g.updatePaymentsHash'() {
      this.receive.show = false
    },
    'g.updatePayments'() {
      void this.refreshArkadeRecovery()
      void this.refreshArkadeBacking()
      this.parse.show = false
      if (
        this.g.wallet.currency &&
        this.$q.localStorage.getItem(
          'lnbits.exchangeRate.' + this.g.wallet.currency
        )
      ) {
        this.g.exchangeRate = this.$q.localStorage.getItem(
          'lnbits.exchangeRate.' + this.g.wallet.currency
        )
        this.g.fiatBalance =
          (this.g.exchangeRate / 100000000) * this.g.wallet.sat
      }
    },
    'g.wallet'() {
      if (this.g.wallet.currency) {
        this.g.fiatTracking = true
        this.g.fiatBalance =
          (this.g.exchangeRate / 100000000) * this.g.wallet.sat
      } else {
        this.g.fiatBalance = 0
        this.g.fiatTracking = false
      }
    },
    'g.isFiatPriority'() {
      this.receive.unit = this.g.isFiatPriority ? this.g.wallet.currency : 'sat'
    },
    'g.fiatBalance'() {
      this.formattedFiatAmount = LNbits.utils.formatCurrency(
        this.g.fiatBalance.toFixed(2),
        this.g.wallet.currency
      )
    },
    'g.exchangeRate'() {
      if (this.g.fiatTracking && this.g.wallet.currency) {
        this.g.fiatBalance =
          (this.g.exchangeRate / 100000000) * this.g.wallet.sat
      }
    }
  }
}
