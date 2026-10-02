window.app.component('lnbits-admin-funding', {
  props: ['active', 'is-super-user', 'form-data', 'settings'],
  template: '#lnbits-admin-funding',
  data() {
    return {
      auditData: []
    }
  },
  created() {
    this.getAudit()
  },
  methods: {
    getAudit() {
      if (this.g.user.installationMode === 'arkade_noncustodial') return
      LNbits.api
        // TODO: should not use admin key here
        .request('GET', '/admin/api/v1/audit', this.g.user.wallets[0].adminkey)
        .then(response => {
          this.auditData = response.data
        })
        .catch(LNbits.utils.notifyApiError)
    }
  }
})
