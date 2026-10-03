import shutil
import subprocess
from pathlib import Path


def test_service_worker_caches_static_assets_but_not_private_requests():
    source = Path("lnbits/templates/service-worker.js").resolve()
    script = r"""
const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')

const handlers = {}
let cacheOpens = 0
let networkRequests = 0
let cacheWrites = 0
const cache = {
  put: async () => { cacheWrites++ },
  match: async () => null
}
const self = {
  location: {origin: 'https://lnbits.test'},
  addEventListener: (name, handler) => { handlers[name] = handler }
}
const caches = {
  open: async () => { cacheOpens++; return cache },
  keys: async () => [],
  delete: async () => true
}
const fetch = async request => {
  networkRequests++
  return {clone() { return this }}
}
const source = fs
  .readFileSync(process.argv[1], 'utf8')
  .replace('{{ cache_version }}', 'test')
vm.runInNewContext(source, {self, caches, fetch, URL, Promise})

async function dispatch(url, method = 'GET') {
  let response = null
  handlers.fetch({request: {url, method}, respondWith: value => { response = value }})
  if (response) await response
  return response !== null
}

;(async () => {
  for (const [url, method] of [
    ['https://lnbits.test/wallet', 'GET'],
    ['https://lnbits.test/api/v1/payments', 'GET'],
    ['https://lnbits.test/api/v1/arkade/enrollment', 'GET'],
    ['https://lnbits.test/arkade/enrollment', 'GET'],
    ['https://other.test/static/app.js', 'GET'],
    ['https://lnbits.test/static/app.js', 'POST']
  ]) {
    assert.equal(await dispatch(url, method), false, `${method} ${url}`)
  }
  assert.equal(cacheOpens, 0)
  assert.equal(networkRequests, 0)

  assert.equal(await dispatch('https://lnbits.test/static/app.js'), true)
  assert.equal(await dispatch('https://lnbits.test/favicon.ico'), true)
  assert.equal(cacheOpens, 2)
  assert.equal(networkRequests, 2)
  assert.equal(cacheWrites, 2)
})().catch(error => {
  console.error(error)
  process.exitCode = 1
})
"""
    node = shutil.which("node")
    assert node is not None, "Node is required for frontend behavior checks"
    subprocess.run(  # noqa: S603 — local Node fixture, no user input
        [node, "-e", script, str(source)],
        check=True,
    )
