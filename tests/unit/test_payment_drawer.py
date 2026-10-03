import shutil
import subprocess
from pathlib import Path


def test_payment_drawer_shows_arkade_row_only_for_arkade_protocol():
    template = Path("lnbits/templates/components.vue").resolve()
    script = r"""
const assert = require('node:assert/strict')
const fs = require('node:fs')
const Vue = require('vue')
const {renderToString} = require('@vue/server-renderer')

const source = fs.readFileSync(process.argv[1], 'utf8')
const match = source.match(
  /<q-item v-if="payment\.protocol === 'arkade'">[\s\S]*?<\/q-item>/
)
assert.ok(match, 'Arkade payment detail row is missing')
const render = Vue.compile(`<div>${match[0]}</div>`, {
  isCustomElement: tag => tag.startsWith('q-')
})
async function renderPayment(payment) {
  const app = Vue.createSSRApp({
    data: () => ({payment, utils: {copyText() {}}}),
    render
  })
  return renderToString(app)
}

;(async () => {
  const lightning = await renderPayment({
    protocol: 'lightning',
    native_id: 'legacy-checking'
  })
  assert.doesNotMatch(lightning, /<q-item(?:\s|>)/)

  const arkade = await renderPayment({protocol: 'arkade', native_id: 'arkade-id'})
  assert.match(arkade, /<q-item(?:\s|>)/)
  assert.match(arkade, /arkade-id/)
})().catch(error => {
  console.error(error)
  process.exitCode = 1
})
"""
    node = shutil.which("node")
    assert node is not None, "Node is required for frontend behavior checks"
    subprocess.run(  # noqa: S603 — local Node fixture, no user input
        [node, "-e", script, str(template)],
        check=True,
    )
