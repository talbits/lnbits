import {defineConfig} from '@playwright/test'

export default defineConfig({
  testDir: __dirname,
  testMatch: 'arkade-bip39.spec.ts',
  webServer: {
    command: 'node arkade-bip39.server.mjs',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false
  },
  use: {
    baseURL: 'http://127.0.0.1:4173',
    browserName: 'chromium',
    headless: true
  }
})
