import {defineConfig} from '@playwright/test'

process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1'

export default defineConfig({
  testDir: __dirname,
  testMatch: 'arkade-official-recovery.spec.ts',
  timeout: 180_000,
  webServer: {
    command: 'node arkade-bip39.server.mjs',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false
  },
  use: {
    browserName: 'chromium',
    headless: true,
    screenshot: 'off',
    trace: 'off',
    video: 'off'
  }
})
