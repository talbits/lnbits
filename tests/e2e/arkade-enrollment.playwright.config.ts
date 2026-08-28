import {defineConfig} from '@playwright/test'

export default defineConfig({
  testDir: __dirname,
  testMatch: 'enrollment.spec.ts',
  use: {browserName: 'chromium', headless: true},
  workers: 1
})
