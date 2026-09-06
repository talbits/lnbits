<template id="page-arkade-enrollment">
  <div class="row justify-center">
    <q-card class="full-width" style="max-width: 720px">
      <q-card-section>
        <div class="text-h5">Arkade wallet setup</div>
        <div class="text-body2 text-grey-7 q-mt-sm">
          Your recovery phrase is the only way to recover your Arkade funds.
          LNbits never receives it or your local unlock password.
        </div>
      </q-card-section>

      <q-card-section v-if="!g.user">
        <q-banner rounded>Please sign in to enroll an Arkade wallet.</q-banner>
      </q-card-section>
      <q-card-section v-else-if="loading" class="text-center">
        <q-spinner color="primary" size="2em" />
        <div class="q-mt-sm">Checking your wallet binding…</div>
      </q-card-section>
      <q-card-section v-else-if="state === 'unavailable'">
        <q-banner rounded inline-actions icon="cloud_off">
          The Arkade wallet service is unavailable. Try again later.
          <template #action
            ><q-btn flat label="Retry" @click="inspect"
          /></template>
        </q-banner>
      </q-card-section>
      <q-card-section v-else-if="state === 'wallet_locked' && !mode">
        <div class="text-h6">Unlock your wallet</div>
        <p>Your wallet is locked after reload or inactivity.</p>
        <q-input
          v-model="password"
          type="password"
          label="Local unlock password"
          @keyup.enter="unlock"
        />
        <q-btn
          class="q-mt-md"
          unelevated
          color="primary"
          label="Unlock"
          :loading="working"
          @click="unlock"
        />
        <q-btn
          class="q-mt-md q-ml-sm"
          flat
          label="Restore with mnemonic"
          @click="startRestore"
        />
      </q-card-section>
      <q-card-section v-else-if="state === 'pending_unlocked'">
        <div class="text-h6">Finish wallet setup</div>
        <p>
          Your recovery phrase is unlocked locally. Complete the ownership proof
          to enable this wallet.
        </p>
        <q-btn
          unelevated
          color="primary"
          label="Complete setup"
          :loading="working"
          @click="finish"
        />
        <q-btn flat class="q-ml-sm" label="Lock" @click="lock" />
      </q-card-section>
      <q-card-section v-else-if="state === 'recovery_required' && !mode">
        <div class="text-h6">Restore your wallet</div>
        <p>
          This browser has no usable local vault. Restore the same recovery
          phrase to continue.
        </p>
        <q-btn
          unelevated
          color="primary"
          label="Restore wallet"
          @click="startRestore"
        />
      </q-card-section>
      <q-card-section v-else-if="state === 'pending' && !mode">
        <div class="text-h6">Create or restore</div>
        <div class="row q-gutter-sm q-mt-md">
          <q-btn
            unelevated
            color="primary"
            label="Create new wallet"
            @click="startCreate"
          />
          <q-btn
            outline
            color="primary"
            label="Restore wallet"
            @click="startRestore"
          />
        </div>
      </q-card-section>
      <q-card-section v-else>
        <div
          v-if="mode === 'create'"
          class="text-h6"
          v-text="'Back up your recovery phrase'"
        ></div>
        <div v-else class="text-h6" v-text="'Restore your wallet'"></div>
        <p v-if="mode === 'create'">
          Write these words down and keep them offline. Anyone with them can
          recover your funds.
        </p>
        <q-input
          v-if="mode === 'create'"
          v-model="mnemonic"
          type="textarea"
          readonly
          autogrow
          class="q-mb-md"
        />
        <q-input
          v-else
          v-model="mnemonic"
          type="textarea"
          autogrow
          label="Recovery phrase"
          hint="Enter your 12 or 24 English words"
        />
        <q-checkbox
          v-if="mode === 'create'"
          v-model="backupAcknowledged"
          label="I wrote down my recovery phrase and can recover it."
        />
        <q-input
          v-model="password"
          type="password"
          label="Local unlock password"
          class="q-mt-md"
        />
        <q-input
          v-model="passwordRepeat"
          type="password"
          label="Confirm local unlock password"
        />
        <div class="text-caption text-grey-7 q-mt-sm">
          Use at least 12 characters. Forgetting this password is recoverable
          with your mnemonic backup.
        </div>
        <q-btn
          class="q-mt-md"
          unelevated
          color="primary"
          :label="mode === 'create' ? 'Create wallet' : 'Restore wallet'"
          :loading="working"
          @click="submit"
        />
        <q-btn class="q-mt-md q-ml-sm" flat label="Cancel" @click="cancel" />
      </q-card-section>
    </q-card>
  </div>
</template>
