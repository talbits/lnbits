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
        <q-spinner color="primary" size="2em"></q-spinner>
        <div class="q-mt-sm">Checking your wallet binding…</div>
      </q-card-section>
      <q-card-section v-else-if="state === 'unavailable'">
        <q-banner rounded inline-actions icon="cloud_off">
          The Arkade wallet service is unavailable. Try again later.
          <template #action
            ><q-btn flat label="Retry" @click="inspect"></q-btn
          ></template>
        </q-banner>
      </q-card-section>
      <q-card-section v-else-if="state === 'migration_required'">
        <q-banner rounded inline-actions icon="upgrade">
          This wallet needs an explicit migration before it can be used. Please
          contact your administrator.
          <template #action
            ><q-btn flat label="Retry" @click="inspect"></q-btn
          ></template>
        </q-banner>
      </q-card-section>
      <q-card-section v-else-if="state === 'wallet_locked' && !mode">
        <div class="text-h6">Unlock your wallet</div>
        <p>Your wallet is locked after reload or inactivity.</p>
        <q-input
          v-model="password"
          type="password"
          label="Local unlock password or PIN"
          @keyup.enter="unlock"
        ></q-input>
        <div class="row items-center q-gutter-sm q-mt-md">
          <q-btn
            unelevated
            color="primary"
            label="Unlock"
            :loading="working"
            @click="unlock"
          ></q-btn>
          <q-space></q-space>
          <q-btn
            outline
            color="primary"
            icon="logout"
            :label="$t('logout')"
            @click="utils.logout"
          ></q-btn>
        </div>
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
        ></q-btn>
        <q-btn flat class="q-ml-sm" label="Lock" @click="lock"></q-btn>
      </q-card-section>
      <q-card-section v-else-if="state === 'recovery_required' && !mode">
        <div class="text-h6">Restore your wallet</div>
        <p>
          This browser has no usable local vault. Restore the same recovery
          phrase to continue.
        </p>
        <div class="row justify-end q-gutter-sm q-mt-md">
          <q-btn
            unelevated
            color="primary"
            label="Restore wallet"
            @click="startRestore"
          ></q-btn>
          <q-btn
            flat
            icon="logout"
            :label="$t('logout')"
            @click="utils.logout"
          ></q-btn>
        </div>
      </q-card-section>
      <q-card-section v-else-if="state === 'pending' && !mode">
        <div class="text-h6">Create or restore</div>
        <div class="row q-gutter-sm q-mt-md">
          <q-btn
            unelevated
            color="primary"
            label="Create new wallet"
            @click="startCreate"
          ></q-btn>
          <q-btn
            outline
            color="primary"
            label="Restore wallet"
            @click="startRestore"
          ></q-btn>
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
        <div v-if="mode === 'create' && !backupAcknowledged">
          <div class="row q-col-gutter-sm q-mb-md">
            <div class="col-6">
              <q-chip
                square
                class="full-width"
                icon="looks_one"
                :color="backup.step === 1 ? 'primary' : 'grey-9'"
                text-color="white"
                label="Backup"
              ></q-chip>
            </div>
            <div class="col-6">
              <q-chip
                square
                class="full-width"
                icon="looks_two"
                :color="backup.step === 2 ? 'primary' : 'grey-9'"
                text-color="white"
                label="Verify"
              ></q-chip>
            </div>
          </div>

          <q-separator class="q-mb-md"></q-separator>

          <div v-if="backup.step === 1">
            <div class="row items-center justify-between q-mb-md">
              <div>
                <div
                  class="text-subtitle1"
                  v-text="`${seedWords.length}-word recovery phrase`"
                ></div>
                <div
                  class="text-caption text-grey-5"
                  v-text="'Write these words down in order.'"
                ></div>
              </div>
              <q-btn
                outline
                no-caps
                color="primary"
                :icon="backup.visible ? 'visibility_off' : 'visibility'"
                :label="backup.visible ? 'Hide words' : 'Show words'"
                @click="backup.visible = !backup.visible"
              ></q-btn>
            </div>

            <div class="row q-col-gutter-sm">
              <div
                class="col-4 col-md-3"
                v-for="word in seedWords"
                :key="word.index"
              >
                <div
                  class="row items-center no-wrap rounded-borders"
                  style="
                    min-height: 42px;
                    border: 1px solid rgba(255, 255, 255, 0.14);
                    background: rgba(255, 255, 255, 0.035);
                  "
                >
                  <div
                    class="text-caption text-grey-5 text-center"
                    style="
                      width: 42px;
                      border-right: 1px solid rgba(255, 255, 255, 0.1);
                    "
                    v-text="word.index + 1"
                  ></div>
                  <div
                    class="text-body2 text-weight-medium q-px-sm"
                    style="min-width: 0; overflow-wrap: anywhere"
                    v-text="backup.visible ? word.word : '••••••'"
                  ></div>
                </div>
              </div>
            </div>

            <div class="row justify-end q-mt-lg">
              <q-btn
                color="primary"
                no-caps
                label="I have written it down"
                @click="prepareChallenge"
              ></q-btn>
            </div>
          </div>

          <div v-else>
            <div class="q-mb-md">
              <div class="text-subtitle1" v-text="'Confirm your backup'"></div>
              <div
                class="text-caption text-grey-5"
                v-text="
                  'Enter the requested words from your written recovery phrase.'
                "
              ></div>
            </div>

            <div class="row q-col-gutter-md">
              <div
                class="col-12 col-sm-6"
                v-for="word in backup.challenge"
                :key="word.index"
              >
                <q-input
                  v-model.trim="backup.answers[word.index]"
                  filled
                  :label="`Word ${word.index + 1}`"
                ></q-input>
              </div>
            </div>
            <div
              class="text-negative q-mt-sm"
              v-if="backup.error"
              v-text="backup.error"
            ></div>
            <div class="row justify-between q-mt-lg">
              <q-btn flat no-caps label="Back" @click="backup.step = 1"></q-btn>
              <q-btn
                color="primary"
                icon="check"
                no-caps
                label="Confirm backup"
                @click="submitChallenge"
              ></q-btn>
            </div>
          </div>
        </div>
        <q-banner
          v-else-if="mode === 'create'"
          rounded
          class="bg-positive text-white q-mb-md"
        >
          Recovery phrase backup verified.
        </q-banner>
        <div v-else>
          <div class="text-subtitle1 q-mb-sm">Recovery phrase</div>
          <div class="row q-col-gutter-sm">
            <div
              v-for="(_, index) in mnemonicWords"
              :key="index"
              class="col-6 col-sm-4"
            >
              <q-input
                v-model.trim="mnemonicWords[index]"
                filled
                :label="`Word ${index + 1}`"
                autocomplete="off"
                autocapitalize="none"
                spellcheck="false"
                @paste="pasteMnemonic($event, index)"
              ></q-input>
            </div>
          </div>
          <div class="text-caption text-grey-7 q-mt-sm">
            Enter the 12 words in order. You can paste the complete phrase into
            any box.
          </div>
        </div>
        <q-input
          v-model="password"
          type="password"
          label="PIN (optional)"
          inputmode="numeric"
          maxlength="6"
          autocomplete="new-password"
          class="q-mt-md"
        ></q-input>
        <q-input
          v-model="passwordRepeat"
          type="password"
          label="Confirm PIN"
          inputmode="numeric"
          maxlength="6"
          autocomplete="new-password"
        ></q-input>
        <div class="text-caption text-grey-7 q-mt-sm">
          Optional 6-digit PIN. Forgetting it is recoverable with your mnemonic
          backup.
        </div>
        <q-btn
          class="q-mt-md"
          unelevated
          color="primary"
          :label="mode === 'create' ? 'Create wallet' : 'Restore wallet'"
          :disable="mode === 'create' && !backupAcknowledged"
          :loading="working"
          @click="submit"
        ></q-btn>
        <q-btn
          class="q-mt-md q-ml-sm"
          flat
          label="Cancel"
          @click="cancel"
        ></q-btn>
      </q-card-section>
    </q-card>
  </div>
</template>
