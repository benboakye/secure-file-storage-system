import assert from 'node:assert/strict'
import test from 'node:test'

import {
  handleAuthenticationExpiry,
  subscribeToAuthenticationExpiry,
} from '../../src/authenticationExpiry.ts'

test('server-confirmed session expiry clears credentials and notifies the app', () => {
  let credentialsCleared = 0
  let appNotifications = 0
  const unsubscribe = subscribeToAuthenticationExpiry(() => { appNotifications += 1 })

  const handled = handleAuthenticationExpiry(
    401,
    'AUTHENTICATION_REQUIRED',
    () => { credentialsCleared += 1 },
  )

  assert.equal(handled, true)
  assert.equal(credentialsCleared, 1)
  assert.equal(appNotifications, 1)
  unsubscribe()
})

test('expected authentication failures do not invalidate an existing session', () => {
  let credentialsCleared = 0
  let appNotifications = 0
  const unsubscribe = subscribeToAuthenticationExpiry(() => { appNotifications += 1 })

  assert.equal(handleAuthenticationExpiry(401, 'INVALID_CREDENTIALS', () => { credentialsCleared += 1 }), false)
  assert.equal(handleAuthenticationExpiry(401, 'MFA_INVALID', () => { credentialsCleared += 1 }), false)
  assert.equal(handleAuthenticationExpiry(401, 'STEP_UP_FAILED', () => { credentialsCleared += 1 }), false)
  assert.equal(handleAuthenticationExpiry(403, 'AUTHENTICATION_REQUIRED', () => { credentialsCleared += 1 }), false)

  assert.equal(credentialsCleared, 0)
  assert.equal(appNotifications, 0)
  unsubscribe()
})

test('unsubscribed application owners are not notified', () => {
  let appNotifications = 0
  const unsubscribe = subscribeToAuthenticationExpiry(() => { appNotifications += 1 })
  unsubscribe()

  assert.equal(handleAuthenticationExpiry(401, 'AUTHENTICATION_REQUIRED', () => {}), true)
  assert.equal(appNotifications, 0)
})
