import assert from 'node:assert/strict'
import test from 'node:test'

import { canManageIdentity } from '../../src/identityPermissions.ts'

test('administrator UI does not offer controls for the current account', () => {
  assert.equal(canManageIdentity('usr_admin', 'usr_admin'), false)
})

test('administrator UI offers controls for a different valid account', () => {
  assert.equal(canManageIdentity('usr_admin', 'usr_target'), true)
})

test('missing identity context fails closed', () => {
  assert.equal(canManageIdentity('', 'usr_target'), false)
  assert.equal(canManageIdentity('usr_admin', ''), false)
  assert.equal(canManageIdentity('   ', 'usr_target'), false)
})
