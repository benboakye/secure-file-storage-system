/**
 * Identity controls always target another account. The API is authoritative,
 * while this UI policy prevents an administrator from being offered a control
 * that the server must reject and labels the row as the current account.
 */
export function canManageIdentity(actorId: string, targetId: string): boolean {
  const actor = actorId.trim()
  const target = targetId.trim()
  return actor !== '' && target !== '' && actor !== target
}
