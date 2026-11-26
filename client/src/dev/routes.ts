// Development only: the stand-in's route table and the helpers its service
// handlers share.
import type { Role, User } from '../lib/types'
import * as seed from './seed'

export type Json = Record<string, unknown>
export interface Ctx { method: string; path: string; query: URLSearchParams; body: Json | null; user: User | null; headers: Headers }
export interface AuthCtx extends Ctx { user: User }
export type Handler = (ctx: Ctx, match: RegExpMatchArray) => [number, unknown]
export type AuthHandler = (ctx: AuthCtx, match: RegExpMatchArray) => [number, unknown]

export const all: Role[] = ['CUSTOMER', 'MERCHANT', 'RIDER', 'SUPPORT', 'OPERATIONS']
export const routes: [string, RegExp, string, Role[] | null, string, Handler][] = []
export const on = (method: string, pattern: RegExp, op: string, roles: Role[] | null, service: string, handler: Handler) => routes.push([method, pattern, op, roles, service, handler])
export const onAuth = (method: string, pattern: RegExp, op: string, roles: Role[], service: string, handler: AuthHandler) =>
  routes.push([method, pattern, op, roles, service, (ctx, match) => (ctx.user ? handler({ ...ctx, user: ctx.user }, match) : err(401, 'unauthenticated', 'Sign in first.'))])

// 16 random bytes in hex: the 32-character form of the gateway's request ID.
export const ref = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('')
export const err = (status: number, error: string, message: string, field?: string): [number, unknown] => [status, { error, message, ...(field ? { field } : {}) }]
export const now = () => new Date().toISOString()

function stockState(id: string) {
  const row = seed.stock.get(id)
  if (!row || row.stock === null) return 'made_to_order'
  const free = row.stock - row.reserved
  // The Inventory service's low-stock mark: 15 free units or fewer.
  return free <= 0 ? 'out' : free <= 15 ? 'low' : 'in_stock'
}
export function itemView(id: string) {
  const item = seed.items.find((i) => i.id === id)
  if (!item) throw new Error(`Unknown seed item: ${id}`)
  return { ...item, stock_state: stockState(id) }
}
export const merchantOf = (id: string) => seed.merchants.find((m) => m.id === id)

export function freeDelivery(customer: string, merchantId: string) {
  const merchant = merchantOf(merchantId)
  if (!merchant || merchant.section !== 'mart') return false
  return !seed.orders.some((o) => o.customer === customer && merchantOf(o.merchant)?.section === 'mart' && o.status !== 'cancelled')
}

export const findOrder = (id: string) => seed.orders.find((o) => o.id === id)
