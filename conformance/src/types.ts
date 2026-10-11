// Response shapes from SPEC §9 (only the fields the suite reads).
export type Kind = 'platform' | 'user' | 'customer' | 'app' | 'agent'
export type Scope = { type: 'merchant' | 'store'; id: string }

export interface Merchant { id: string; name: string; status: 'active' | 'suspended' }
export interface Store { id: string; merchantId: string; name: string }
export interface Product { id: string; title: string; priceCents: number }
export interface Role { id: string; name: string; system: boolean; permissions: string[]; refundLimitCents?: number | null }
export interface Assignment { id: string; userId?: string; roleId?: string; scope?: Scope }
export interface OrderItem { productId: string; qty: number; unitPriceCents: number }
export interface Order {
  id: string
  storeId: string
  customerId: string
  items: OrderItem[]
  totalCents: number
  status: 'pending' | 'paid' | 'fulfilling' | 'delivered' | 'cancelled'
  refundedCents: number
}
export interface Payment { id: string; orderId: string; status: 'captured'; amountCents: number }
export interface Shipment { id: string; orderId: string; carrier: string; status: 'label_created' | 'in_transit' | 'delivered' }
export interface ClientCreds { id: string; clientId: string; clientSecret: string }
export interface Install { id: string; appId: string; storeId: string; scopes: string[] }
export interface Grant { id: string; expiresAt: string }
export interface BreakGlass { id: string; expiresAt: string }
export interface AuditEntry { actor: string; action: string; merchantId: string; at: string }
export interface Me { id: string; kind: Kind; merchantId?: string | null }
export interface Items<T> { items: T[] }
