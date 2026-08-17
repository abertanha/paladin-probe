# Business Logic Abuse Scenarios

Domain-specific scenario templates. Adapt to the actual codebase.

## E-Commerce

### Discount Abuse
- Apply code → remove → re-apply: does it stack?
- Apply code on item → change quantity → price recalculated with discount?
- Apply code → checkout → cancel → re-checkout: discount still valid?
- Multiple codes: can they stack? Exceed 100% off?
- Negative discount: code with value -100 generates credit?
- Apply code, intercept and modify discount percentage in request
- Expired code: manipulate timestamp or reuse old code ID

### Cart/Purchase Manipulation
- Add item, intercept price change in request: pay $0.01
- Add item with negative quantity: reduce total?
- Add item, buy, refund, re-buy same item: refund > purchase price?
- Purchase with insufficient funds: race condition between check and debit
- Create order, intercept total in request body vs server-computed total
- Gift card: use partial balance, remaining should persist. Does it?

### Inventory Races
- Add last item to cart, but don't checkout
- Second user adds same item and checks out first
- First user checks out → oversold?
- Reserve → timeout → release: can you checkout after reserve expired?

## Banking/Fintech

### Transfer Logic
- Transfer negative amount: receive money instead of sending?
- Transfer more than balance: race between balance check and debit
- Transfer to self: does it count as valid transaction?
- Transfer to non-existent account: is money lost?
- Scheduled transfer: cancel after schedule, modify amount before execution
- Batch transfer: one fails → whole batch rolls back? Partial commit?

### Withdrawal
- Withdraw negative amount: deposit instead?
- Withdraw more than balance: race condition
- Withdraw with fee: can fee exceed withdrawal amount? Negative fee?
- Multiple simultaneous withdrawals from same account

## SaaS / Multi-Tenant

### Tenant Isolation
- Access tenant A data with tenant B token
- Change tenant ID in URL/body
- Create resource without tenant ID: visible to all tenants?
- Delete tenant A resource from tenant B session

### Subscription/Plan
- Sign up for free → upgrade → downgrade before billing date → features?
- Cancel → immediate vs end-of-period: access revoked correctly?
- Change plan quantity: proration logic exploitable?
- Trial → cancel → re-signup: infinite trials?
- Payment fails → grace period → payment succeeds: timeline correct?

## User Management

### Registration
- Register with existing email: error or overwrite?
- Register with existing username: error?
- Register with role field in body: escalate?
- Register with no email verification: full access immediately?
- Register, verify email, change email, verify again: old email verified?

### Deletion
- Delete account → can you re-register with same email immediately?
- Delete account → resources still accessible via shared links?
- Delete account → associated data (reviews, orders) orphaned?
- Admin deletes user → user's active sessions invalidated?

### Invitations
- Invite self to organization: accept own invite?
- Invite non-existent email: invite consumed or resendable?
- Invite → change email before accepting: hijack invite?
- Invite with admin role: escalate via invitation system?

## Resource Exhaustion

### ReDoS — Regex Catastrophic Backtracking
- Input `a` repeated 50+ times then `b` matches catastrophic regex like `(a+)+b`
- URLs with long parameter values hitting regex-based validation
- Email validation regex with nested quantifiers and long input
- Rate-limited vs unauthenticated endpoints — unauthenticated ReDoS is more severe

### Large Payload Abuse
- Upload enormous request body (100 MB+ JSON)
- Submit array with 100k+ elements to batch endpoints
- Deep JSON/XML nesting (10k+ levels) to trigger stack overflow
- GraphQL query with deep nesting on introspection-enabled endpoints

### Pagination / Resource Abuse
- Request `?limit=9999999` on paginated endpoints
- Request `?page=100000` on cursor-less pagination (sequential DB scan)
- Download massive CSV export while server generates it in memory
- Upload enormous image that triggers expensive thumbnail generation

### Expensive Query Attacks
- Sort on unindexed column with large dataset
- Use `LIKE '%...%'` pattern on text search (full table scan)
- Request deeply joined GraphQL queries (friends-of-friends-of-friends)
- Trigger expensive aggregation on large dataset without filters
