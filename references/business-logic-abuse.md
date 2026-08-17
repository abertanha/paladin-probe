# Business Logic Abuse

Test edge cases the developer never considered. Focus on state transitions,
financial operations, multi-step workflows, and limit enforcement.

## Probe Patterns

### Workflow Bypass
- Skip required steps (e.g., go straight to /checkout without /cart)
- Reorder steps (e.g., apply coupon after final price calculated)
- Repeat steps (e.g., apply same coupon N times)
- Partial completion (e.g., start registration but never confirm email, yet get access)

### Race Conditions (TOCTOU)
- Check balance → time gap → withdraw: withdraw more than balance
- Reserve item → time gap → confirm: over-reserve inventory
- Validate coupon → time gap → apply: use coupon N times in parallel
- Pattern: any "check then act" with a gap between them

### Value Manipulation
- Negative values: quantity=-1, discount=-100, transfer=-5000
- Overflow values: MAX_INT + 1, very large decimals
- Precision attacks: 0.1 + 0.2 != 0.3 in floating point
- Type confusion: string "infinity" as price, NaN as quantity
- Null/unset fields that bypass validation (e.g., price: null → free)

### Limit/Quota Bypass
- Pagination: request page 9999 to enumerate all records
- Rate limit: test per-IP vs per-user vs per-session limiting
- Max quantity: order 9999 items when limit is 10
- File size: upload tiny file vs enormous file vs 0-byte file
- Concurrent sessions: does limit apply globally or per-session?

### Idempotency Violations
- POST without idempotency key → repeat request creates multiple resources
- PUT with partial body → second call behaves differently than first
- DELETE on already-deleted resource → different response code

## Example: E-commerce Discount Abuse

```
Flow: Add items → Apply code COOL50 → See 50% off → Checkout

Test scenarios:
- Apply COOL50, remove, apply again → 50% off again? 100% off?
- Apply COOL50, change quantity, recalculate → discount still applies?
- Apply COOL50 + STACK20 → 70% off? 50% off of 20% off? Error?
- Apply COOL50 → checkout → cancel → re-checkout → discount still active?
- Apply COOL50, modify price in intercepted request → -$100 total?
```

## Integration with Domain Druid

Before probing, load active business rules from domain-druid:

```yaml
# Rules to target for abuse:
- "Max 5 active subscriptions per user" → try creating 6 in parallel
- "Discount code single-use" → try using same code on two accounts
- "Refund only within 30 days" → try refunding with altered timestamp
```
