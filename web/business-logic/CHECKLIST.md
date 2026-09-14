# Business Logic Manual Checklist

Use only researcher-controlled accounts and reversible/non-monetary proof.

## Payment, coupon, order, booking, entitlement

For each feature that actually exists in the normal Minly UI:

1. Identify the server-controlled invariant.
2. Record the normal request from Account A.
3. Repeat the same normal flow from Account B where available.
4. Check whether the client controls fields that should be server-owned, such as price, discount, entitlement, owner, order status, refund amount, or creator/service ID.
5. Perform only one minimal safe comparison.
6. Stop before financial loss, duplicate fulfillment, spam, or staff/celebrity burden.

## Evidence required

- Expected invariant.
- Actual server behavior.
- Researcher-controlled account/object proof.
- Minimal redacted request/response or visual evidence.
- Concrete "As an attacker, I could..." impact statement.

Scanner-only warnings and theoretical tampering ideas are not submission-ready.
