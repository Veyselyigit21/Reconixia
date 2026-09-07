# IDOR / BOLA Testing

Reconixia can assist with IDOR/BOLA triage by replaying owned-account requests with two separate authorized test accounts.

This module is designed for bug bounty programs that explicitly allow testing with accounts you own and control. Do not use it against other users, third-party systems, or endpoints where replaying the request could modify, delete, purchase, bid, stream, message, or otherwise affect production state.

## Workflow

1. Create two test accounts allowed by the program, for example `username@wearehackerone.com` and `username+whatnot@wearehackerone.com`.
2. Log in as account A.
3. Browse account-owned surfaces such as profile, orders, addresses, seller inventory, livestream management, messages, or account settings.
4. Export requests as HAR from the browser or Burp.
5. Get account A and account B auth headers.
6. Run `reconixia-idor`.

```bash
export RECONIXIA_IDOR_AUTH_A='Authorization: Bearer account-a-token'
export RECONIXIA_IDOR_AUTH_B='Authorization: Bearer account-b-token'

./reconixia-idor \
  -target whatnot.com \
  -har whatnot-owned-account.har \
  -rules examples/program-policies/whatnot.idor-policy.example.json \
  -h1-user aello \
  -rate 2 \
  -max 50
```

For applications that store session state in cookies instead of a bearer header, keep the cookie values in environment variables only:

```bash
export RECONIXIA_IDOR_COOKIE_A='account-a-cookie-header-value'
export RECONIXIA_IDOR_COOKIE_B='account-b-cookie-header-value'
```

Never paste those values into chats, reports, screenshots, or JSONL files.

## Classification

- `possible_idor`: account B received a successful response for account A's request.
- `protected`: account B received `401`, `403`, or `404`.
- `public_endpoint`: the no-auth baseline could access a similar response, so the signal is not IDOR by itself.
- `empty_or_anonymous`: account A did not receive meaningful GraphQL account data; refresh cookies or capture object-detail requests with owned IDs.
- `inconclusive`: responses are not enough to make a useful call.

The module does not store raw response bodies. It records status codes, response sizes, object hints, and sensitive-looking JSON field names such as `email`, `role`, `userId`, `accountId`, `balance`, `address`, or `token`.

High-value IDOR captures should include object-detail reads, not only generic dashboard queries. Prefer owned objects such as order detail, shipment detail, conversation detail, listing/inventory detail, payout detail, address detail, or seller settings detail. Generic `me` queries often compare the current session's own account or return empty anonymous data, which is useful for safety but weak for IDOR proof.

## Safety Defaults

- Default allowed methods are `GET`, `HEAD`, and `OPTIONS`.
- Read-only GraphQL `POST` requests whose body starts with `query` are allowed when the program policy includes `POST`.
- GraphQL `mutation`, `PUT`, `PATCH`, and `DELETE` require `-allow-mutating`.
- Captured `Authorization` and `Cookie` headers from HAR are stripped and replaced with the explicit account A/B auth values.
- The default request rate is low. Keep it within the program's rate limits.

## Program Policy

Different programs have different rules. Use `-rules` to keep those constraints explicit and reusable.

```json
{
  "name": "Example owned-account IDOR policy",
  "target": "example.com",
  "research_header": "X-HackerOne-Research",
  "h1_user": "aello",
  "rate": 2,
  "max_requests": 50,
  "require_owned_accounts": true,
  "allow_mutating": false,
  "allowed_methods": ["GET", "HEAD", "OPTIONS"],
  "blocked_url_keywords": ["/checkout", "/purchase", "/bid", "/message/send"]
}
```

If `allowed_methods` contains a mutating method such as `POST`, the command still requires `-allow-mutating` or `"allow_mutating": true`. Keep that enabled only for lab targets or for owned test data where the program explicitly permits it.
