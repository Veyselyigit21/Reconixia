# Safe PoC Helpers

Reconixia intentionally does not include reverse shell generators, persistence helpers, destructive payloads, or code-execution payload builders.

For bug bounty work, those features create unnecessary risk and are commonly prohibited by program rules. Most high-value web/API findings can be demonstrated with safer evidence:

- Account A/B authorization replay for IDOR/BOLA.
- Sensitive field classification without storing raw response bodies.
- OAST/callback verification for blind server-side interactions.
- Minimal screenshots, request/response metadata, and reproduction steps.

## Callback Helper

The browser extension includes a safe callback helper. Paste your own OAST domain, such as a Burp Collaborator or interactsh domain, and it generates:

```txt
https://your-oast-domain/reconixia/aello
http://your-oast-domain/reconixia/aello
aello.your-oast-domain
```

Use these only for authorized, non-destructive callback checks. Do not use payloads that open a shell, install persistence, modify data, or degrade service.

## Why Not Reverse Shells?

Reverse shells prove command execution by creating an interactive connection from the target to the researcher. That can cross into backdoor or persistent-access territory and may violate bug bounty rules even when the original vulnerability is in scope.

For report quality, prefer safer evidence:

- Show that a controlled callback fired.
- Show the vulnerable parameter and exact request.
- Show minimal non-sensitive server-side behavior.
- Stop when impact is clear.
