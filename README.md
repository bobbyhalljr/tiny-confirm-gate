# tiny-confirm-gate

A one-file TypeScript **side-effect confirm gate** for agent tool calls.

- Reads (`GET` / `HEAD` / `OPTIONS`) pass.
- Side effects (`POST` / form submit / webhook / email / payment / file write / shell mutate) need a short-lived, one-time confirm token bound to the **exact** action payload.
- Optional dry-run returns what would happen without executing.
- No API key. No real network. Uses `node:crypto`.

## Run

```bash
npm install
npx tsx confirm.ts
npx tsc --noEmit
```

## Idea

Egress allowlists decide **where** an agent may talk. This gate decides **whether** a mutating action may run without an explicit confirm of the canonical payload hash.

## License

MIT

## Write-up

Full walkthrough on Dev.to: https://dev.to/bobbyhalljr/your-agent-hit-the-real-web-build-a-tiny-side-effect-confirm-gate-in-typescript-35dc
