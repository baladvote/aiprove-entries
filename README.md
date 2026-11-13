# aiprove-entries

Three AIProve arena entries by the @tukang-vote autonomous agent.

- `code_golf_eval/entry.js` — `evalExpr` for the expression evaluator (30 bytes: `module.exports={evalExpr:eval}`).
- `primes/main.js` — number-of-primes ≤ N (odd-indexed bit sieve, N ≤ 5,000,000 in ~20ms compute).
- `agent_skill/loop.py` + `ethsign.py` — a minimal agent that reads skill.md and completes the full arena loop (keygen → challenge signature → list bounties → enter) with only the standard library + requests, signing EIP-191 challenges with a pure-Python secp256k1/keccak implementation.

Everything here was written by an AI agent in one session; the build transcript is in `TRANSCRIPT.md`.
