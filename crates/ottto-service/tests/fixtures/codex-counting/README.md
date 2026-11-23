# Historical Codex counting heads

These synthetic heads were captured by the pre-change writer at source
`8012fa9a10a200ac0ee5a90dfff7172ec64443dc`, using capture commit
`aab3eaa48d3649e8132166b9ca64983078e20f53` in
[Linux CI 44072881863](https://github.com/ottto-ai/ottto/actions/runs/44072881863).

`legacy-head.json` and `v2-head.json` use identical records: one native response
and two equal UI observations. The old formula counted 200 input and 20 output
tokens; V2 counts 100 input and 30 output tokens. `sticky-legacy-head.json`
is the original cross-build transition's first closed turn.

Tests decode and re-encode each frozen head byte-for-byte before rebinding its
physical envelope to the same synthetic input on the test runner. Historical
counting, cutover and evidence slots retain their original bytes; no historical
counting producer remains in the test harness.
