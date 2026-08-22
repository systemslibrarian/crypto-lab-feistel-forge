10. Feistel Forge

crypto-lab-feistel-forge · ENCRYPTION

Thesis. SPN gets three labs (Iron Serpent, Biham Lens, Matsui Line). Sponge gets two (KMAC Gate, Ascon). Feistel — the third construction the block-cipher world is built from — gets none.

Construction. Real DES: full 16 rounds, real S-boxes, PC-1/PC-2 key schedule, IP/FP. Not a toy cipher — Biham Lens already occupies the toy-SPN slot. Vectors: withdrawn is fine, unmarked is not. Revision 3 said to avoid withdrawn FIPS 46-3 and then offered SP 800-17 — which was itself withdrawn in 2018, precisely because it covers deprecated algorithms including DES. For a historical cipher there may be no live normative source, and that is acceptable. Use NIST's archived CAVP DES validation vectors as the executable anchor, cite FIPS 46-3 and SP 800-17 as historical specification and validation sources, and mark both withdrawn, with dates, in PRIOR-ART.md per the contract rule.

Acts
The round. Step one Feistel round. Show that F need not be invertible and the structure is still reversible — the property that makes Feistel possible and is invisible in SPN designs.
Same circuit both ways. Decrypt by running the identical circuit with the key schedule reversed. Weak keys where encryption is decryption.
Complementation. DES(K̄, P̄) = ¬DES(K, P). One free bit off brute force, on real vectors.
2DES meet-in-the-middle. Encrypt under all K1 into a table, decrypt under all K2, match. Reduced keyspace so it completes in-browser, with real-scale numbers beside it. This is why the answer was 3DES and not 2DES.
Sweet32 — the climax. A 64-bit block collides after roughly 2³² blocks. In CBC, C_i = C_j gives P_i ⊕ P_j = C_{i−1} ⊕ C_{j−1}; with a known repeated plaintext — a session cookie in every request — the unknown falls out. Arrange the collision rather than generating 32 GB, say so persistently, and show the birthday math live so the arrangement is auditable.

Negative claim (NEG-1). Increasing key length does not repair a 64-bit block-size birthday bound. Keep it to that. 3DES had separate key-strength limitations as well — meet-in-the-middle against 2-key variants, and the deprecation rationale cited both — and the teaching point is that these are independent axes: fixing the key axis left the block size exactly where it was. Links to Nonce Collision and Collision Vault, which teach the same bound in two other places.

Failure codes. WEAK_KEY · PARITY_INVALID · BLOCK_SIZE_EXCEEDED (the Sweet32 data limit, reported as the policy failure a real library should raise)

Repo description.

Browser demo: real DES stepped round by round, 2DES falling to meet-in-the-middle, and a 64-bit block colliding at the birthday bound to leak a repeated plaintext out of CBC. No key length repairs a block size.