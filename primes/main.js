let b = [];
process.stdin.on('data', c => b.push(c)).on('end', () => {
  const N = parseInt(Buffer.concat(b).toString().trim(), 10);
  if (N < 2) { console.log(0); return; }
  const K = N >> 1;
  const s = Buffer.alloc((K + 7) >> 3);
  const lim = Math.sqrt(N) | 0;
  for (let i = 1; 2 * i + 1 <= lim; i++) {
    if (s[i >> 3] & (1 << (i & 7))) continue;
    const p = 2 * i + 1;
    for (let j = (p * p - 1) >> 1; j < K; j += p) s[j >> 3] |= 1 << (j & 7);
  }
  let cnt = 1;
  for (let i = 1; i < K; i++) if (!(s[i >> 3] & (1 << (i & 7)))) cnt++;
  console.log(cnt);
});
