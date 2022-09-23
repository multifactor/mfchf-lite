const mfchf = require('./index');

(async () => {
  // const hash = await mfchf.argon2id.hotp6.setup('password')
  const out = await mfchf.argon2id.hotp6.verify('password', 864615, 'mfchf-argon2id-hotp6#1,711916,Sbvq2UOfJ9uQcwb0Lji91/7hmwkczPcy#bsZYy5ocRmtb9YzStgubHhVJWhVOWQdSHCwopyadNCE=#7Xf2vRPhdvLtfiW0+88Jo2a2d2a211eH')
  console.log(out)
})();
