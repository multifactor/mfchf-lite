const argon2 = require('argon2-browser')
const crypto = require('crypto')
const xor = require('buffer-xor')
const speakeasy = require('speakeasy')
const random = require('random-number-csprng')

function mod (n, m) {
  return ((n % m) + m) % m
}

async function setup (password) {
  const target = await random(0, (10 ** 8) - 1)
  const secret = await crypto.randomBytes(24)
  const code = parseInt(speakeasy.hotp({ secret: secret.toString('hex'), encoding: 'hex', counter: 1, algorithm: 'sha1', digits: 8 }))
  console.log(code)
  const offset = mod(target - code, 10 ** 8)
  const uri = speakeasy.otpauthURL({ secret: secret.toString('hex'), encoding: 'hex', label: 'mfchf', type: 'hotp', counter: 1, issuer: 'mfchf', algorithm: 'sha1', digits: 8 })
  const salt = await crypto.randomBytes(24)
  const hash = await argon2.hash({ pass: password + target, salt, time: 100, mem: 4096, type: argon2.ArgonType.Argon2id })
  const pad = xor(hash.hash, secret)
  const sha = crypto.createHash('sha256').update(hash.hash).digest('base64')
  const out = 'mfchf-argon2id-hotp8#1,' + offset + ',' + pad.toString('base64') + '#' + sha + '#' + salt.toString('base64')
  console.log(out)
  return { uri, out }
}

async function verify (password, otp, mfchf) {
  const parts = mfchf.split('#')
  const hotp = parts[1].split(',')
  const ctr = parseInt(hotp[0]) + 1
  const offset = parseInt(hotp[1])
  const pad = Buffer.from(hotp[2], 'base64')
  const enc = parts[2]
  const salt = Buffer.from(parts[3], 'base64')

  const target = mod(offset + otp, 10 ** 8)
  const hash = await argon2.hash({ pass: password + target, salt, time: 100, mem: 4096, type: argon2.ArgonType.Argon2id })
  const sha = crypto.createHash('sha256').update(hash.hash).digest('base64')

  if (sha !== enc) return { valid: false };

  const secret = xor(pad, hash.hash)
  const code = parseInt(speakeasy.hotp({ secret: secret.toString('hex'), encoding: 'hex', counter: ctr, algorithm: 'sha1', digits: 8 }))
  const next = mod(target - code, 10 ** 8)

  const out = 'mfchf-argon2id-hotp8#' + ctr + ',' + next + ',' + pad.toString('base64') + '#' + sha + '#' + salt.toString('base64')
  return { valid: true, out }

}

module.exports.setup = setup
module.exports.verify = verify
