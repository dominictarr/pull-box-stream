'use strict'
var sodium = require('sodium/build/Release/sodium')
var Reader = require('pull-reader')
var increment = require('increment-buffer')
var through = require('pull-through')
var split = require('split-buffer')

var isBuffer = Buffer.isBuffer
var concat = Buffer.concat

var zeros = new Buffer(16); zeros.fill(0)

function box (buffer, nonce, key) {
  var b = sodium.crypto_secretbox(buffer, nonce, key)
  return b.slice(16, b.length)
}

function unbox (boxed, nonce, key) {
  return sodium.crypto_secretbox_open(concat([zeros, boxed]), nonce, key)
}

function unbox_detached (mac, boxed, nonce, key) {
  return sodium.crypto_secretbox_open(concat([zeros, mac, boxed]), nonce, key)
}

var max = 1024*4

var NONCE_LEN = 24
var HEADER_LEN = 2+16+16

function isZeros(b) {
  for(var i = 0; i < b.length; i++)
    if(b[i] !== 0) return false
  return true
}
exports.createBoxStream =
exports.createEncryptStream = function (key) {

var zeros = new Buffer(16); zeros.fill(0)
  var init_nonce = new Buffer(24), first = true
  sodium.randombytes(init_nonce)
  // we need two nonces because increment mutates,
  // and we need the next for the header,
  // and the next next nonce for the packet
  var nonce1 = new Buffer(24), nonce2 = new Buffer(24)
  init_nonce.copy(nonce1, 0, 0, 24)
  init_nonce.copy(nonce2, 0, 0, 24)
  var head = new Buffer(18)

  return through(function (data) {

    if(!isBuffer(data))
      return this.emit('error', new Error('input must be a buffer'))

    if(first) {
      this.queue(init_nonce)
      first = false
    }
    var input = split(data, max)

    for(var i = 0; i < input.length; i++) {
      head.writeUInt16BE(input[i].length, 0)
      var boxed = box(input[i], increment(nonce2), key)
      //write the mac into the header.
      boxed.copy(head, 2, 0, 16)

      this.queue(box(head, nonce1, key))
      this.queue(boxed.slice(16, 16 + input[i].length))

      increment(increment(nonce1)); increment(nonce2)
    }
  }, function (err) {
    if(err) return this.queue(null)

    //handle special-case of empty session
    if(first) {
      this.queue(init_nonce)
      first = false
    }

    //final header is same length as header except all zeros (inside box)
    var final = new Buffer(2+16); final.fill(0)
    this.queue(box(final, nonce1, key))
    this.queue(null)
  })

}
exports.createUnboxStream =
exports.createDecryptStream = function (key) {

var zeros = new Buffer(16); zeros.fill(0)
  var reader = Reader(), first = true, nonce, ended

  return function (read) {
    reader(read)
    return function (abort, cb) {
      if(ended) return cb(ended)
      if(!first) rest()
      else {
        first = false
        reader.read(NONCE_LEN, function (err, _nonce) {
          if(err) return cb(err)
          nonce = _nonce
          rest()
        })
      }

      function rest () {
        reader.read(HEADER_LEN, function (err, cipherheader) {
          if(err === true) return cb(new Error('unexpected hangup'))
          if(err) return cb(err)

          var header = unbox(cipherheader, nonce, key)

          if(!header)
            return cb(new Error('invalid header'))

          if(isZeros(header))
            return cb(ended = true)

          var length = header.readUInt16BE(0)
          var mac = header.slice(2, 34)

          reader.read(length, function (err, cipherpacket) {
            if(err) return cb(err)
            //recreate a valid packet
            //TODO: PR to sodium bindings for detached box/open
            var plainpacket = unbox_detached(mac, cipherpacket, increment(nonce), key)
            if(!plainpacket)
              return cb(new Error('invalid packet'))

            increment(nonce)
            cb(null, plainpacket)
          })
        })
      }
    }
  }
}
