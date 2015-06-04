'use strict'
var sodium = require('sodium/build/Release/sodium')
var Reader = require('pull-reader')
var increment = require('increment-buffer')
var through = require('pull-through')
var split = require('split-buffer')

var isBuffer = Buffer.isBuffer

var zeros = new Buffer(16); zeros.fill(0)

var unbox = sodium.crypto_secretbox_open
var box   = sodium.crypto_secretbox

var max = 1024*4

var NONCE_LEN = 24
var HEADER_LEN = 2+16+16

var concat = Buffer.concat

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
      boxed.copy(head, 2, 16, 32)

      this.queue(box(head, nonce1, key).slice(16, 18+16+16))
      this.queue(boxed.slice(32, 32 + input[i].length))

      increment(increment(nonce1)); increment(nonce2)
    }
  })

}

exports.createDecryptStream = function (key) {

var zeros = new Buffer(16); zeros.fill(0)
  var reader = Reader(), first = true, nonce

  return function (read) {
    reader(read)
    return function (abort, cb) {

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
          if(err) return cb(err)

          var header = unbox(concat([zeros, cipherheader]), nonce, key)
          var length = header.readUInt16BE(0)
          var mac = header.slice(2, 34)

          reader.read(length, function (err, packet) {
            if(err) return cb(err)
            //recreate a valid packet
            var _packet = concat([zeros, mac, packet])
            var data = unbox(_packet, increment(nonce), key)
            increment(nonce)
            cb(null, data)
          })
        })
      }
    }
  }
}
