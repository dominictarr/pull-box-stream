'use strict'
var sodium = require('chloride')
var Reader = require('pull-reader')
var increment = require('increment-buffer')
var through = require('pull-through')
var split = require('split-buffer')

var isBuffer = Buffer.isBuffer
var concat = Buffer.concat

var box = sodium.crypto_secretbox_easy
var unbox = sodium.crypto_secretbox_open_easy  

function unbox_detached (mac, boxed, nonce, key) {
  return sodium.crypto_secretbox_open_easy(concat([mac, boxed]), nonce, key)
}

var max = 1024*4

var NONCE_LEN = 24
var HEADER_LEN = 2+16+16

function isZeros(b) {
  for(var i = 0; i < b.length; i++)
    if(b[i] !== 0) return false
  return true
}

function randomSecret(n) {
  var rand = new Buffer(n)
  sodium.randombytes(rand)
  return rand
}

function copy (a) {
  var b = new Buffer(a.length)
  a.copy(b, 0, 0, a.length)
  return b
}

exports.createBoxStream =
exports.createEncryptStream = function (key, init_nonce) {

  if(key.length === 56) {
    init_nonce = key.slice(32, 56)
    key = key.slice(0, 32)
  }
  else if(!(key.length === 32 && init_nonce.length === 24))
    throw new Error('nonce must be 24 bytes')

  // we need two nonces because increment mutates,
  // and we need the next for the header,
  // and the next next nonce for the packet
  var nonce1 = copy(init_nonce), nonce2 = copy(init_nonce)
  var head = new Buffer(18)

  return through(function (data) {

    if('string' === typeof data)
      data = new Buffer(data, 'utf8')
    else if(!isBuffer(data))
      return this.emit('error', new Error('must be buffer'))

    if(data.length === 0) return

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
    //final header is same length as header except all zeros (inside box)
    var final = new Buffer(2+16); final.fill(0)
    this.queue(box(final, nonce1, key))
    this.queue(null)
  })

}
exports.createUnboxStream =
exports.createDecryptStream = function (key, nonce) {


  if(key.length == 56) {
    nonce = key.slice(32, 56)
    key = key.slice(0, 32)
  }
  else if(!(key.length === 32 && nonce.length === 24))
    throw new Error('nonce must be 24 bytes')
  nonce = copy(nonce)

  var reader = Reader(), first = true,  ended
  var first = true

  return function (read) {
    reader(read)
    return function (end, cb) {
      if(end) return reader.abort(end, cb)
      //use abort when the input was invalid,
      //but the source hasn't actually ended yet.
      function abort(err) {
        reader.abort(ended = err || true, cb)
      }

      if(ended) return cb(ended)
      reader.read(HEADER_LEN, function (err, cipherheader) {
        if(err === true) return cb(ended = new Error('unexpected hangup'))
        if(err) return cb(ended = err)

        var header = unbox(cipherheader, nonce, key)

        if(!header)
          return abort(new Error('invalid header'))

        //valid end of stream
        if(isZeros(header))
          return cb(ended = true)

        var length = header.readUInt16BE(0)
        var mac = header.slice(2, 34)

        reader.read(length, function (err, cipherpacket) {
          if(err) return cb(ended = err)
          //recreate a valid packet
          //TODO: PR to sodium bindings for detached box/open
          var plainpacket = unbox_detached(mac, cipherpacket, increment(nonce), key)
          if(!plainpacket)
            return abort(new Error('invalid packet'))

          increment(nonce)
          cb(null, plainpacket)
        })
      })
    }
  }
}
