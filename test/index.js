
var tape = require('tape')
var pull = require('pull-stream')
var randomBytes = require('crypto').randomBytes
var increment = require('increment-buffer')
var split = require('pull-randomly-split')
var boxes = require('../')

var sodium = require('sodium').api

var box = sodium.crypto_secretbox
var unbox = sodium.crypto_secretbox_open

var concat = Buffer.concat

var zeros = new Buffer(16); zeros.fill(0)

// testing is easier when 

function testKey (str) {
  return sodium.crypto_hash(new Buffer(str)).slice(0, 32)
}

tape('encrypt a stream', function (t) {

  var key = testKey('encrypt a stream - test 1')

  pull(
    pull.values([new Buffer('hello there')]),
    boxes.createEncryptStream(key),
    pull.collect(function (err, ary) {
      if(err) throw err
      //cipher text

      //decrypt the head.
      var nonce = ary[0]
      var head = ary[1]
      var chunk = ary[2]

      var plainhead = unbox(concat([zeros, head]), nonce, key)
      var length = plainhead.readUInt16BE(0)

      t.equal(length, 11)
      t.equal(length, chunk.length)

      var mac = plainhead.slice(2, 18)
      var nonce2 = new Buffer(24)
      nonce.copy(nonce2, 0, 0, 24)

      var plainchunk =
        unbox(concat([zeros, mac, chunk]), increment(nonce2), key)

      t.deepEqual(plainchunk, new Buffer('hello there'))

      //now decrypt the same
      pull(
        pull.values(ary),
        boxes.createDecryptStream(key),
        pull.collect(function (err, data) {
          if(err) throw err
          t.deepEqual(data, [new Buffer('hello there')])
          t.end()
        })
      )
    })
  )
})


tape('encrypt/decrypt', function (t) {

  var input = randomBytes(1024*1024*100)
  var start = Date.now()
  console.log('e/d')
  var key = testKey('encrypt/decrypt a stream')

  pull(
    pull.values([input]),
//    split(),
    boxes.createEncryptStream(key),
//    split(),
    boxes.createDecryptStream(key),

    pull.collect(function (err, output) {
      var time = Date.now() - start
      console.log(100/(time/1000), 'mb/s')

      if(err) throw err

      output = concat(output)
      t.equal(output.length, input.length)
      t.deepEqual(output, input)
      t.end()
    })
  )
})

tape('error if input is not a buffer', function (t) {

  var key = testKey('error if not a buffer')

  pull(
    pull.values([0, 1, 2]),
    boxes.createEncryptStream(key),
    pull.collect(function (err) {
      t.ok(err)
      t.end()
    })
  )

})
