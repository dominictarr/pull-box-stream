
var tape = require('tape')
var pull = require('pull-stream')
var randomBytes = require('crypto').randomBytes
var increment = require('increment-buffer')
var split = require('pull-randomly-split')
var boxes = require('../')
var bitflipper = require('pull-bitflipper')

var sodium = require('chloride')

var box = sodium.crypto_secretbox_easy
var unbox = sodium.crypto_secretbox_open_easy

var concat = Buffer.concat

//var zeros = new Buffer(16); zeros.fill(0)

// testing is easier when 

function testKey (str) {
  return sodium.crypto_hash(new Buffer(str)).slice(0, 56)
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
      var head = ary[0]
      var chunk = ary[1]

      var _key = key.slice(0, 32)
      var _nonce = key.slice(32, 56)

      console.log(ary)
      console.log(ary.map(function (e) { return e.length }))

      var plainhead = unbox(head, _nonce, _key)
      var length = plainhead.readUInt16BE(0)

      t.equal(length, 11)
      t.equal(length, chunk.length)

      var mac = plainhead.slice(2, 18)
      var nonce2 = new Buffer(24)
      _nonce.copy(nonce2, 0, 0, 24)

      var plainchunk =
        unbox(concat([mac, chunk]), increment(nonce2), _key)

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

function randomBuffers(len, n) {
  var a = []
  while(n--)
    a.push(randomBytes(len))
  return a
}

tape('encrypt/decrypt simple', function (t) {

  var start = Date.now()
  console.log('e/d')
  var key = testKey('encrypt/decrypt a stream, easy')

  var input = [new Buffer('can you read this?'), new Buffer(4100)]
  pull(
    pull.values(input),
    boxes.createEncryptStream(new Buffer(key)),
    boxes.createDecryptStream(new Buffer(key)),
    pull.through(console.log),
    pull.collect(function (err, output) {
      var time = Date.now() - start
      console.log(100/(time/1000), 'mb/s')

      if(err) throw err

      output = concat(output)
      input = concat(input)
      t.equal(output.length, input.length)
      t.deepEqual(output, input)
      t.end()
    })
  )
})
return

tape('encrypt/decrypt', function (t) {

  var input = randomBuffers(1024*512, 2*10)
  var start = Date.now()
  console.log('e/d')
  var key = testKey('encrypt/decrypt a stream')

  pull(
    pull.values(input),
    split(),
    boxes.createEncryptStream(new Buffer(key)),
    split(),
    boxes.createDecryptStream(new Buffer(key)),
    pull.through(console.log),
    pull.collect(function (err, output) {
      var time = Date.now() - start
      console.log(100/(time/1000), 'mb/s')

      if(err) throw err

      output = concat(output)
      input = concat(input)
      t.equal(output.length, input.length)
      t.deepEqual(output, input)
      t.end()
    })
  )
})

tape('error if input is not a buffer', function (t) {

  var key = testKey('error if not a buffer')

  pull(
    pull.values([0, 1, 2], function (err) { t.end() }),
    boxes.createEncryptStream(key),
    pull.collect(function (err) {
      console.log('error', err)
      t.ok(err)
    })
  )

})

tape('detect flipped bits', function (t) {

  var input = randomBuffers(1024, 100)
  var key = testKey('bit flipper')

  pull(
    pull.values(input, function () { t.end() }),
    boxes.createEncryptStream(key),
    bitflipper(0.1),
    boxes.createDecryptStream(key),
    pull.collect(function (err, output) {
      t.ok(err)
      t.notEqual(output.length, input.length)
    })
  )

})

function rand (i) {
  return ~~(Math.random()*i)
}

tape('protect against reordering', function (t) {

  var input = randomBuffers(1024, 100)
  var key = testKey('reordering')

  pull(
    pull.values(input),
    boxes.createEncryptStream(key),
    pull.collect(function (err, valid) {
      //randomly switch two blocks
      var invalid = valid.slice()
      //since every even packet is a header,
      //moving those will produce valid messages
      //but the counters will be wrong.
      var i = rand(valid.length/2)*2
      var j = rand(valid.length/2)*2
      invalid[i] = valid[j]
      invalid[i+1] = valid[j+1]
      invalid[j] = valid[i]
      invalid[j+1] = valid[i+1]
      pull(
        pull.values(invalid, function () { t.end() }),
        boxes.createDecryptStream(key),
        pull.collect(function (err, output) {
          t.notEqual(output.length, input.length)
          t.ok(err)
        })
      )
    })
  )
})

tape('detect unexpected hangup', function (t) {

    var input = [
    new Buffer('I <3 TLS\n'),
    new Buffer('...\n'),
    new Buffer("NOT!!!")
  ]

  var key = testKey('detect unexpected hangup')

  pull(
    pull.values(input),
    boxes.createBoxStream(key),
    pull.take(4), //header packet header packet.
    boxes.createUnboxStream(key),
    pull.collect(function (err, data) {
      console.log(err)
      t.ok(err) //expects an error
      t.equal(data.join(''), 'I <3 TLS\n...\n')
      t.end()
    })
  )

})


tape('detect unexpected hangup, interrupt just the last packet', function (t) {

    var input = [
    new Buffer('I <3 TLS\n'),
    new Buffer('...\n'),
    new Buffer("NOT!!!")
  ]

  var key = testKey('drop hangup packet')

  pull(
    pull.values(input),
    boxes.createBoxStream(key),
    pull.take(6), //header packet header packet.
    boxes.createUnboxStream(key),
    pull.collect(function (err, data) {
      console.log(err)
      t.ok(err) //expects an error
      t.equal(data.join(''), 'I <3 TLS\n...\nNOT!!!')
      t.end()
    })
  )

})


tape('immediately hangup', function (t) {

  var key = testKey('empty session')

  pull(
    pull.values([]),
    boxes.createBoxStream(key),
    boxes.createUnboxStream(key),
    pull.collect(function (err, data) {
      t.notOk(err)
      t.deepEqual(data, [])
      t.end()
    })
  )

})

function stall () {
  var _cb
  return function (abort, cb) {
    console.log('Abort?', abort)
    if(abort) {
      console.log(abort, _cb, cb)
      _cb && _cb(abort)
      cb && cb(abort)
    }
    else _cb = cb
  }

}

tape('stalled abort', function (t) {

  var key = testKey('stalled abort')
  var err = new Error('intentional')
  var read = pull(stall(), boxes.createBoxStream(key))

  var i = 0
  read(null, function (_err, data) {
    t.equal(_err, err)
    t.equal(++i, 1)
  })

  read(err, function () {
    t.ok(true)
    t.equal(++i, 2)
    t.end()
  })

})

tape('stalled abort', function (t) {

  var key = testKey('stalled abort2')
  var read = pull(stall(), boxes.createUnboxStream(key))
  var err = new Error('intentional')

  var i = 0
  read(null, function (_err, data) {
    t.equal(_err, err)
    t.equal(++i, 1)
    console.log('ended', err, data)
  })

  read(err, function () {
    t.ok(true)
    t.equal(++i, 2)
    t.end()
  })

})

tape('encrypt empty buffers', function (t) {

  var key = testKey('empty')
  pull(
    pull.values([new Buffer(0)]),
    boxes.createBoxStream(key),
    boxes.createUnboxStream(key),
    pull.collect(function (err, buffers) {
      var actual = Buffer.concat(buffers)
      t.deepEqual(actual, new Buffer(0))
      t.end()
    })
  )

})




