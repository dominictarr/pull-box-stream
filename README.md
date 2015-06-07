# pull-box-stream

stream _one way_ encryption based on [libsodium](https://github.com/paixaop/node-sodium)'s secretbox primitive.

![Travis CI Status](https://travis-ci.org/dominictarr/pull-box-stream)

This protocol should not be used to encrypt a tcp connection
unless it was combined with a handshake protocol
that was used to derive a forward secure shared key.

It may be used to encrypt a file.

## Claims

### All bytes are authenticated & encrypted.


*  The reciever never reads an unauthenticated number of bytes.

This protects against attackers causing deadlocks on certain application protocols protected with box-stream.
(description of this attack on
[old version of hmac-stream](https://github.com/calvinmetcalf/hmac-stream/issues/5))

* The end of the stream is authenticated.

This detects if an attacker cut off the end of the stream.
for example:

Alice: hey bob, just calling to say that I think TLS is really great,
  really elegant protocol, and that I love everything about it.

Mallory (man in the middle): (SNIP! ...terminates connection...)

Alice: NOT!!!!! (Bob never receives this!)

Bob... WTF, I thought Alice had taste!

Bob never gets the punchline, so thinks that Alice's childish humor was
actually her sincere belief.

With box-stream this would result in an error and Bob would know
that there was some additional content he missed which hopefully
explained Alice's absurd statement.

## Disclaims

* This protocol does not obscure packet boundries or packet timing.
* This protocol is not a substitute for TLS, it must be used with another handshake protocol to derive a shared key.

## Protocol

This protocol has no malleable bytes.
Even the framing is authenticated, and since the framing is
authenticated separately to the packet content, an attacker cannot
flip any bits without being immediately detected.

The design follows on from that used in
[pull-mac](https://github.com/dominictarr/pull-mac),
where both the framing and the framed packet are authenticated.

In `pull-mac`, the packet is hashed, and then the header hmac'd.
Since the header contains the packet hash and the packet length,
then changing a bit in the packet will produce a different hash
and thus an invalid packet. Flipping a bit in the header will
invalidate the hmac.

In `pull-boxes` a similar approach is used, but via nacl's authenticated
encryption primitive: `secretbox`. salsa20 encryption + poly1305 mac.
The packet is boxed, then the header is constructed from the packet 
length + packet mac, then the header is boxed.

This protocol uses a 56 byte key (448 bits). The first 32 bytes
are the salsa20 key, and the last 24 bytes are the nonce. Previous
verisons of this protocol generated a nonce and transmitted it,
but it could be simplified by considering it part of the key.

Since every header and packet body are encrypted,
then every byte in the stream appears random.

The only information an evesdropper can extract is
packet timing and to guess at packet boundries
(although, sometimes packets will be appended, obscuring the true boundries)

## Example

``` js
var boxes = require('pull-box-stream')
//generate a random secret, 56 bytes long.

var key = createRandomSecret(56)

pull(
  plaintext_input,

  //encrypt every byte
  boxes.createBoxStream(key),

  //the encrypted stream
  pull.through(console.log),

  //decrypt every byte
  boxes.createUnboxStream(key),

  plaintext_output
)


```

## Protocol

```
(

  [header MAC (16)] // sends header MAC
     |
     |   .--header-box-----------------.
     \-> |length (2), [packet MAC (16)]| // sends encrypted header
         `--^------------|-------------`
            |            |
            |            |  .-packet-box-------.
            |            `->|data.. (length...)| // sends encrypted packet
            |               `-----------|------`
            \---------------------------/

) * // repeat 0-N times

[final header MAC(16)]
   |
   |  .-final-header-box-------.
   \->|length=0 (2), zeros (16)|
      `------------------------`
```

Since the packet mac is inside the header box, the packet
must be boxed first.

The last 24 bytes of the 56 byte key is used as the nonce.
When boxing, you must use a different nonce everytime a particular key is used.

The recommended way to do this is to randomly generate an initial
nonce for that key, and then increment that nonce on each boxing.
(this way security is not dependant on the random number generator)

The protocol sends zero or more {header, packet} pairs, then a final
header, that is same length, but is just boxed zeros.
 Each header is 34 bytes long (header mac + packet_length + packet mac).
Then the packet_length is length long (with a maximum length of 4096
bytes long, if the in coming packet is longer than that it is split
into 4096 byte long sections.)

Packet number P uses N+2P as the nonce on the header box,
and N+2P+1 as the nonce on the packet box.

A final packet is sent so that an incorrectly terminated session
can be detected.

## License

MIT
