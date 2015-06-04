# pull-box-stream

Streaming encryption based on [libsodium](https://github.com/paixaop/node-sodium)'s box primitive.

This protocol is unusually robust, there are no malleable bytes.
Even the framing is authenticated, and an attacker cannot
flip any bytes without being immediately detected.

The design follows on from that used in
[pull-mac](https://github.com/dominictarr/pull-mac),
where both the framing and the framed packet are authenticated.

In pull-mac, the packet is hashed, and then that hash, with the
packet sequence number and mac are hmaced.

In `pull-boxes`, first the packet is boxed, then the header
is constructed from the length + packet mac, then the header is boxed.

Since the stream is a random nonce then every
 header and packet body are encrypted, then every byte in the stream
appears random. The only information an evesdropper can extract is
packet timing and to guess at packet boundries
(although, sometimes packets will be appended)

```
[nonce (24)] // send random nonce

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
   \->|length=0 (2), zeros (18)|
      `------------------------`
```

Since the packet mac is inside the header box, the packet
must be boxed first. When boxing, it's okay to reuse the same
key, but never the same {key, nonce} pair. The recommended
way to generate a fresh nonce is to randomly generate an initial
nonce for that key, and then increment it on each boxing.
(this way security is not dependant on the random number generator)

The protocol begins by writing a 24 byte random nonce (N) to the stream,
then zero or more {header, packet} pairs. Each header is 34 bytes
long (header mac + length + packet mac). Then the packet is length long
(with a maximum length of 4096 bytes long)

Packet number P uses N+2P as the nonce on the header box,
and N+2P+1 as the nonce on the packet box.

A final packet is sent so that an incorrectly terminated session
can be detected.

## License

MIT
