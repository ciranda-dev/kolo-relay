// Package kolorelay lets two Kolo peers that cannot reach each other connect through a relay they chose.
//
// The peers run a kolo-secure connection end to end; its packets travel
// inside each peer's own connection to the relay, as frames on a stream, or
// as QUIC datagrams when the application opts in and the relay offers them,
// so the relay forwards ciphertext of a session it is not part of. Using a
// relay is always an explicit choice of the application.
//
// Experimental: the API may change before v1.0.0.
package kolorelay
