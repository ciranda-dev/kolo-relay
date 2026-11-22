// Package wire encodes the kolo-relay control messages and the packet frames of a session.
package wire

import (
	"errors"
	"io"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// Protocol versions: version 0 carries packets as frames on the session stream, version 1 also as datagrams.
const (
	Version0 = 0
	Version1 = 1
)

// KeySize is the size of a kolo-id public key.
const KeySize = 32

// MaxMessageSize is the largest control message body.
const MaxMessageSize = 64

// MaxPacketSize is the largest packet in a frame or a datagram: quic-go's MaxPacketBufferSize.
const MaxPacketSize = 1452

// MaxQuarterStreamID is the largest quarter stream ID, since QUIC stream IDs are below 2^62 (RFC 9297 section 2.1).
const MaxQuarterStreamID = 1<<60 - 1

// Message types.
const (
	TypeReserve  = 1
	TypeConnect  = 2
	TypeIncoming = 3
	TypeStatus   = 4
)

// Status codes.
const (
	StatusOK                 = 0
	StatusUnavailable        = 1
	StatusNotAllowed         = 2
	StatusLimit              = 3
	StatusUnsupportedVersion = 4
)

var (
	// ErrProtocol means a message or frame was malformed, truncated, too large or unexpected.
	ErrProtocol = errors.New("kolorelay: invalid message")
	// ErrUnsupportedVersion means the peer speaks another protocol version.
	ErrUnsupportedVersion = errors.New("kolorelay: unsupported protocol version")
	// ErrPacketSize means a packet to send is empty or larger than MaxPacketSize.
	ErrPacketSize = errors.New("kolorelay: packet size out of range")
)

// Message is a decoded control message.
type Message struct {
	Type    uint64
	Version uint64
	Key     []byte
	Code    uint64
}

// EncodeReserve returns the body of a Reserve message in version.
func EncodeReserve(version uint64) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(TypeReserve)
	e.PutUvarint(version)
	return e.Bytes()
}

// EncodeConnect returns the body of a Connect message in version for the target key.
func EncodeConnect(version uint64, target []byte) []byte {
	return encodeKeyed(TypeConnect, version, target)
}

// EncodeIncoming returns the body of an Incoming message in version for the initiator key.
func EncodeIncoming(version uint64, initiator []byte) []byte {
	return encodeKeyed(TypeIncoming, version, initiator)
}

func encodeKeyed(typ, version uint64, key []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(typ)
	e.PutUvarint(version)
	e.PutFixed(key)
	return e.Bytes()
}

// EncodeStatus returns the body of a Status message.
func EncodeStatus(code uint64) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(TypeStatus)
	e.PutUvarint(code)
	return e.Bytes()
}

// Decode parses a control message body; anything but an exact message of a known type is ErrProtocol.
func Decode(body []byte) (Message, error) {
	d := kolocodec.NewDecoder(body)
	typ, err := d.Uvarint()
	if err != nil {
		return Message{}, ErrProtocol
	}
	m := Message{Type: typ}
	switch typ {
	case TypeReserve, TypeConnect, TypeIncoming:
		v, err := d.Uvarint()
		if err != nil {
			return Message{}, ErrProtocol
		}
		// Checked before the rest, so a later version may change the layout.
		if v != Version0 && v != Version1 {
			return Message{}, ErrUnsupportedVersion
		}
		m.Version = v
		if typ != TypeReserve {
			if m.Key, err = d.Fixed(KeySize); err != nil {
				return Message{}, ErrProtocol
			}
		}
		if d.Done() != nil {
			return Message{}, ErrProtocol
		}
	case TypeStatus:
		if m.Code, err = d.UvarintMax(StatusUnsupportedVersion); err != nil || d.Done() != nil {
			return Message{}, ErrProtocol
		}
	default:
		return Message{}, ErrProtocol
	}
	return m, nil
}

// WriteMessage writes body as one frame: a one-byte length, then body.
func WriteMessage(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > MaxMessageSize {
		return ErrProtocol
	}
	_, err := w.Write(append([]byte{byte(len(body))}, body...))
	return err
}

// ReadMessage reads one control frame of at most MaxMessageSize bytes; io.EOF means no frame started.
func ReadMessage(r io.Reader) ([]byte, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	if n[0] == 0 || n[0] > MaxMessageSize {
		return nil, ErrProtocol
	}
	body := make([]byte, n[0])
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, truncated(err)
	}
	return body, nil
}

func truncated(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrProtocol
	}
	return err
}

// PacketWriter writes packet frames, reusing one buffer; it is not safe for concurrent use.
type PacketWriter struct {
	buf []byte
}

// Write writes p as one frame: uvarint(len(p)), then p, in a single Write call.
func (pw *PacketWriter) Write(w io.Writer, p []byte) error {
	var err error
	if pw.buf, err = AppendFrame(pw.buf[:0], p); err != nil {
		return err
	}
	_, err = w.Write(pw.buf)
	return err
}

// AppendFrame appends p as one frame, uvarint(len(p)) then p, to dst.
func AppendFrame(dst, p []byte) ([]byte, error) {
	if len(p) == 0 || len(p) > MaxPacketSize {
		return dst, ErrPacketSize
	}
	var e kolocodec.Encoder
	e.PutUvarint(uint64(len(p)))
	return append(append(dst, e.Bytes()...), p...), nil
}

// FrameSize returns the size of the frame of an n-byte packet, length prefix included.
func FrameSize(n int) int {
	if n < 0x80 {
		return n + 1
	}
	return n + 2
}

// PacketReader reads packet frames; it is not safe for concurrent use.
type PacketReader struct {
	r       io.Reader
	scratch [MaxPacketSize]byte
}

// NewPacketReader returns a PacketReader that reads frames from r.
func NewPacketReader(r io.Reader) *PacketReader { return &PacketReader{r: r} }

// Read reads the next frame into p, truncating it if p is shorter, like a UDP read; io.EOF means no frame started.
func (pr *PacketReader) Read(p []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(pr.r, hdr[:1]); err != nil {
		return 0, err
	}
	n := 1
	if hdr[0] >= 0x80 {
		if _, err := io.ReadFull(pr.r, hdr[1:]); err != nil {
			return 0, truncated(err)
		}
		n = 2
	}
	d := kolocodec.NewDecoder(hdr[:n])
	size, err := d.UvarintMax(MaxPacketSize)
	if err != nil || d.Done() != nil || size == 0 {
		return 0, ErrProtocol
	}
	body := pr.scratch[:size]
	if _, err := io.ReadFull(pr.r, body); err != nil {
		return 0, truncated(err)
	}
	return copy(p, body), nil
}

// AppendDatagram appends the datagram payload uvarint(id) || p to dst, id being the quarter stream ID of the session's stream.
func AppendDatagram(dst []byte, id uint64, p []byte) ([]byte, error) {
	if len(p) == 0 || len(p) > MaxPacketSize {
		return dst, ErrPacketSize
	}
	if id > MaxQuarterStreamID {
		return dst, ErrProtocol
	}
	var e kolocodec.Encoder
	e.PutUvarint(id)
	return append(append(dst, e.Bytes()...), p...), nil
}

// DecodeDatagram splits a datagram payload into its quarter stream ID and its packet, which shares b's memory.
func DecodeDatagram(b []byte) (id uint64, p []byte, err error) {
	d := kolocodec.NewDecoder(b)
	id, err = d.UvarintMax(MaxQuarterStreamID)
	if err != nil || d.Len() == 0 || d.Len() > MaxPacketSize {
		return 0, nil, ErrProtocol
	}
	return id, b[len(b)-d.Len():], nil
}
