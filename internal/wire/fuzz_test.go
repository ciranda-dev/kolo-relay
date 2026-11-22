package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func FuzzDecode(f *testing.F) {
	f.Add(EncodeReserve(Version0))
	f.Add(EncodeConnect(Version0, key(1)))
	f.Add(EncodeIncoming(Version0, key(2)))
	f.Add(EncodeReserve(Version1))
	f.Add(EncodeConnect(Version1, key(1)))
	f.Add(EncodeIncoming(Version1, key(2)))
	f.Add(EncodeStatus(StatusLimit))
	f.Add([]byte{1, 1})
	f.Fuzz(func(t *testing.T, body []byte) {
		m, err := Decode(body)
		if err != nil {
			if !errors.Is(err, ErrProtocol) && !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if m.Version != Version0 && m.Version != Version1 {
			t.Fatalf("decoded version %d", m.Version)
		}
		var again []byte
		switch m.Type {
		case TypeReserve:
			again = EncodeReserve(m.Version)
		case TypeConnect:
			again = EncodeConnect(m.Version, m.Key)
		case TypeIncoming:
			again = EncodeIncoming(m.Version, m.Key)
		case TypeStatus:
			again = EncodeStatus(m.Code)
		}
		if !bytes.Equal(again, body) {
			t.Fatalf("decoded %x, re-encoded %x", body, again)
		}
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{2, 1, 0})
	f.Add([]byte{0})
	f.Add([]byte{65})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		body, err := ReadMessage(r)
		if err != nil {
			if err != io.EOF && !errors.Is(err, ErrProtocol) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if len(body) == 0 || len(body) > MaxMessageSize || int(in[0]) != len(body) {
			t.Fatalf("body of %d bytes from %x", len(body), in)
		}
		if read := len(in) - r.Len(); read != len(body)+1 {
			t.Fatalf("read %d bytes for a %d-byte body", read, len(body))
		}
	})
}

func FuzzReadPacket(f *testing.F) {
	var buf bytes.Buffer
	var w PacketWriter
	w.Write(&buf, []byte("hello"))
	w.Write(&buf, make([]byte, MaxPacketSize))
	f.Add(buf.Bytes(), 1500)
	f.Add([]byte{0xad, 0x0b}, 10)
	f.Fuzz(func(t *testing.T, in []byte, size int) {
		if size < 0 || size > 4096 {
			return
		}
		r := NewPacketReader(bytes.NewReader(in))
		p := make([]byte, size)
		for {
			n, err := r.Read(p)
			if err != nil {
				if err != io.EOF && !errors.Is(err, ErrProtocol) {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if n > size || n > MaxPacketSize {
				t.Fatalf("read %d bytes into %d", n, size)
			}
		}
	})
}

func FuzzDecodeDatagram(f *testing.F) {
	d, _ := AppendDatagram(nil, 1, []byte("hello"))
	f.Add(d)
	d, _ = AppendDatagram(nil, MaxQuarterStreamID, make([]byte, MaxPacketSize))
	f.Add(d)
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, in []byte) {
		id, p, err := DecodeDatagram(in)
		if err != nil {
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if len(p) == 0 || len(p) > MaxPacketSize || id > MaxQuarterStreamID {
			t.Fatalf("ID %d with %d bytes from %x", id, len(p), in)
		}
		again, err := AppendDatagram(nil, id, p)
		if err != nil || !bytes.Equal(again, in) {
			t.Fatalf("decoded %x, re-encoded %x (%v)", in, again, err)
		}
	})
}
