package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		body []byte
		want Message
	}{
		{EncodeReserve(Version0), Message{Type: TypeReserve}},
		{EncodeConnect(Version0, key(1)), Message{Type: TypeConnect, Key: key(1)}},
		{EncodeIncoming(Version0, key(2)), Message{Type: TypeIncoming, Key: key(2)}},
		{EncodeReserve(Version1), Message{Type: TypeReserve, Version: Version1}},
		{EncodeConnect(Version1, key(3)), Message{Type: TypeConnect, Version: Version1, Key: key(3)}},
		{EncodeIncoming(Version1, key(4)), Message{Type: TypeIncoming, Version: Version1, Key: key(4)}},
		{EncodeStatus(StatusOK), Message{Type: TypeStatus, Code: StatusOK}},
		{EncodeStatus(StatusUnsupportedVersion), Message{Type: TypeStatus, Code: StatusUnsupportedVersion}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, c.body); err != nil {
			t.Fatal(err)
		}
		body, err := ReadMessage(&buf)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(body)
		if err != nil {
			t.Fatalf("Decode(%x): %v", body, err)
		}
		if got.Type != c.want.Type || got.Version != c.want.Version || got.Code != c.want.Code || !bytes.Equal(got.Key, c.want.Key) {
			t.Fatalf("got %+v, want %+v", got, c.want)
		}
		if buf.Len() != 0 {
			t.Fatalf("%d bytes left", buf.Len())
		}
	}
}

func TestFormats(t *testing.T) {
	for _, v := range []uint64{Version0, Version1} {
		if got, want := EncodeReserve(v), []byte{1, byte(v)}; !bytes.Equal(got, want) {
			t.Fatalf("Reserve %x, want %x", got, want)
		}
		if got, want := EncodeConnect(v, key(7)), append([]byte{2, byte(v)}, key(7)...); !bytes.Equal(got, want) {
			t.Fatalf("Connect %x, want %x", got, want)
		}
		if got, want := EncodeIncoming(v, key(7)), append([]byte{3, byte(v)}, key(7)...); !bytes.Equal(got, want) {
			t.Fatalf("Incoming %x, want %x", got, want)
		}
	}
	if got, want := EncodeStatus(StatusLimit), []byte{4, 3}; !bytes.Equal(got, want) {
		t.Fatalf("Status %x, want %x", got, want)
	}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, EncodeReserve(Version0)); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.Bytes(), []byte{2, 1, 0}; !bytes.Equal(got, want) {
		t.Fatalf("frame %x, want %x", got, want)
	}
}

func TestDecodeErrors(t *testing.T) {
	long := append([]byte{2, 0}, key(1)...)
	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"empty", nil, ErrProtocol},
		{"unknown type", []byte{5, 0}, ErrProtocol},
		{"type zero", []byte{0, 0}, ErrProtocol},
		{"non-canonical type", []byte{0x81, 0x00, 0}, ErrProtocol},
		{"reserve no version", []byte{1}, ErrProtocol},
		{"reserve version 2", []byte{1, 2}, ErrUnsupportedVersion},
		{"reserve trailing", []byte{1, 0, 0}, ErrProtocol},
		{"reserve v1 trailing", []byte{1, 1, 0}, ErrProtocol},
		{"reserve non-canonical version", []byte{1, 0x81, 0x00}, ErrProtocol},
		{"connect short key", long[:len(long)-1], ErrProtocol},
		{"connect trailing", append(long, 0), ErrProtocol},
		{"connect version 2", append([]byte{2, 2}, key(1)...), ErrUnsupportedVersion},
		{"connect version 2 short key", []byte{2, 2}, ErrUnsupportedVersion},
		{"incoming large version", []byte{3, 0x80, 0x01}, ErrUnsupportedVersion},
		{"connect v1 short key", append([]byte{2, 1}, key(1)[1:]...), ErrProtocol},
		{"incoming no key", []byte{3, 0}, ErrProtocol},
		{"status no code", []byte{4}, ErrProtocol},
		{"status unknown code", []byte{4, 5}, ErrProtocol},
		{"status trailing", []byte{4, 0, 0}, ErrProtocol},
	}
	for _, c := range cases {
		if _, err := Decode(c.body); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestWriteMessageSize(t *testing.T) {
	if err := WriteMessage(io.Discard, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("empty: %v", err)
	}
	if err := WriteMessage(io.Discard, make([]byte, MaxMessageSize+1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("too long: %v", err)
	}
}

func TestReadMessageErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"nothing", nil, io.EOF},
		{"zero length", []byte{0}, ErrProtocol},
		{"over max", []byte{MaxMessageSize + 1}, ErrProtocol},
		{"two-byte length", []byte{0x80, 0x01}, ErrProtocol},
		{"truncated body", []byte{3, 1, 0}, ErrProtocol},
	}
	for _, c := range cases {
		if _, err := ReadMessage(bytes.NewReader(c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestReadMessageReadsOnlyItsFrame(t *testing.T) {
	r := bytes.NewReader([]byte{2, 1, 0, 9, 9})
	if _, err := ReadMessage(r); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 2 {
		t.Fatalf("%d bytes left, want 2", r.Len())
	}
}

func TestPacketRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	var w PacketWriter
	sizes := []int{1, 127, 128, 1280, MaxPacketSize}
	for _, n := range sizes {
		if err := w.Write(&buf, bytes.Repeat([]byte{byte(n)}, n)); err != nil {
			t.Fatal(err)
		}
	}
	r := NewPacketReader(&buf)
	p := make([]byte, MaxPacketSize)
	for _, n := range sizes {
		got, err := r.Read(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p[:got], bytes.Repeat([]byte{byte(n)}, n)) {
			t.Fatalf("packet of %d bytes: got %d bytes", n, got)
		}
	}
	if _, err := r.Read(p); err != io.EOF {
		t.Fatalf("after last packet: %v, want io.EOF", err)
	}
}

func TestPacketFormat(t *testing.T) {
	var buf bytes.Buffer
	var w PacketWriter
	if err := w.Write(&buf, bytes.Repeat([]byte{0xaa}, 200)); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes()[:2]; !bytes.Equal(got, []byte{0xc8, 0x01}) {
		t.Fatalf("header %x, want c801", got)
	}
	if buf.Len() != 202 {
		t.Fatalf("frame %d bytes, want 202", buf.Len())
	}
}

func TestPacketWriteSize(t *testing.T) {
	var w PacketWriter
	for _, n := range []int{0, MaxPacketSize + 1} {
		if err := w.Write(io.Discard, make([]byte, n)); !errors.Is(err, ErrPacketSize) {
			t.Errorf("%d bytes: %v, want ErrPacketSize", n, err)
		}
	}
}

func TestPacketTruncatedBuffer(t *testing.T) {
	var buf bytes.Buffer
	var w PacketWriter
	w.Write(&buf, []byte{1, 2, 3, 4})
	w.Write(&buf, []byte{5})
	r := NewPacketReader(&buf)
	p := make([]byte, 2)
	n, err := r.Read(p)
	if err != nil || n != 2 || !bytes.Equal(p, []byte{1, 2}) {
		t.Fatalf("got %d %x %v, want 2 0102", n, p[:n], err)
	}
	n, err = r.Read(p)
	if err != nil || n != 1 || p[0] != 5 {
		t.Fatalf("next frame: got %d %v", n, err)
	}
}

func TestPacketReadErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"zero length", []byte{0}},
		{"over max", []byte{0xad, 0x0b}},
		{"three-byte length", []byte{0x80, 0x80, 0x01}},
		{"non-canonical length", []byte{0x81, 0x00}},
		{"truncated length", []byte{0x80}},
		{"truncated body", []byte{3, 1, 2}},
	}
	for _, c := range cases {
		r := NewPacketReader(bytes.NewReader(c.in))
		if _, err := r.Read(make([]byte, MaxPacketSize)); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: got %v, want ErrProtocol", c.name, err)
		}
	}
}

func TestPacketReadLimitIsExact(t *testing.T) {
	var e []byte
	e = append(e, 0xac, 0x0b) // 1452
	e = append(e, make([]byte, MaxPacketSize)...)
	r := NewPacketReader(bytes.NewReader(e))
	if n, err := r.Read(make([]byte, MaxPacketSize)); err != nil || n != MaxPacketSize {
		t.Fatalf("1452 bytes: %d %v", n, err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadErrorsPassThrough(t *testing.T) {
	boom := errors.New("boom")
	if _, err := ReadMessage(errReader{boom}); !errors.Is(err, boom) {
		t.Fatalf("ReadMessage: %v", err)
	}
	if _, err := NewPacketReader(errReader{boom}).Read(make([]byte, 10)); !errors.Is(err, boom) {
		t.Fatalf("PacketReader: %v", err)
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	for _, id := range []uint64{0, 1, 127, 128, MaxQuarterStreamID} {
		for _, n := range []int{1, 1200, MaxPacketSize} {
			p := bytes.Repeat([]byte{byte(n)}, n)
			b, err := AppendDatagram([]byte("x"), id, p)
			if err != nil {
				t.Fatal(err)
			}
			gid, gp, err := DecodeDatagram(b[1:])
			if err != nil || gid != id || !bytes.Equal(gp, p) {
				t.Fatalf("id %d, %d bytes: got %d, %d bytes, %v", id, n, gid, len(gp), err)
			}
		}
	}
}

func TestDatagramFormat(t *testing.T) {
	b, err := AppendDatagram(nil, 200, []byte{0xaa, 0xbb})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xc8, 0x01, 0xaa, 0xbb}; !bytes.Equal(b, want) {
		t.Fatalf("datagram %x, want %x", b, want)
	}
}

func TestDatagramErrors(t *testing.T) {
	for _, n := range []int{0, MaxPacketSize + 1} {
		if _, err := AppendDatagram(nil, 1, make([]byte, n)); !errors.Is(err, ErrPacketSize) {
			t.Errorf("append %d bytes: %v, want ErrPacketSize", n, err)
		}
	}
	if _, err := AppendDatagram(nil, MaxQuarterStreamID+1, []byte{1}); !errors.Is(err, ErrProtocol) {
		t.Errorf("append ID 2^60: %v, want ErrProtocol", err)
	}
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"ID only", []byte{5}},
		{"truncated ID", []byte{0x80}},
		{"non-canonical ID", []byte{0x81, 0x00, 1}},
		{"ID 2^60", append([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10}, 1)},
		{"packet too long", append([]byte{1}, make([]byte, MaxPacketSize+1)...)},
	}
	for _, c := range cases {
		if _, _, err := DecodeDatagram(c.in); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: got %v, want ErrProtocol", c.name, err)
		}
	}
}

func TestDecodeDatagramDoesNotAllocate(t *testing.T) {
	b, _ := AppendDatagram(nil, 300, make([]byte, MaxPacketSize))
	long := append([]byte{1}, make([]byte, 4096)...)
	if n := testing.AllocsPerRun(100, func() {
		DecodeDatagram(b)
		DecodeDatagram(long)
	}); n != 0 {
		t.Fatalf("%v allocations per decode", n)
	}
}

func TestAppendFrameAndFrameSize(t *testing.T) {
	for _, n := range []int{1, 127, 128, MaxPacketSize} {
		b, err := AppendFrame([]byte("x"), make([]byte, n))
		if err != nil || len(b)-1 != FrameSize(n) {
			t.Fatalf("%d bytes: frame of %d, FrameSize %d, %v", n, len(b)-1, FrameSize(n), err)
		}
		got, err := NewPacketReader(bytes.NewReader(b[1:])).Read(make([]byte, MaxPacketSize))
		if err != nil || got != n {
			t.Fatalf("%d bytes: read %d %v", n, got, err)
		}
	}
	if _, err := AppendFrame(nil, nil); !errors.Is(err, ErrPacketSize) {
		t.Fatalf("empty: %v", err)
	}
}
