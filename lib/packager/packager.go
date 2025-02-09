package packager

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type Packager struct {
	writer io.Writer
}

func NewPackager(w io.Writer) (*Packager, error) {
	pkg := &Packager{writer: w}

	if err := pkg.writeStart(); err != nil {
		return nil, fmt.Errorf("failed to write start bytes: %w", err)
	}

	return pkg, nil
}

func (p *Packager) Pack(name string, data io.Reader) error {
	return p.writeData(name, data)
}

func (p *Packager) Close() error {
	return p.writeEnd()
}

func (p *Packager) writeStart() error {
	// PACK
	_, err := p.writer.Write([]byte("PACK"))
	return err
}

func (p *Packager) writeEnd() error {
	// ACKE
	_, err := p.writer.Write([]byte("ACKE"))
	return err
}

func (p *Packager) writeData(name string, data io.Reader) error {
	buf := [8]byte{}

	// NAME
	_, err := p.writer.Write([]byte("NAME"))
	if err != nil {
		return fmt.Errorf("failed to write NAME: %w", err)
	}

	// name length
	binary.BigEndian.PutUint64(buf[:], uint64(len(name)))
	_, err = p.writer.Write(buf[:])
	if err != nil {
		return fmt.Errorf("failed to write name length: %w", err)
	}

	// name
	_, err = p.writer.Write([]byte(name))
	if err != nil {
		return fmt.Errorf("failed to write name value: %w", err)
	}

	// DATA
	_, err = p.writer.Write([]byte("DATA"))
	if err != nil {
		return fmt.Errorf("failed to write DATA: %w", err)
	}

	// data
	_, err = io.Copy(p.writer, data)
	if err != nil {
		return fmt.Errorf("failed to write data value: %w", err)
	}

	if _, err := p.writer.Write([]byte("HOLE")); err != nil {
		return fmt.Errorf("failed to write end bytes: %w", err)
	}

	return nil
}

type Unpackager struct {
	reader io.ReadSeeker
}

func NewUnpackager(r io.ReadSeeker) (*Unpackager, error) {
	upkg := &Unpackager{reader: r}

	if err := upkg.readStart(); err != nil {
		return nil, fmt.Errorf("failed to read start bytes: %w", err)
	}

	return upkg, nil
}

func (u *Unpackager) Unpack() (string, io.Reader, error) {
	return u.readData()
}

func (u *Unpackager) IsEnd() bool {
	buf := make([]byte, 4)
	if _, err := u.reader.Read(buf); err != nil {
		return false
	}
	defer u.reader.Seek(-4, io.SeekCurrent)

	if string(buf) == "ACKE" {
		return true
	}

	return false
}

func (u *Unpackager) readStart() error {
	buf := make([]byte, 4)
	if _, err := u.reader.Read(buf); err != nil {
		return fmt.Errorf("failed to read start bytes: %w", err)
	}

	if string(buf) != "PACK" {
		return fmt.Errorf("invalid start bytes: %s", buf)
	}

	return nil
}

func (u *Unpackager) readData() (string, io.ReadSeeker, error) {
	buf := make([]byte, 4)
	if _, err := u.reader.Read(buf); err != nil {
		return "", nil, fmt.Errorf("failed to read data type: %w", err)
	}

	if string(buf) != "NAME" {
		u.reader.Seek(-4, io.SeekCurrent)
		return "", nil, fmt.Errorf("unexpected data type, expected NAME: %s", buf)
	}

	name, err := u.readName()
	if err != nil {
		return "", nil, err
	}

	buf = make([]byte, 4)
	if _, err := u.reader.Read(buf); err != nil {
		return "", nil, fmt.Errorf("failed to read data type: %w", err)
	}

	if string(buf) != "DATA" {
		return "", nil, fmt.Errorf("unexpected data type, expected DATA: %s", buf)
	}

	responseBuffer := bytes.NewBuffer(nil)
	writtenBuffer := 0
	readBuffer := [4096]byte{}
	doubleEOF := false
loop:
	for {
		n, err := u.reader.Read(readBuffer[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				if !doubleEOF {
					doubleEOF = true
					continue loop
				}
			}
			return "", nil, fmt.Errorf("failed to read data: %w", err)
		}

		for i := 0; i < n; i++ {
			if bytes.Equal(readBuffer[i:i+4], []byte("HOLE")) {
				if _, err := responseBuffer.Write(readBuffer[:i]); err != nil {
					return "", nil, fmt.Errorf("failed to write data: %w", err)
				}
				writtenBuffer += i

				if _, err := u.reader.Seek(-int64(n-i-4), io.SeekCurrent); err != nil {
					return "", nil, fmt.Errorf("failed to seek to end bytes: %w", err)
				}

				return name, bytes.NewReader(responseBuffer.Bytes()), nil
			}
		}

		writtenBuffer += n
		if _, err := responseBuffer.Write(readBuffer[:n]); err != nil {
			return "", nil, fmt.Errorf("failed to write data: %w", err)
		}
	}
}

func (u *Unpackager) readName() (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(u.reader, buf); err != nil {
		return "", fmt.Errorf("failed to read name length: %w", err)
	}

	name := make([]byte, binary.BigEndian.Uint64(buf[:]))
	if _, err := io.ReadFull(u.reader, name); err != nil {
		return "", fmt.Errorf("failed to read name value: %w", err)
	}

	return string(name), nil
}
