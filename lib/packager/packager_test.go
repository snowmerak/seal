package packager_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/snowmerak/seal/lib/packager"
)

func TestPackager(t *testing.T) {
	buffer := bytes.NewBuffer(nil)

	pkg, err := packager.NewPackager(buffer)
	if err != nil {
		t.Fatal(err)
	}

	if err := pkg.Pack("test", bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}

	if err := pkg.Pack("test2", bytes.NewReader([]byte("world"))); err != nil {
		t.Fatal(err)
	}

	if err := pkg.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("buffer: %s", buffer.String())

	upkg, err := packager.NewUnpackager(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	for {
		name, data, err := upkg.Unpack()
		if err != nil {
			isEnded := upkg.IsEnd()
			if isEnded {
				t.Logf(fmt.Sprint(upkg.IsEnd()))
				break
			}
			t.Logf("error: %v", err)
			break
		}

		t.Logf("name: %s, data: %s", name, data)
	}
}
