package main

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"github.com/jftuga/mtool/v2/internal/imgconv"
	"os"
	"path/filepath"
	"testing"
)

func TestInferImageFormat(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"photo.png", "png"},
		{"photo.PNG", "png"},
		{"photo.jpg", "jpg"},
		{"photo.jpeg", "jpg"},
		{"photo.JPEG", "jpg"},
		{"photo.gif", "gif"},
		{"photo.bmp", ""},
		{"photo.tiff", ""},
		{"noext", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := imgconv.InferImageFormat(tt.path)
			if got != tt.want {
				t.Errorf("InferImageFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func newTestImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	colors := []color.RGBA{
		{255, 0, 0, 255},
		{0, 255, 0, 255},
		{0, 0, 255, 255},
		{255, 255, 0, 255},
	}
	for y := range 4 {
		for x := range 4 {
			img.SetRGBA(x, y, colors[(x+y)%len(colors)])
		}
	}
	return img
}

func TestEncodeImage_PNG(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer
	if err := imgconv.EncodeImage(&buf, img, "png", 0); err != nil {
		t.Fatalf("EncodeImage png: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("png output is empty")
	}
	decoded, err := png.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding png: %v", err)
	}
	if decoded.Bounds() != img.Bounds() {
		t.Errorf("bounds = %v, want %v", decoded.Bounds(), img.Bounds())
	}
}

func TestEncodeImage_JPEG(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer
	if err := imgconv.EncodeImage(&buf, img, "jpg", 75); err != nil {
		t.Fatalf("EncodeImage jpg: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("jpeg output is empty")
	}
	decoded, err := jpeg.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding jpeg: %v", err)
	}
	if decoded.Bounds() != img.Bounds() {
		t.Errorf("bounds = %v, want %v", decoded.Bounds(), img.Bounds())
	}
}

func TestEncodeImage_GIF(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer
	if err := imgconv.EncodeImage(&buf, img, "gif", 0); err != nil {
		t.Fatalf("EncodeImage gif: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("gif output is empty")
	}
	decoded, err := gif.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding gif: %v", err)
	}
	if decoded.Bounds() != img.Bounds() {
		t.Errorf("bounds = %v, want %v", decoded.Bounds(), img.Bounds())
	}
}

func TestEncodeImage_Unsupported(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer
	if err := imgconv.EncodeImage(&buf, img, "bmp", 0); err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}

func TestImageRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := newTestImage()

	pngPath := filepath.Join(dir, "source.png")
	f, err := os.Create(pngPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, src); err != nil {
		t.Fatal(err)
	}
	f.Close()

	jpgPath := filepath.Join(dir, "output.jpg")
	if err := cmdImage([]string{"-quality", "95", pngPath, jpgPath}); err != nil {
		t.Fatalf("cmdImage png->jpg: %v", err)
	}

	stat, err := os.Stat(jpgPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Error("JPEG output file is empty")
	}

	gifPath := filepath.Join(dir, "output.gif")
	if err := cmdImage([]string{jpgPath, gifPath}); err != nil {
		t.Fatalf("cmdImage jpg->gif: %v", err)
	}

	stat, err = os.Stat(gifPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Error("GIF output file is empty")
	}

	pngPath2 := filepath.Join(dir, "final.png")
	if err := cmdImage([]string{"-format", "png", gifPath, pngPath2}); err != nil {
		t.Fatalf("cmdImage gif->png: %v", err)
	}

	final, err := os.Open(pngPath2)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()

	decoded, _, err := image.Decode(final)
	if err != nil {
		t.Fatalf("decoding final png: %v", err)
	}
	if decoded.Bounds() != src.Bounds() {
		t.Errorf("final bounds = %v, want %v", decoded.Bounds(), src.Bounds())
	}
}
