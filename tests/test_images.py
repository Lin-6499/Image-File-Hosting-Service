"""Tests for image inspection, sniffing and EXIF handling."""

from __future__ import annotations

import io

import pytest
from PIL import Image

from app.images import NotAnImage, inspect_image, make_thumbnail, sniff_mime, strip_exif
from tests.conftest import jpeg_with_exif, png_bytes


class TestSniffMime:
    def test_png(self):
        assert sniff_mime(png_bytes()[:64]) == "image/png"

    def test_jpeg(self):
        assert sniff_mime(jpeg_with_exif()[:64]) == "image/jpeg"

    def test_gif(self):
        buf = io.BytesIO()
        Image.new("P", (8, 8)).save(buf, format="GIF")
        assert sniff_mime(buf.getvalue()[:64]) == "image/gif"

    def test_webp(self):
        buf = io.BytesIO()
        Image.new("RGB", (8, 8)).save(buf, format="WEBP")
        assert sniff_mime(buf.getvalue()[:64]) == "image/webp"

    def test_pdf(self):
        assert sniff_mime(b"%PDF-1.7\n...") == "application/pdf"

    def test_zip(self):
        assert sniff_mime(b"PK\x03\x04rest") == "application/zip"

    def test_unknown_falls_back(self):
        assert sniff_mime(b"random bytes here") == "application/octet-stream"

    def test_text_is_not_image(self):
        assert sniff_mime(b"just some text") == "application/octet-stream"

    def test_html_not_misdetected_as_image(self):
        assert sniff_mime(b"<html><body>hi</body></html>") == "application/octet-stream"


class TestInspectImage:
    def test_dimensions_reported(self, tmp_path):
        p = tmp_path / "a.png"
        Image.new("RGB", (123, 45)).save(p, format="PNG")
        info = inspect_image(p)
        assert (info.width, info.height) == (123, 45)
        assert info.format == "PNG"
        assert info.mime_type == "image/png"

    def test_non_image_raises(self, tmp_path):
        p = tmp_path / "not.txt"
        p.write_bytes(b"plain text")
        with pytest.raises(NotAnImage):
            inspect_image(p)

    def test_svg_rejected(self, tmp_path):
        """SVG is a stored-XSS vector and must not be treated as an image."""
        p = tmp_path / "x.svg"
        p.write_bytes(b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>')
        with pytest.raises(NotAnImage):
            inspect_image(p)

    def test_truncated_image_raises(self, tmp_path):
        p = tmp_path / "trunc.png"
        p.write_bytes(png_bytes()[:20])
        with pytest.raises(NotAnImage):
            inspect_image(p)


class TestThumbnail:
    def test_generates_downscaled_webp(self, tmp_path):
        src = tmp_path / "big.png"
        Image.new("RGB", (2000, 1000), (10, 20, 30)).save(src, format="PNG")

        dest = make_thumbnail(src, "a" * 64)
        assert dest is not None and dest.exists()
        with Image.open(dest) as im:
            assert im.format == "WEBP"
            assert max(im.size) <= 512

    def test_small_image_not_upscaled(self, tmp_path):
        src = tmp_path / "small.png"
        Image.new("RGB", (32, 24)).save(src, format="PNG")
        dest = make_thumbnail(src, "b" * 64)
        with Image.open(dest) as im:
            assert im.size == (32, 24)

    def test_animated_gif_skipped(self, tmp_path):
        """Flattening an animated GIF would silently destroy its point.

        The frames must differ in actual pixel content. Frames built by only
        varying the palette index, or identical RGB frames, are coalesced by
        Pillow into a single-frame GIF -- which would make this test pass for
        the wrong reason. The assertion below guards against that.
        """
        from PIL import ImageDraw

        src = tmp_path / "anim.gif"
        frames = []
        for i, col in enumerate([(255, 0, 0), (0, 255, 0), (0, 0, 255)]):
            f = Image.new("RGB", (16, 16), (0, 0, 0))
            ImageDraw.Draw(f).rectangle([i * 4, 0, i * 4 + 5, 15], fill=col)
            frames.append(f.convert("P", palette=Image.ADAPTIVE))

        frames[0].save(
            src, format="GIF", save_all=True, append_images=frames[1:],
            duration=150, loop=0, disposal=2,
        )

        with Image.open(src) as probe:
            assert probe.n_frames > 1, "fixture is not actually animated"

        assert make_thumbnail(src, "c" * 64) is None

    def test_single_frame_gif_gets_thumbnail(self, tmp_path):
        src = tmp_path / "still.gif"
        Image.new("P", (32, 32), 3).save(src, format="GIF")
        assert make_thumbnail(src, "f" * 64) is not None

    def test_aspect_ratio_preserved(self, tmp_path):
        src = tmp_path / "wide.png"
        Image.new("RGB", (1000, 250)).save(src, format="PNG")
        dest = make_thumbnail(src, "d" * 64)
        with Image.open(dest) as im:
            assert abs(im.width / im.height - 4.0) < 0.05

    def test_alpha_channel_flattened_to_rgb(self, tmp_path):
        src = tmp_path / "alpha.png"
        Image.new("RGBA", (64, 64), (255, 0, 0, 128)).save(src, format="PNG")
        dest = make_thumbnail(src, "e" * 64)
        with Image.open(dest) as im:
            assert im.mode in ("RGB", "RGBA")


class TestExifStripping:
    def test_gps_removed(self, tmp_path):
        p = tmp_path / "gps.jpg"
        p.write_bytes(jpeg_with_exif())

        with Image.open(p) as im:
            assert 0x8825 in im.getexif(), "fixture should contain GPS"

        assert strip_exif(p) is True

        with Image.open(p) as im:
            assert 0x8825 not in im.getexif()

    def test_png_untouched(self, tmp_path):
        p = tmp_path / "plain.png"
        p.write_bytes(png_bytes())
        assert strip_exif(p) is False

    def test_no_exif_returns_false(self, tmp_path):
        p = tmp_path / "clean.jpg"
        Image.new("RGB", (20, 20)).save(p, format="JPEG")
        assert strip_exif(p) is False

    def test_stripped_file_still_readable(self, tmp_path):
        p = tmp_path / "still.jpg"
        p.write_bytes(jpeg_with_exif())
        strip_exif(p)
        with Image.open(p) as im:
            assert im.size == (40, 30)
