"""Regenerate the extension's code-native M/connection logo (requires Pillow)."""
from pathlib import Path

from PIL import Image, ImageDraw

output = Path(__file__).resolve().parents[1] / "extension" / "icons"
output.mkdir(parents=True, exist_ok=True)
# Draw at 4x the largest size so the toolbar icons keep smooth edges.
image = Image.new("RGBA", (512, 512))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((16, 16, 496, 496), radius=112, fill="#0f766e")
points = [(128, 360), (128, 160), (256, 288), (384, 160), (384, 360)]
draw.line(points, fill="#ffffff", width=44, joint="curve")
for x, y in points:
    draw.ellipse((x - 22, y - 22, x + 22, y + 22), fill="#ffffff")
# The central packet highlights the proxy between two endpoints.
draw.ellipse((220, 252, 292, 324), fill="#fbbf24")
for size in (16, 32, 48, 128):
    image.resize((size, size), Image.Resampling.LANCZOS).save(output / f"icon-{size}.png")
