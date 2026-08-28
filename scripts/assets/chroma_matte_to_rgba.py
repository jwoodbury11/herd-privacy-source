#!/usr/bin/env python3
"""Convert one flat chroma-matte render into a decontaminated RGBA PNG.

This is the canonical fallback when an image generator cannot return trustworthy
native transparency. Never feed it a checkerboard preview.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter


def smoothstep(edge0: float, edge1: float, value: np.ndarray) -> np.ndarray:
    t = np.clip((value - edge0) / (edge1 - edge0), 0.0, 1.0)
    return t * t * (3.0 - 2.0 * t)


def propagate_interior_colors(
    rgb: np.ndarray, alpha: np.ndarray, radius: int = 3
) -> np.ndarray:
    """Replace matte-contaminated boundary RGB with nearby trusted subject RGB."""
    transparent = alpha == 0.0
    edge_band = np.asarray(
        Image.fromarray((transparent.astype(np.uint8) * 255), mode="L").filter(
            ImageFilter.MaxFilter(radius * 2 + 1)
        )
    ) > 0
    remaining = edge_band & (alpha > 0.0)
    trusted = (alpha >= 0.985) & ~edge_band
    result = rgb.copy()

    for _ in range(radius * 2 + 2):
        padded_trusted = np.pad(trusted, 1, mode="constant")
        padded_rgb = np.pad(result, ((1, 1), (1, 1), (0, 0)), mode="edge")
        neighbor_count = np.zeros(alpha.shape, dtype=np.float32)
        neighbor_sum = np.zeros_like(result, dtype=np.float32)
        for dy in range(3):
            for dx in range(3):
                if dx == 1 and dy == 1:
                    continue
                mask = padded_trusted[dy : dy + alpha.shape[0], dx : dx + alpha.shape[1]]
                neighbor_count += mask
                neighbor_sum += (
                    padded_rgb[dy : dy + alpha.shape[0], dx : dx + alpha.shape[1]]
                    * mask[..., None]
                )
        fill = remaining & (neighbor_count > 0)
        if not np.any(fill):
            break
        result[fill] = neighbor_sum[fill] / neighbor_count[fill, None]
        trusted[fill] = True
        remaining[fill] = False
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--key-edge-scale",
        type=float,
        default=0.55,
        help="Lower values remove more chroma from subject boundaries.",
    )
    parser.add_argument(
        "--edge-chroma-mode",
        choices=("max", "min"),
        default="max",
        help="Use min for matte spill mixed with a strongly colored subject edge.",
    )
    parser.add_argument("--matte-edge-radius", type=int, default=3)
    args = parser.parse_args()

    source = np.asarray(Image.open(args.input).convert("RGB"), dtype=np.float32) / 255.0
    height, width, _ = source.shape
    corner = max(12, min(height, width) // 40)
    samples = np.concatenate(
        [
            source[:corner, :corner].reshape(-1, 3),
            source[:corner, -corner:].reshape(-1, 3),
            source[-corner:, :corner].reshape(-1, 3),
            source[-corner:, -corner:].reshape(-1, 3),
        ],
        axis=0,
    )
    matte = np.median(samples, axis=0)

    dominant = int(np.argmax(matte))
    other_channels = [index for index in range(3) if index != dominant]
    matte_excess = float(matte[dominant] - np.max(matte[other_channels]))
    if matte_excess < 0.45:
        raise SystemExit(f"Matte is not sufficiently single-channel chroma: {matte.tolist()}")
    chroma_excess = source[..., dominant] - np.maximum(
        source[..., other_channels[0]], source[..., other_channels[1]]
    )

    # The generated matte varies slightly across the canvas. Key by green excess,
    # leaving natural foliage opaque while retaining a narrow antialiased fringe.
    low = max(0.24, matte_excess * 0.38)
    high = max(low + 0.12, matte_excess * 0.88)
    alpha = 1.0 - smoothstep(low, high, chroma_excess)

    # Smoothstep alone can misclassify a thin green-contaminated outline as
    # opaque foreground. Within three pixels of certain matte, use a linear
    # coverage estimate so that fringe becomes antialiasing, not a solid ring.
    hard_background = chroma_excess >= high
    near_background = np.asarray(
        Image.fromarray((hard_background.astype(np.uint8) * 255), mode="L").filter(
            ImageFilter.MaxFilter(args.matte_edge_radius * 2 + 1)
        )
    ) > 0
    if args.edge_chroma_mode == "min":
        edge_chroma = source[..., dominant] - np.minimum(
            source[..., other_channels[0]], source[..., other_channels[1]]
        )
    else:
        edge_chroma = chroma_excess
    linear_alpha = np.clip(
        1.0 - (edge_chroma / (matte_excess * args.key_edge_scale)), 0.0, 1.0
    ) ** 1.5
    alpha[near_background] = np.minimum(alpha[near_background], linear_alpha[near_background])

    # Force pixels that closely match the measured matte fully transparent.
    matte_distance = np.linalg.norm(source - matte.reshape(1, 1, 3), axis=2)
    alpha[matte_distance < 0.075] = 0.0
    alpha[alpha < 0.015] = 0.0
    alpha[alpha > 0.985] = 1.0

    # Reverse the matte blend on partial pixels. This removes green spill instead
    # of merely hiding it behind low alpha, which prevents colored edge halos.
    safe_alpha = np.maximum(alpha, 0.04)[..., None]
    foreground = (source - (1.0 - safe_alpha) * matte.reshape(1, 1, 3)) / safe_alpha
    foreground = np.clip(foreground, 0.0, 1.0)

    # Suppress any residual chroma only in the antialiased transition, while
    # preserving opaque green foliage and court landscaping.
    transition = np.clip((1.0 - alpha) * 1.35, 0.0, 1.0)
    neutral_dominant = np.maximum(
        foreground[..., other_channels[0]], foreground[..., other_channels[1]]
    ) * 1.05
    corrected_dominant = np.minimum(foreground[..., dominant], neutral_dominant)
    aggressive_edge = (alpha < 1.0) | (near_background & (chroma_excess > 0.08))
    foreground[..., dominant] = np.where(
        aggressive_edge,
        corrected_dominant,
        foreground[..., dominant] * (1.0 - transition)
        + corrected_dominant * transition,
    )
    foreground = propagate_interior_colors(foreground, alpha)
    foreground[alpha == 0.0] = 0.0

    rgba = np.dstack((foreground, alpha))
    encoded = np.round(rgba * 255.0).astype(np.uint8)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(encoded, mode="RGBA").save(args.output, optimize=True)

    semi = (encoded[..., 3] > 0) & (encoded[..., 3] < 255)
    edge_rgb = encoded[..., :3][semi]
    residual_matte = 0
    bright_neutral = 0
    if len(edge_rgb):
        residual_matte = int(
            np.count_nonzero(
                edge_rgb[:, dominant]
                > np.maximum(
                    edge_rgb[:, other_channels[0]], edge_rgb[:, other_channels[1]]
                )
                + 28
            )
        )
        bright_neutral = int(np.count_nonzero(np.min(edge_rgb, axis=1) > 235))
    report = {
        "input": str(args.input),
        "output": str(args.output),
        "dimensions": [width, height],
        "matteRgb": [round(float(channel * 255.0), 2) for channel in matte],
        "matteDominantChannel": ["red", "green", "blue"][dominant],
        "matteChromaExcess": round(matte_excess, 4),
        "transparentPixels": int(np.count_nonzero(encoded[..., 3] == 0)),
        "opaquePixels": int(np.count_nonzero(encoded[..., 3] == 255)),
        "semTransparentPixels": int(np.count_nonzero(semi)),
        "residualMatteEdgePixels": residual_matte,
        "brightNeutralEdgePixels": bright_neutral,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
