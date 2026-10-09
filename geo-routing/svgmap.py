#!/usr/bin/env python3
"""SVG map renderer for the road graph and computed routes. Zero dependencies."""

import math


def render(g, bbox, routes=(), stops=(), width=1000, path="map.svg",
           minor_color="#cccccc", route_colors=("#d62728", "#1f77b4",
                                               "#2ca02c", "#ff7f0e")):
    """routes: list of node-id lists. stops: list of (name, lat, lon)."""
    lat0, lat1, lon0, lon1 = bbox
    kx = math.cos(math.radians((lat0 + lat1) / 2))
    W = (lon1 - lon0) * kx
    H = lat1 - lat0
    height = int(width * H / W)

    def proj(lat, lon):
        x = (lon - lon0) * kx / W * width
        y = (lat1 - lat) / H * height
        return x, y

    lines = []
    for u, edges in g.adj.items():
        x1, y1 = proj(*g.coords[u])
        for v, _t, _d in edges:
            x2, y2 = proj(*g.coords[v])
            lines.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                f'stroke="{minor_color}" stroke-width="0.6"/>')

    route_svg = []
    for ri, path_nodes in enumerate(routes):
        pts = " ".join(f"{p[0]:.1f},{p[1]:.1f}"
                       for p in (proj(*g.coords[n]) for n in path_nodes))
        route_svg.append(
            f'<polyline points="{pts}" fill="none" '
            f'stroke="{route_colors[ri % len(route_colors)]}" '
            f'stroke-width="3.5" stroke-linecap="round" '
            f'stroke-linejoin="round"/>')

    stop_svg = []
    for name, lat, lon in stops:
        x, y = proj(lat, lon)
        stop_svg.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="#111" '
            f'stroke="#fff" stroke-width="2"/>'
            f'<text x="{x + 10:.1f}" y="{y + 4:.1f}" font-size="15" '
            f'font-family="sans-serif" font-weight="bold">{name}</text>')

    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
           f'height="{height}" viewBox="0 0 {width} {height}">'
           f'<rect width="{width}" height="{height}" fill="#f7f7f7"/>'
           + "".join(lines) + "".join(route_svg) + "".join(stop_svg) + "</svg>")
    with open(path, "w") as f:
        f.write(svg)
    return path
