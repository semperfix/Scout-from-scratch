#!/usr/bin/env python3
"""Lightweight route-map renderer: title, route polylines, labeled stops,
scale bar. Overwrites the heavy SVGs with compact versions."""

import math
import pickle
import sys

sys.path.insert(0, ".")
from roads import RoadGraph  # noqa: E402
from router import route_between  # noqa: E402

BBOX = (31.98, 32.48, -81.52, -81.12)

STOPS = {
    "Bloomingdale": (32.13225, -81.29894),
    "Pooler": (32.11915, -81.24356),
    "Guyton": (32.33193, -81.39317),
    "Springfield": (32.37121, -81.31371),
}

d = pickle.load(open("graph.pkl", "rb"))
g = RoadGraph()
g.coords, g.adj = d["coords"], d["adj"]

lat0, lat1, lon0, lon1 = BBOX
kx = math.cos(math.radians((lat0 + lat1) / 2))
W, H = (lon1 - lon0) * kx, lat1 - lat0
WIDTH = 900
HEIGHT = int(WIDTH * H / W)


def proj(lat, lon):
    return ((lon - lon0) * kx / W * WIDTH, (lat1 - lat) / H * HEIGHT)


def render_map(title, legs, stops, path):
    """legs: list of ((name_a,name_b), node-path, color)."""
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" '
             f'height="{HEIGHT + 60}" viewBox="0 0 {WIDTH} {HEIGHT + 60}">',
             f'<rect width="{WIDTH}" height="{HEIGHT + 60}" fill="#eef3f0"/>']
    for (a, b), nodes, color in legs:
        pts = " ".join(f"{p[0]:.1f},{p[1]:.1f}"
                       for p in (proj(*g.coords[n]) for n in nodes))
        parts.append(f'<polyline points="{pts}" fill="none" stroke="{color}" '
                     f'stroke-width="4" stroke-linecap="round" '
                     f'stroke-linejoin="round" opacity="0.85"/>')
    for name, lat, lon in stops:
        x, y = proj(lat, lon)
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="#111" '
                     f'stroke="#fff" stroke-width="2.5"/>'
                     f'<text x="{x + 12:.1f}" y="{y + 5:.1f}" font-size="16" '
                     f'font-family="sans-serif" font-weight="bold" '
                     f'fill="#111">{name}</text>')
    # scale bar: 5 km
    km5_px = 5 / (W * 111.32 * kx) * WIDTH
    sx, sy = 30, HEIGHT - 25
    parts.append(f'<line x1="{sx}" y1="{sy}" x2="{sx + km5_px:.0f}" y2="{sy}" '
                 f'stroke="#111" stroke-width="3"/>'
                 f'<text x="{sx}" y="{sy - 8}" font-size="13" '
                 f'font-family="sans-serif">5 km</text>')
    parts.append(f'<text x="30" y="{HEIGHT + 32}" font-size="18" '
                 f'font-family="sans-serif" font-weight="bold">{title}</text>')
    parts.append('</svg>')
    with open(path, "w") as f:
        f.write("".join(parts))
    print(f"wrote {path}")


# Map 1: Bloomingdale -> Guyton
r = route_between(g, *STOPS["Bloomingdale"], *STOPS["Guyton"])
render_map(
    f"Bloomingdale → Guyton — {r['dist_km']:.1f} km, {r['time_h']*60:.0f} min",
    [(("Bloomingdale", "Guyton"), r["path"], "#d62728")],
    [("Bloomingdale", *STOPS["Bloomingdale"]), ("Guyton", *STOPS["Guyton"])],
    "route-bloomingdale-guyton.svg")

# Map 2: TSP day tour
from router import time_matrix, tsp_two_opt  # noqa: E402
pts = [("Bloomingdale", *STOPS["Bloomingdale"]),
       ("Pooler", *STOPS["Pooler"]),
       ("Guyton", *STOPS["Guyton"]),
       ("Springfield", *STOPS["Springfield"])]
T, Dmat, _ = time_matrix(g, pts)
order, total = tsp_two_opt(T)
colors = ["#d62728", "#1f77b4", "#2ca02c", "#9467bd"]
legs = []
total_km = 0.0
for k, (a, b) in enumerate(zip(order, order[1:])):
    rr = route_between(g, pts[a][1], pts[a][2], pts[b][1], pts[b][2])
    total_km += rr["dist_km"]
    legs.append(((pts[a][0], pts[b][0]), rr["path"], colors[k % 4]))
names = " → ".join(pts[i][0] for i in order)
render_map(f"Tree-work day: {names} — {total_km:.0f} km, {total*60:.0f} min",
           legs, pts, "route-tsp-day.svg")
