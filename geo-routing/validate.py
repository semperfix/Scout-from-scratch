#!/usr/bin/env python3
"""Validation + demo: route real GA towns, multi-stop TSP, render SVG maps."""

import pickle
import sys
import time

sys.path.insert(0, ".")
from roads import RoadGraph, haversine_km  # noqa: E402
from router import route_between, time_matrix, tsp_two_opt  # noqa: E402
from svgmap import render  # noqa: E402

with open("graph.pkl", "rb") as f:
    data = pickle.load(f)
g = RoadGraph()
g.coords, g.adj, BBOX = data["coords"], data["adj"], data["bbox"]
print("graph stats:", data["stats"], "bbox:", BBOX)

STOPS = {
    "Bloomingdale": (32.13225, -81.29894),
    "Pooler": (32.11915, -81.24356),
    "Guyton": (32.33193, -81.39317),
    "Springfield": (32.37121, -81.31371),
}

# --- check 1: nearest-node snapping is tight (<= 500 m) -------------------
print("\n[nearest-node snap]")
for name, (lat, lon) in STOPS.items():
    n = g.nearest(lat, lon)
    nlat, nlon = g.coords[n]
    d = haversine_km(lat, lon, nlat, nlon) * 1000
    print(f"  {name:14s} snap {d:7.1f} m  node {n}")
    assert d < 500, f"snap too far for {name}"

# --- check 2: Bloomingdale -> Guyton ---------------------------------------
print("\n[route Bloomingdale -> Guyton]")
t0 = time.time()
r = route_between(g, *STOPS["Bloomingdale"], *STOPS["Guyton"])
dt = time.time() - t0
straight = haversine_km(*STOPS["Bloomingdale"], *STOPS["Guyton"])
print(f"  straight-line {straight:.1f} km | driving {r['dist_km']:.1f} km | "
      f"time {r['time_h']*60:.1f} min | nodes {len(r['path'])} | "
      f"computed in {dt*1000:.0f} ms")
ratio = r["dist_km"] / straight
print(f"  detour ratio {ratio:.2f}")
assert 1.02 <= ratio <= 2.0, "implausible detour ratio"
assert r["time_h"] * 60 < 120
render(g, BBOX, routes=[r["path"]],
       stops=[("Bloomingdale", *STOPS["Bloomingdale"]),
              ("Guyton", *STOPS["Guyton"])],
       path="route-bloomingdale-guyton.svg")
print("  wrote route-bloomingdale-guyton.svg")

# --- check 3: Pooler -> Springfield ------------------------------------------
print("\n[route Pooler -> Springfield]")
r2 = route_between(g, *STOPS["Pooler"], *STOPS["Springfield"])
straight2 = haversine_km(*STOPS["Pooler"], *STOPS["Springfield"])
print(f"  straight-line {straight2:.1f} km | driving {r2['dist_km']:.1f} km | "
      f"time {r2['time_h']*60:.1f} min")
assert 1.02 <= r2["dist_km"] / straight2 <= 2.0

# --- check 4: multi-stop tree-work day (TSP) ----------------------------------
print("\n[TSP: Bloomingdale base -> Pooler, Guyton, Springfield -> back]")
pts = [("Bloomingdale", *STOPS["Bloomingdale"]),
       ("Pooler", *STOPS["Pooler"]),
       ("Guyton", *STOPS["Guyton"]),
       ("Springfield", *STOPS["Springfield"])]
T, D, nodes = time_matrix(g, pts)
print("  time matrix (min):")
for i, (nm, _, _) in enumerate(pts):
    print(f"    {nm:13s}" + "".join(f"{T[i][j]*60:8.1f}" for j in range(4)))
order, total = tsp_two_opt(T)
names = [pts[i][0] for i in order]
print(f"  best order: {' -> '.join(names)}  total {total*60:.1f} min")
# naive order (Bloomingdale->Pooler->Guyton->Springfield->Bloomingdale) for contrast
naive = sum(T[i][i + 1] for i in range(3)) + T[3][0]
print(f"  naive order total: {naive*60:.1f} min  (saved {(naive-total)*60:.1f} min)")
assert total <= naive + 1e-9

# render full TSP tour
tour_paths = []
for a, b in zip(order, order[1:]):
    rr = route_between(g, pts[a][1], pts[a][2], pts[b][1], pts[b][2])
    tour_paths.append(rr["path"])
render(g, BBOX, routes=tour_paths,
       stops=[(nm, la, lo) for nm, la, lo in pts],
       path="route-tsp-day.svg")
print("  wrote route-tsp-day.svg")

# --- check 5: symmetry sanity (undirected graph should be ~symmetric) ---------
print("\n[symmetry]")
r_back = route_between(g, *STOPS["Guyton"], *STOPS["Bloomingdale"])
print(f"  forward {r['time_h']*60:.1f} min / {r['dist_km']:.1f} km | "
      f"back {r_back['time_h']*60:.1f} min / {r_back['dist_km']:.1f} km")
assert abs(r["dist_km"] - r_back["dist_km"]) / r["dist_km"] < 0.15

print("\nALL CHECKS PASSED")
