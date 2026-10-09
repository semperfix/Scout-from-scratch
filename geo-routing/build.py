#!/usr/bin/env python3
"""Stream the GA extract, build the road graph for the Savannah-area bbox,
and pickle the result. Run: python3 build.py"""

import pickle
import sys
import time

sys.path.insert(0, ".")

from pbf import PBFReader  # noqa: E402
from roads import RoadGraph  # noqa: E402

# Savannah / Effingham / Chatham area: lat 31.98-32.48, lon -81.52..-81.12
BBOX = (31.98, 32.48, -81.52, -81.12)

t0 = time.time()
r = PBFReader()
g = RoadGraph()
way_cb, kept = g.make_way_cb()
r.stream("georgia.osm.pbf", node_cb=g.make_node_cb(BBOX), way_cb=way_cb)
print(f"stream: {time.time()-t0:.1f}s  nodes={r.n_nodes} ways={r.n_ways} "
      f"rels={r.n_relations}")
print("header required_features:", r.header["required_features"])
print(f"ways passing highway filter: {len(kept)}")

t0 = time.time()
g.build(kept)
print(f"graph build: {time.time()-t0:.1f}s")
print("graph stats:", g.stats())

with open("graph.pkl", "wb") as f:
    pickle.dump({"coords": g.coords, "adj": g.adj, "bbox": BBOX,
                 "stats": g.stats()}, f)
print("saved graph.pkl")
