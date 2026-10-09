# Geo-Routing — OSM PBF Parsing & Road Routing from Scratch

A zero-dependency geospatial stack: a hand-rolled OSM PBF parser (protobuf
codec, delta-coded dense nodes, string tables), a road-graph builder (drivable
highway classes, one-way rules incl. roundabouts, haversine weights, per-class
speeds), and a router (A\* with admissible travel-time heuristic +
independent Dijkstra cross-check, nearest-node snapping, all-pairs time matrix,
nearest-neighbor + 2-opt TSP). It turns a raw planet-style extract into
shortest-time routes and printable SVG maps — e.g. Bloomingdale → Guyton:
26.0 km, 21.8 min, computed in ~1 s, A\* and Dijkstra agreeing bit-exactly.

## Dependencies

Stdlib only (`zlib` for blob decompression — ships with Python). No
`osmium`, no `networkx`.

## Data

The pipeline builds from a **Geofabrik OSM extract** (the Georgia one is at
https://download.geofabrik.de/north-america/us/georgia.html — any region works).

```
python3 build.py     # streams georgia.osm.pbf (~4 min pure Python for 357 MB),
                     # filters to the Savannah-area bbox, writes graph.pkl
```

`georgia.osm.pbf` (357 MB) and the built `graph.pkl` (25 MB) are intentionally
**not** shipped — rebuild locally with `build.py`. The two example SVG maps are
included (`route-bloomingdale-guyton.svg`, `route-tsp-day.svg`).

## How to run

```
python3 tests.py       # parser + graph + routing checks
python3 validate.py    # end-to-end assertions on the built graph.pkl
python3 build.py       # rebuild graph.pkl from a Geofabrik extract
```

`maps.py` renders routes to SVG (needs `graph.pkl`).

## Usage example

```python
import pickle
from router import route_between, tsp_two_opt, time_matrix

g = pickle.load(open("graph.pkl", "rb"))   # {"coords", "adj", "bbox", "stats"}
r = route_between(g, 32.13225, -81.29894, 32.33193, -81.39317)  # Bloomingdale -> Guyton
print(f"{r['dist_km']:.1f} km, {r['mins']:.1f} min, {len(r['path'])} nodes")

T = time_matrix(g, stops)          # all-pairs travel-time matrix
order, cost = tsp_two_opt(T)      # optimal stop order
```

## Key learnings

- **PBF's classic trap: `BlobHeader.datasize` is field 3, not 2** (field 2 is
  `indexdata`). Caught by hexdumping the first block's raw bytes — "dump the
  bytes, don't trust the memory."
- **The whole 357 MB miracle is delta coding.** Node ids/lats/lons are
  zigzag-varint deltas, tags are stringtable index pairs — OSM PBF is a
  masterclass in making 45M geographic records downloadable.
- **Coordinates are `(lat_offset + granularity × value) × 1e-9` degrees**,
  granularity defaulting to 100 nanodegrees (~1.1 cm) — sub-centimeter precision
  is why snap distances of 2–50 m are trustworthy.
- **The visualization was the test.** Ways crossing the bbox edge reference
  dropped nodes — splitting polylines there (and keeping sink-only one-way
  endpoints) was caught by the SVG renderer raising `KeyError`, not by the
  router.

## Files

- `pbf.py` — hand-rolled OSM PBF parser (protobuf codec, framing, delta decode)
- `roads.py` — road-graph builder (highway classes, one-way rules, weights)
- `router.py` — A\* + Dijkstra, nearest-node snap, time matrix, TSP
- `svgmap.py` — SVG route-map renderer
- `maps.py` — compact maps with stops/scale bar/title (needs `graph.pkl`)
- `build.py` — stream extract → filter bbox → write `graph.pkl`
- `validate.py` — end-to-end assertions on the built graph (needs `graph.pkl`)
- `tests.py` — parser/graph/routing checks
- `route-bloomingdale-guyton.svg`, `route-tsp-day.svg` — example output maps
- `LEARNINGS.md` — the full expedition writeup
