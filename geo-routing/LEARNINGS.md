# Expedition #33 — Geospatial: OSM PBF parsing & road routing from scratch

## What was built
Zero-dependency geospatial stack in `~/workspace/learning/33-geo-routing/`:
- `pbf.py` — hand-rolled OSM PBF parser: protobuf codec (varint, zigzag sint,
  fixed32/64, length-delimited, packed fields), FileBlock framing
  (4-byte BE header length → BlobHeader → zlib Blob), OSMHeader, PrimitiveBlock
  stringtable, granularity/offset coordinate math, delta-coded DenseNodes,
  delta-coded Way refs, relation counting.
- `roads.py` — road graph builder: drivable highway classes, one-way rules
  (incl. `junction=roundabout`), bbox filtering, polyline splitting at missing
  nodes, haversine edge weights, per-class speed table for travel-time costs.
- `router.py` — A* (haversine/max-speed admissible heuristic) + independent
  Dijkstra cross-check, nearest-node snapping, all-pairs time matrix,
  nearest-neighbor + 2-opt TSP.
- `maps.py` — compact SVG route maps with stops, scale bar, title.
- `build.py` / `validate.py` / `tests.py` — full pipeline + assertions.

Data: Geofabrik Georgia extract (357 MB, 2026-10-08): **45.2M nodes,
5.39M ways, 30.8k relations** streamed in ~4 min pure Python. Savannah-area
bbox (31.98–32.48, −81.52–−81.12) → 284,310-node / 570,724-edge graph.

## Validated results
- Bloomingdale → Guyton: 26.0 km driving vs 23.9 km straight-line (detour
  ratio 1.09), 21.8 min, 441-node path, computed in ~1 s. A* and Dijkstra
  agree bit-exact on every query (asserted).
- Every route path verified link-continuous against the adjacency list.
- 4-stop tree-work day TSP (Bloomingdale base → Guyton/Springfield/Pooler):
  optimal 58.6 min vs naive 66.0 min — saves 7.3 min of driving.
- Parser: varint/zigzag round-trips, two-independent-code-paths dense-node
  cross-check (8,000 nodes agree to 1e-12°), header feature assertions,
  truncation rejection.

## Earned insights
- PBF's classic trap: `BlobHeader.datasize` is **field 3**, not 2 (field 2 is
  `indexdata`). Caught by hexdumping the first block's raw bytes — the fix
  was one line, the lesson is "dump the bytes, don't trust the memory."
- The whole 357 MB miracle is delta coding: node ids/lats/lons are
  zigzag-varint deltas and tags are stringtable index pairs. OSM's PBF is a
  masterclass in making 45M geographic records fit in a download.
- Coordinates: `(lat_offset + granularity × value) × 1e-9` degrees;
  granularity defaults to 100 nanodegrees (~1.1 cm). Sub-centimeter precision
  is why snap distances of 2–50 m are trustworthy.
- Graph-building subtlety: ways crossing the bbox edge reference nodes you
  dropped — split the polyline there instead of discarding the way, and keep
  sink-only nodes (one-way street ends) that appear only as edge targets.
  The latter bug was caught by the SVG renderer (`KeyError`), not the router:
  **the visualization was the test.**
- A* admissibility for travel time: `haversine / max_speed` with max_speed ≥
  every class speed. Dijkstra cross-check never disagreed — the value was the
  discipline, not the catch.
- Honest limitation: per-class speed guesses are the weakest link. This is
  free-flow routing, not live traffic. Real ETAs need observed speeds.
- `map.geocode` gave the endpoints (Bloomingdale 32.13225,-81.29894;
  Guyton 32.33193,-81.39317; Pooler; Springfield) — routing demo uses Kyle's
  actual area, so the tool doubles as a job-site route planner.

## The tool for
"What's the fastest driving order for today's job sites" — real local road
network, real shortest-time paths, multi-stop optimization, printable maps.
Pairs with the time-series weather work (#26) for full work-day planning
(when to go × what order to drive).
