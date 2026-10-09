#!/usr/bin/env python3
"""Road graph builder from OSM data. Zero dependencies.

Filters drivable ways, applies one-way rules, builds an adjacency graph with
haversine-distance edges and per-class speed estimates for travel-time routing.
"""

import math
from array import array

EARTH_KM = 6371.0088

DRIVABLE = {
    "motorway", "trunk", "primary", "secondary", "tertiary",
    "unclassified", "residential", "living_street", "service", "road",
    "motorway_link", "trunk_link", "primary_link", "secondary_link",
    "tertiary_link",
}

SPEEDS_KMH = {  # rough free-flow speeds per highway class
    "motorway": 105, "trunk": 90, "primary": 80, "secondary": 70,
    "tertiary": 60, "unclassified": 50, "residential": 40,
    "living_street": 25, "service": 20, "road": 40,
    "motorway_link": 60, "trunk_link": 55, "primary_link": 50,
    "secondary_link": 45, "tertiary_link": 40,
}


def haversine_km(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_KM * math.asin(math.sqrt(a))


def is_oneway(tags):
    if tags.get("junction") == "roundabout":
        return 1
    ow = tags.get("oneway", "").lower()
    if ow in ("yes", "1", "true"):
        return 1
    if ow in ("-1", "reverse"):
        return -1
    return 0


class RoadGraph:
    def __init__(self):
        self.coords = {}        # node_id -> (lat, lon)
        self.adj = {}           # node_id -> list of (nbr, time_h, dist_km)
        self.n_ways_kept = 0
        self.n_ways_seen = 0
        self.n_edges = 0

    # -- streaming callbacks ------------------------------------------------
    def make_node_cb(self, bbox, margin=0.02):
        lat0, lat1, lon0, lon1 = bbox
        coords = self.coords

        def cb(node):
            lat, lon = node["lat"], node["lon"]
            if (lat0 - margin) <= lat <= (lat1 + margin) and \
               (lon0 - margin) <= lon <= (lon1 + margin):
                coords[node["id"]] = (lat, lon)
        return cb

    def make_way_cb(self):
        kept = []

        def cb(way):
            self.n_ways_seen += 1
            tags = way["tags"]
            hwy = tags.get("highway")
            if hwy not in DRIVABLE:
                return
            if tags.get("access") == "no":
                return
            refs = way["refs"]
            if len(refs) < 2:
                return
            kept.append((array("q", refs), hwy, is_oneway(tags),
                         tags.get("name", "")))
        return cb, kept

    # -- graph build --------------------------------------------------------
    def build(self, kept_ways):
        coords, adj = self.coords, self.adj
        for refs, hwy, oneway, _name in kept_ways:
            # resolve to coordinates; split polyline where nodes are missing
            segs = []
            cur = []
            for r in refs:
                c = coords.get(r)
                if c is None:
                    if len(cur) >= 2:
                        segs.append(cur)
                    cur = []
                else:
                    cur.append((r, c))
            if len(cur) >= 2:
                segs.append(cur)
            if not segs:
                continue
            self.n_ways_kept += 1
            speed = SPEEDS_KMH[hwy]
            for seg in segs:
                for (a, ca), (b, cb_) in zip(seg, seg[1:]):
                    d = haversine_km(ca[0], ca[1], cb_[0], cb_[1])
                    t = d / speed
                    if oneway >= 0:
                        adj.setdefault(a, []).append((b, t, d))
                    if oneway <= 0:
                        adj.setdefault(b, []).append((a, t, d))
                    self.n_edges += 1 if oneway else 2
        # drop coordinate entries that no edge touches (keep sink-only nodes
        # that appear as neighbors, e.g. at the end of one-way streets)
        used = set(adj)
        for edges in adj.values():
            for v, _t, _d in edges:
                used.add(v)
        for k in [k for k in coords if k not in used]:
            del coords[k]

    def nearest(self, lat, lon):
        """Nearest graph node to (lat, lon). Linear scan — fine for bbox scale."""
        best, best_d = None, float("inf")
        for nid, (nlat, nlon) in self.coords.items():
            d = (nlat - lat) ** 2 + ((nlon - lon) * 0.8) ** 2
            if d < best_d:
                best, best_d = nid, d
        if best is None:
            raise ValueError("empty graph")
        return best

    def stats(self):
        return {
            "nodes": len(self.coords),
            "ways_kept": self.n_ways_kept,
            "ways_seen": self.n_ways_seen,
            "edges": self.n_edges,
        }
