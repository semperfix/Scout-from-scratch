#!/usr/bin/env python3
"""Routing on the road graph. Zero dependencies.

- A* with haversine/max-speed admissible heuristic (minimizes travel time)
- Dijkstra as an independent cross-check implementation
- Held-Karp-free TSP: nearest-neighbor seed + 2-opt improvement for multi-stop
  day planning
"""

import heapq
import math
from roads import haversine_km

MAX_SPEED_KMH = 105.0  # must be >= every class speed for an admissible heuristic


def heuristic(a, b, coords):
    lat1, lon1 = coords[a]
    lat2, lon2 = coords[b]
    return haversine_km(lat1, lon1, lat2, lon2) / MAX_SPEED_KMH


def astar(g, src, dst):
    """Return (time_h, dist_km, path_node_ids) minimizing travel time."""
    coords, adj = g.coords, g.adj
    open_ = [(heuristic(src, dst, coords), 0.0, src)]
    gscore = {src: 0.0}
    dist = {src: 0.0}
    came = {}
    closed = set()
    while open_:
        _, t, u = heapq.heappop(open_)
        if u in closed:
            continue
        if u == dst:
            path = [u]
            while u in came:
                u = came[u]
                path.append(u)
            path.reverse()
            return t, dist[dst], path
        closed.add(u)
        for v, et, ed in adj.get(u, ()):  # noqa: B007
            nt = t + et
            if nt < gscore.get(v, float("inf")):
                gscore[v] = nt
                dist[v] = dist[u] + ed
                came[v] = u
                heapq.heappush(open_, (nt + heuristic(v, dst, coords), nt, v))
    return None


def dijkstra(g, src, dst):
    """Independent implementation for cross-validation of A*."""
    adj = g.adj
    pq = [(0.0, src)]
    tscore = {src: 0.0}
    dscore = {src: 0.0}
    came = {}
    done = set()
    while pq:
        t, u = heapq.heappop(pq)
        if u in done:
            continue
        if u == dst:
            path = [u]
            while u in came:
                u = came[u]
                path.append(u)
            path.reverse()
            return t, dscore[dst], path
        done.add(u)
        for v, et, ed in adj.get(u, ()):  # noqa: B007
            nt = t + et
            if nt < tscore.get(v, float("inf")):
                tscore[v] = nt
                dscore[v] = dscore[u] + ed
                came[v] = u
                heapq.heappush(pq, (nt, v))
    return None


def route_between(g, lat1, lon1, lat2, lon2):
    s = g.nearest(lat1, lon1)
    d = g.nearest(lat2, lon2)
    a = astar(g, s, d)
    dj = dijkstra(g, s, d)
    assert a is not None and dj is not None, "no route found"
    assert abs(a[0] - dj[0]) < 1e-9 and abs(a[1] - dj[1]) < 1e-9, \
        "A*/Dijkstra disagreement"
    return {"time_h": a[0], "dist_km": a[1], "path": a[2],
            "src_node": s, "dst_node": d}


def time_matrix(g, points):
    """All-pairs (time_h, dist_km) between named (lat, lon) points."""
    n = len(points)
    T = [[0.0] * n for _ in range(n)]
    D = [[0.0] * n for _ in range(n)]
    nodes = [g.nearest(lat, lon) for _, lat, lon in points]
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            r = astar(g, nodes[i], nodes[j])
            assert r is not None, f"no route {points[i][0]} -> {points[j][0]}"
            T[i][j], D[i][j] = r[0], r[1]
    return T, D, nodes


def tsp_two_opt(T):
    """Nearest-neighbor seed + 2-opt. Returns (order, total_time)."""
    n = len(T)
    unvisited = set(range(1, n))
    order = [0]
    while unvisited:
        cur = order[-1]
        nxt = min(unvisited, key=lambda j: T[cur][j])
        order.append(nxt)
        unvisited.remove(nxt)
    order.append(0)

    def cost(o):
        return sum(T[o[i]][o[i + 1]] for i in range(len(o) - 1))

    improved = True
    while improved:
        improved = False
        best = cost(order)
        for i in range(1, n - 1):
            for k in range(i + 1, n):
                cand = order[:i] + order[i:k + 1][::-1] + order[k + 1:]
                c = cost(cand)
                if c < best - 1e-12:
                    order, best = cand, c
                    improved = True
    return order, cost(order)
