"""OCI container image forensics. Hand-rolled tar/OCI logic (see tar.py);
network via stdlib http.client over the egress proxy; JSON via stdlib json.

Pulls public images from a registry (Docker Hub default), verifies manifest
digests (the tag is a lie; the digest is the truth), applies layers with
OCI whiteout semantics, reconstructs an approximate Dockerfile from history,
and triages the result: secrets, setuid, opaque dirs, config env secrets.
"""

import base64
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import urllib.parse
import urllib.request

import tar

DOCKER_AUTH = "https://auth.docker.io/token"
DOCKER_REG = "registry-1.docker.io"


class OCIError(Exception):
    pass


# ---------------------------------------------------------------- registry

def _proxy_url(target: str) -> str:
    """Return a URL fetchable directly (proxy env handles the rest)."""
    return target


def _http(method, url, headers=None, body=None, timeout=60):
    req = urllib.request.Request(url, data=body, headers=headers or {},
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def registry_token(registry: str, repo: str, scope_extra: str = "pull") -> str:
    """Anonymous bearer token for registry.docker.io-style token auth."""
    url = (f"{DOCKER_AUTH}?service=registry.docker.io"
           f"&scope=repository:{repo}:{scope_extra}")
    st, _, body = _http("GET", url)
    if st != 200:
        raise OCIError(f"token request failed: HTTP {st}")
    return json.loads(body)["token"]


def _auth_headers(token: str, accept: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": accept}


MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
ACCEPT = ", ".join([MANIFEST_LIST, MANIFEST_V2, OCI_INDEX, OCI_MANIFEST])


def get_manifest(repo: str, ref: str, token: str):
    """Fetch manifest; follow a manifest list to the local platform.
    Returns (digest, manifest_dict). Verifies sha256 of the body."""
    url = f"https://{DOCKER_REG}/v2/{repo}/manifests/{ref}"
    st, hdrs, body = _http("GET", url, _auth_headers(token, ACCEPT))
    if st != 200:
        raise OCIError(f"manifest fetch failed: HTTP {st} {body[:120]}")
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    hdr_digest = hdrs.get("Docker-Content-Digest") or hdrs.get(
        "docker-content-digest")
    if hdr_digest and hdr_digest != digest:
        raise OCIError(f"manifest digest mismatch: header {hdr_digest} != computed {digest}")
    man = json.loads(body)
    if man.get("mediaType") in (MANIFEST_LIST, OCI_INDEX):
        plat = _local_platform()
        for m in man["manifests"]:
            p = m.get("platform", {})
            if (p.get("architecture"), p.get("os")) == plat:
                return get_manifest_by_digest(repo, m["digest"], token)
        raise OCIError(f"no manifest for platform {plat}")
    return digest, man


def get_manifest_by_digest(repo: str, digest: str, token: str):
    url = f"https://{DOCKER_REG}/v2/{repo}/manifests/{digest}"
    st, hdrs, body = _http("GET", url, _auth_headers(token, ACCEPT))
    if st != 200:
        raise OCIError(f"manifest-by-digest failed: HTTP {st}")
    if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
        raise OCIError("manifest digest mismatch on pull-by-digest")
    return digest, json.loads(body)


def _local_platform():
    import platform
    arch = platform.machine()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    return (arch, "linux")


def get_blob(repo: str, digest: str, token: str, dest: str,
             progress=None) -> str:
    """Download a blob, streaming, verifying sha256. Returns dest path."""
    algo, _, hexd = digest.partition(":")
    if algo != "sha256":
        raise OCIError(f"unsupported digest algo: {algo}")
    url = f"https://{DOCKER_REG}/v2/{repo}/blobs/{digest}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    h = hashlib.sha256()
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        total = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            f.write(chunk)
            total += len(chunk)
            if progress:
                progress(total)
    if h.hexdigest() != hexd:
        raise OCIError(f"blob digest mismatch for {digest}")
    return dest


def parse_repo_ref(image: str):
    """Split 'repo[:tag]' / 'registry/repo[:tag]' into (registry, repo, ref)."""
    if "://" in image:
        image = image.split("://", 1)[1]
    parts = image.split("/")
    if len(parts) == 1 or ("." not in parts[0] and ":" not in parts[0]
                           and parts[0] != "localhost"):
        registry, rest = DOCKER_REG, image
        if "/" not in rest:
            rest = "library/" + rest
    else:
        registry, rest = parts[0], "/".join(parts[1:])
    if ":" in rest.rsplit("/", 1)[-1]:
        rest, ref = rest.rsplit(":", 1)
    else:
        ref = "latest"
    return registry, rest, ref


def pull(image: str, destdir: str, progress=None):
    """Pull an image into destdir: manifest.json, config, layer tars.
    Returns dict with digest, manifest, config, layer_paths."""
    registry, repo, ref = parse_repo_ref(image)
    if registry != DOCKER_REG:
        raise OCIError("this client only speaks registry-1.docker.io")
    os.makedirs(destdir, exist_ok=True)
    token = registry_token(registry, repo)
    digest, man = get_manifest(repo, ref, token)
    cfg_digest = man["config"]["digest"]
    cfg_path = os.path.join(destdir, "config.json")
    get_blob(repo, cfg_digest, token, cfg_path)
    config = json.load(open(cfg_path))
    layer_paths = []
    for i, lyr in enumerate(man["layers"]):
        lp = os.path.join(destdir, f"layer-{i}.tar.gz")
        get_blob(repo, lyr["digest"], token, lp,
                 progress=(lambda n, i=i: progress(i, n)) if progress else None)
        layer_paths.append(lp)
    json.dump({"digest": digest, "manifest": man},
              open(os.path.join(destdir, "manifest.json"), "w"), indent=1)
    return {"digest": digest, "manifest": man, "config": config,
            "layer_paths": layer_paths, "repo": repo, "ref": ref}


# ---------------------------------------------------------------- layers

def _norm(p: str) -> str:
    # strip a leading ./ or / only — never bare leading dots (.dockerenv,
    # .wh.* whiteouts must keep theirs)
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if p.endswith("/") and len(p) > 1:
        p = p[:-1]
    return p


class FileTree:
    """Result of applying layers. nodes: path -> dict."""

    def __init__(self):
        self.nodes = {}  # norm path -> node dict

    def apply_member(self, m: "tar.TarMember", raw: bytes, layer_idx: int):
        name = _norm(m.name)
        if not name or name == ".":
            return None
        base = name.rsplit("/", 1)[-1]
        if base == ".wh..wh..opq":
            # opaque dir: drop all pre-existing children of the parent dir
            parent = name.rsplit("/", 1)[0] if "/" in name else ""
            prefix = parent + "/" if parent else ""
            for k in [k for k in self.nodes
                      if k != parent and k.startswith(prefix)]:
                del self.nodes[k]
            self.nodes.setdefault(parent or ".", _dirnode(m, layer_idx))
            return ("opaque", parent or "/")
        if base.startswith(".wh."):
            # whiteout: remove the named path recursively
            target = (name.rsplit("/", 1)[0] + "/" + base[4:]
                      if "/" in name else base[4:])
            removed = [k for k in self.nodes
                       if k == target or k.startswith(target + "/")]
            for k in removed:
                del self.nodes[k]
            return ("whiteout", target, len(removed))
        if m.isdir:
            self.nodes.setdefault(name, _dirnode(m, layer_idx))
            return ("dir", name)
        if m.issym:
            self.nodes[name] = {"kind": "symlink", "target": m.linkname,
                                "mode": m.mode, "layer": layer_idx,
                                "size": 0}
            return ("add", name)
        if m.ishard:
            self.nodes[name] = {"kind": "hardlink", "target": _norm(m.linkname),
                                "mode": m.mode, "layer": layer_idx, "size": 0}
            return ("add", name)
        if m.isreg:
            self.nodes[name] = {"kind": "file", "mode": m.mode,
                                "uid": m.uid, "gid": m.gid,
                                "size": m.size, "layer": layer_idx,
                                "sha256": hashlib.sha256(raw).hexdigest()}
            return ("add", name)
        return None


def _dirnode(m, layer_idx):
    return {"kind": "dir", "mode": m.mode, "layer": layer_idx, "size": 0}


def apply_layers(layer_paths) -> tuple:
    """Apply gzip'd layer tars in order. Returns (tree, per_layer_events)."""
    tree = FileTree()
    events = []
    for i, lp in enumerate(layer_paths):
        with open(lp, "rb") as f:
            raw_tar = gzip.decompress(f.read())
        members = tar.parse(raw_tar)
        ev = []
        for m in members:
            blob = raw_tar[m.data_off:m.data_off + m.size]
            r = tree.apply_member(m, blob, i)
            if r:
                ev.append(r)
        events.append(ev)
    return tree, events


def diff_layers(tree: FileTree, events) -> list:
    """Per-layer (added, modified, whiteouts, opaques) from event log.

    A file is 'modified' if it already existed in the tree when the layer
    wrote it; 'added' otherwise. Rebuild by replaying is exact here because
    apply_member already mutated the tree — so recompute from events only
    for whiteout counts and use tree node 'layer' fields for add/modify.
    """
    per = []
    for i, ev in enumerate(events):
        added = sum(1 for e in ev if e[0] == "add")
        whiteouts = [(e[1], e[2]) for e in ev if e[0] == "whiteout"]
        opaques = [e[1] for e in ev if e[0] == "opaque"]
        per.append({"layer": i, "writes": added,
                    "whiteouts": whiteouts, "opaques": opaques})
    # modified vs added: a write is a modify if an earlier layer wrote it
    seen = set()
    for i, ev in enumerate(events):
        mod = 0
        for e in ev:
            if e[0] == "add":
                if e[1] in seen:
                    mod += 1
                seen.add(e[1])
        per[i]["modified"] = mod
        per[i]["added"] = per[i]["writes"] - mod
    return per


# ---------------------------------------------------------------- dockerfile

def reconstruct_dockerfile(config: dict) -> list:
    """Best-effort Dockerfile from config.history (created_by strings)."""
    lines = []
    for h in config.get("history", []):
        if h.get("empty_layer"):
            continue
        cmd = (h.get("created_by") or "").strip()
        # strip the /bin/sh -c #(nop) prefixes docker records
        cmd = re.sub(r"^/bin/sh -c #\(nop\)\s*", "", cmd)
        cmd = re.sub(r"^/bin/sh -c\s+", "RUN ", cmd)
        if cmd.startswith("ADD file:"):
            lines.append("ADD <context> " + cmd.split(" in ", 1)[-1]
                         if " in " in cmd else cmd)
        elif cmd and not cmd.startswith("RUN "):
            lines.append(cmd if cmd[:1].isupper() else "RUN " + cmd)
        elif cmd:
            lines.append(cmd)
    return lines


# ---------------------------------------------------------------- triage

SECRET_RES = [
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}"), True),
    ("aws_secret", re.compile(rb"(?i)aws_secret[^=:\n]{0,20}[=:\s]+[A-Za-z0-9/+=]{20,}"), True),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY"), True),
    ("github_token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"), True),
    ("slack_token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"), True),
    ("generic_secret_assign", re.compile(
        rb"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^'\"\s]{4,}"), False),
]
# (regex tuple order: label, compiled, high_signal)
# under vendor paths only high-signal patterns run — source code and docs
# are full of words like "password=" that would drown real findings.

SKIP_SECRET_PATHS = ("usr/", "lib/", "bin/", "sbin/", "opt/")  # no leading /: _norm strips it


def collect_all_blobs(layer_paths, max_bytes=2 * 1024 * 1024):
    """Every layer's file blobs: {layer_idx: {path: bytes}}, hardlinks resolved
    within their own layer. For finding things a later layer tried to bury."""
    per_layer = {}
    for i, lp in enumerate(layer_paths):
        with open(lp, "rb") as f:
            raw_tar = gzip.decompress(f.read())
        content, hardlinks = {}, {}
        for m in tar.parse(raw_tar):
            name = _norm(m.name)
            if m.isreg and m.size and m.size <= max_bytes:
                content[name] = raw_tar[m.data_off:m.data_off + m.size]
            elif m.ishard:
                hardlinks[name] = _norm(m.linkname)
        for path, target in hardlinks.items():
            if target in content and path not in content:
                content[path] = content[target]
        per_layer[i] = content
    return per_layer


def scan_secrets(blobs: dict, vendor_only_high=True) -> list:
    """(path, label) hits in a {path: bytes} map. Text blobs only."""
    hits = []
    for path, blob in blobs.items():
        if not is_text_blob(blob):
            continue
        vendor = path.startswith(SKIP_SECRET_PATHS)
        for label, rx, high in SECRET_RES:
            if vendor and not high:
                continue
            if rx.search(blob):
                hits.append((path, label))
                break
    return hits


def triage(tree: FileTree, layer_blobs: dict, config: dict,
           all_blobs: dict = None) -> dict:
    """layer_blobs: final-tree path -> bytes. all_blobs (optional): output of
    collect_all_blobs — enables buried-secret detection across layers."""
    findings = {"secrets": [], "buried_secrets": [], "setuid": [],
                "setgid": [], "world_writable": [], "ssh_dirs": [],
                "extra_root_users": [], "big_files": [],
                "config_env_secrets": []}
    for path, label in scan_secrets(layer_blobs):
        findings["secrets"].append((path, label, tree.nodes[path]["layer"]))
    if all_blobs is not None:
        final = set(layer_blobs)
        for i, blobs in all_blobs.items():
            for path, label in scan_secrets(blobs):
                if path not in final:
                    findings["buried_secrets"].append((path, label, i))
    for path, node in tree.nodes.items():
        if node["kind"] in ("file", "hardlink"):
            mode = node.get("mode", 0)
            if mode & 0o4000:
                findings["setuid"].append(path)
            if mode & 0o2000:
                findings["setgid"].append(path)
            if mode & 0o002:
                findings["world_writable"].append(path)
            if node["size"] and node["size"] > 50 * 1024 * 1024:
                findings["big_files"].append((path, node["size"]))
        elif node["kind"] == "dir" and path.rsplit("/", 1)[-1] == ".ssh":
            findings["ssh_dirs"].append(path)
    # /etc/passwd extra uid-0 users
    pw = layer_blobs.get("etc/passwd")
    if pw:
        for line in pw.decode("utf-8", "replace").splitlines():
            f = line.split(":")
            if len(f) > 3 and f[2] == "0" and f[0] != "root":
                findings["extra_root_users"].append(f[0])
    # config env
    for e in (config.get("config") or {}).get("Env") or []:
        k, _, v = e.partition("=")
        if re.search(r"(?i)(key|secret|token|passw)", k) and v:
            findings["config_env_secrets"].append(k)
    return findings


def collect_blobs(tree: FileTree, layer_paths, max_bytes=2 * 1024 * 1024):
    """Map final-tree file paths -> content, for triage scanning.

    Two passes: first collect every regular file's bytes keyed by path,
    then resolve hardlinks to their target's bytes. Paths shadowed by a
    later whiteout are dropped — the applied tree is the truth."""
    content = {}
    hardlinks = {}  # path -> target path
    for i, lp in enumerate(layer_paths):
        with open(lp, "rb") as f:
            raw_tar = gzip.decompress(f.read())
        for m in tar.parse(raw_tar):
            name = _norm(m.name)
            if m.isreg and m.size and m.size <= max_bytes:
                content[name] = raw_tar[m.data_off:m.data_off + m.size]
            elif m.ishard:
                hardlinks[name] = _norm(m.linkname)
    for path, target in hardlinks.items():
        if path in tree.nodes and target in content and path not in content:
            content[path] = content[target]
    return {p: c for p, c in content.items()
            if p in tree.nodes and tree.nodes[p]["kind"] in ("file", "hardlink")}


def is_text_blob(blob: bytes, sample: int = 4096) -> bool:
    """Heuristic: secrets live in text. Skip binaries (NUL in the sample)."""
    return b"\x00" not in blob[:sample]
