"""Build the index over a corpus of markdown files. Usage: build.py <corpus_dir> <out.idx>"""
import os
import sys
from index import IndexBuilder

SKIP = {"INDEX.md"}
# bank/ is runtime-managed mirror content (duplicates the curated notes);
# indexing it would double-count every fact and let the mirrors dominate.
SKIP_DIRS = {"bank"}


def main():
    corpus, out = sys.argv[1], sys.argv[2]
    b = IndexBuilder()
    paths = []
    for root, dirs, files in os.walk(corpus):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            if f.endswith(".md") and f not in SKIP:
                paths.append(os.path.join(root, f))
    # ~/MEMORY.md is the curated long-term memory; it lives beside, not under,
    # the corpus dir, so add it explicitly.
    memory_md = os.path.expanduser("~/MEMORY.md")
    if os.path.isfile(memory_md):
        paths.append(memory_md)
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        title = os.path.relpath(p, corpus)
        b.add_document(p, text, title=title)
    size = b.save(out)
    n_terms = len(b.postings)
    print(f"docs={len(b.docs)} unique_terms={n_terms} index_bytes={size}")


if __name__ == "__main__":
    main()
