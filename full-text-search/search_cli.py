"""CLI: search_cli.py <index> "<query>" [--top N]"""
import sys
from index import Index
from query import search
from snippets import make_snippet


def main():
    args = sys.argv[1:]
    top = 5
    if "--top" in args:
        i = args.index("--top")
        top = int(args[i + 1])
        args = args[:i] + args[i + 2:]
    idx_path, q = args[0], args[1]
    ix = Index(idx_path)
    texts = {}
    for doc_id, score in search(ix, q, top_k=top):
        doc = ix.docs[doc_id]
        if doc["path"] not in texts:
            with open(doc["path"], encoding="utf-8", errors="replace") as f:
                texts[doc["path"]] = f.read()
        print(f"[{score:.2f}] {doc['title']}")
        print(f"   {make_snippet(texts[doc['path']], q)}")
        print()


if __name__ == "__main__":
    main()
