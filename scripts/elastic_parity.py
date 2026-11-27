"""SIEM parity: does a real Elasticsearch fire on the same events as DetectForge's matcher?

DetectForge scores rules with its own Python implementation of Sigma matching, and exports each rule
as an Elastic Lucene query (pySigma, ECS field names). If the two disagree, a number measured here
would not hold in the SIEM. This script loads the attack library into Elasticsearch with an ECS
mapping like Elastic's own (executables also as a lowercase `.caseless` keyword, command lines as a
`wildcard` field), runs each rule's exported query, and compares, event by event, with the matcher.

    df scripts/elastic_parity.py --url http://localhost:9200            # the 27 community rules
    df scripts/elastic_parity.py --url http://localhost:9200 --approved data/runs/approved
                                                                        # plus approved agent rules
Start Elasticsearch locally with:
    docker run -d -p 9200:9200 -e discovery.type=single-node -e xpack.security.enabled=false \\
        docker.elastic.co/elasticsearch/elasticsearch:8.15.3
In CI it runs against an Elasticsearch service container (.github/workflows/nightly.yml).
Lives outside the package, so the code fingerprint in each run's setup key is unchanged.
"""

import argparse
import contextlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from detectforge.events import load_events
from detectforge.harness import run
from detectforge.reference.index import ReferenceIndex
from detectforge.rules.convert import convert_rule
from detectforge.rules.parse import RuleError
from detectforge.schemas import Event

INDEX = "detectforge-parity"
_KEYWORD_CASELESS = {
    "type": "keyword",
    "fields": {"caseless": {"type": "keyword", "normalizer": "lowercase"}},
}
MAPPING = {
    "settings": {
        "analysis": {"normalizer": {"lowercase": {"type": "custom", "filter": ["lowercase"]}}},
        "number_of_replicas": 0,
    },
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "process": {
                "properties": {
                    "executable": _KEYWORD_CASELESS,
                    "command_line": {"type": "wildcard"},
                    "pe": {"properties": {"original_file_name": {"type": "keyword"}}},
                    "parent": {
                        "properties": {"executable": _KEYWORD_CASELESS, "command_line": {"type": "wildcard"}}
                    },
                }
            },
        }
    },
}


def doc_of(event: Event) -> dict:
    """An event as an ECS document (the fields pySigma's ecs_windows pipeline queries)."""
    process: dict = {"executable": event.image, "command_line": event.command_line}
    if event.original_file_name:
        process["pe"] = {"original_file_name": event.original_file_name}
    parent: dict = {"executable": event.parent_image}
    if event.parent_command_line:
        parent["command_line"] = event.parent_command_line
    process["parent"] = parent
    return {"event_id": event.event_id, "process": process}


def _call(url: str, method: str = "GET", body: dict | str | None = None) -> dict:
    data = None
    headers = {"Content-Type": "application/json"}
    if isinstance(body, str):
        data, headers["Content-Type"] = body.encode(), "application/x-ndjson"
    elif body is not None:
        data = json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def wait_for(url: str, seconds: int = 120) -> None:
    deadline = time.time() + seconds
    while True:
        try:
            _call(f"{url}/_cluster/health?wait_for_status=yellow&timeout=5s")
            return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if time.time() > deadline:
                raise SystemExit(f"Elasticsearch did not answer at {url}") from None
            time.sleep(3)


def load_index(url: str, events: list[Event]) -> None:
    with contextlib.suppress(urllib.error.HTTPError):
        _call(f"{url}/{INDEX}", "DELETE")
    _call(f"{url}/{INDEX}", "PUT", MAPPING)
    lines = []
    for e in events:
        lines += [json.dumps({"index": {"_index": INDEX, "_id": e.event_id}}), json.dumps(doc_of(e))]
    result = _call(f"{url}/_bulk?refresh=true", "POST", "\n".join(lines) + "\n")
    if result.get("errors"):
        raise SystemExit("bulk load reported errors")


def elastic_hits(url: str, query: str) -> set[str]:
    body = {"query": {"query_string": {"query": query}}, "size": 10000, "_source": ["event_id"]}
    result = _call(f"{url}/{INDEX}/_search", "POST", body)
    return {h["_source"]["event_id"] for h in result["hits"]["hits"]}


def compare(name: str, rule_yaml: str, events: list[Event], url: str) -> dict:
    ours = set(run(rule_yaml, events).matched_event_ids)
    try:
        queries = convert_rule(rule_yaml, "lucene")
    except RuleError as e:
        return {"rule": name, "error": str(e)}
    theirs: set[str] = set()
    for q in queries:
        theirs |= elastic_hits(url, q)
    return {
        "rule": name,
        "ours": len(ours),
        "elastic": len(theirs),
        "only_ours": sorted(ours - theirs),
        "only_elastic": sorted(theirs - ours),
    }


def summary(results: list[dict], events: dict[str, Event]) -> str:
    agree = [r for r in results if "error" not in r and not r["only_ours"] and not r["only_elastic"]]
    lines = [
        "## SIEM parity: DetectForge's matcher vs a real Elasticsearch",
        "",
        f"- Rules compared: {len(results)}; identical on every event: **{len(agree)}**",
    ]
    for r in results:
        if "error" in r:
            lines.append(f"- {r['rule']}: could not convert ({r['error'][:120]})")
        elif r["only_ours"] or r["only_elastic"]:
            lines.append(f"- {r['rule']}: matcher {r['ours']} · Elastic {r['elastic']}")
            for side, ids in (("only our matcher", r["only_ours"]), ("only Elastic", r["only_elastic"])):
                for i in ids[:4]:
                    lines.append(f"  - {side}: `{events[i].command_line[:110]}` ({events[i].transform})")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--url", default="http://localhost:9200")
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    p.add_argument("--approved", type=Path, help="also compare the approved agent rules in this folder")
    p.add_argument("--json", type=Path, help="save the per-rule results here")
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    events = [e for path in sorted((args.data_dir / "eval").glob("*.jsonl")) for e in load_events(path)]
    wait_for(args.url)
    load_index(args.url, events)
    selection = yaml.safe_load((args.data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))
    by_id = {r.id: r for r in ReferenceIndex.load(args.data_dir / "sigmahq").rules}
    rules = [
        (f"community: {r['title']}", by_id[r["id"]].rule_yaml) for r in selection["rules"] if r["id"] in by_id
    ]
    if args.approved and args.approved.exists():
        rules += [
            (f"approved: {p.stem[:8]}", p.read_text(encoding="utf-8"))
            for p in sorted(args.approved.glob("*.yml"))
        ]
    results = [compare(name, text, events, args.url) for name, text in rules]
    text = summary(results, {e.event_id: e for e in events})
    print(text)
    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    if out := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(out, "a", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
