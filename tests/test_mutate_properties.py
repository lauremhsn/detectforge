"""Property-based tests for the mutation engine (Hypothesis).

These generalise the example tests in test_mutate.py: instead of one hand-picked command, they throw
hundreds of generated commands and capabilities at the engine and check the invariants that have to
hold for the mutation set to be trustworthy -- determinism, distinct/bounded output, and the two
behaviour-preserving round trips (reordering keeps the token multiset; recoding decodes back).
"""

import base64
import ipaddress
import string

from hypothesis import given, settings
from hypothesis import strategies as st

from detectforge.dataset.argfuscator import Capability
from detectforge.dataset.mutate import (
    MAX_PER_TRANSFORM,
    SPLIT_OF,
    _tokens,
    _verb_index,
    mutate_command,
    mutate_event,
)
from detectforge.schemas import Event

# deadline off: a slow CI box shouldn't flake a pure-function test on timing.
SETTINGS = settings(deadline=None, max_examples=200)

_NAME = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=6)
_BARE_VALUE = st.text(alphabet=string.ascii_letters + string.digits + "\\:._", min_size=1, max_size=8).filter(
    lambda s: not s.startswith(("/", "-"))
)
# A quoted value may hold spaces and flag-looking junk like "/create -x"; it must stay one token.
_QUOTED_VALUE = st.text(alphabet=string.ascii_letters + string.digits + " /-:\\._", max_size=12).map(
    lambda s: f'"{s}"'
)


@st.composite
def _flag_unit(draw):
    opt = draw(st.sampled_from(["/", "-"]))
    unit = f"{opt}{draw(_NAME)}"
    if draw(st.booleans()):
        unit += " " + draw(st.one_of(_BARE_VALUE, _QUOTED_VALUE))
    return unit


@st.composite
def commands(draw):
    binary = draw(st.sampled_from(["schtasks.exe", "reg.exe", "wmic.exe", "certutil.exe", "foo"]))
    parts = [binary]
    if draw(st.booleans()):
        parts.append(draw(_NAME))  # a verb token, e.g. reg export
    parts += draw(st.lists(_flag_unit(), max_size=6))
    return " ".join(parts)


@st.composite
def reorderable_commands(draw):
    # Three or more distinct flag units and no positional, so a real swap always happens.
    binary = draw(st.sampled_from(["schtasks.exe", "reg.exe", "wmic.exe"]))
    parts = [binary]
    if draw(st.booleans()):
        parts.append(draw(_NAME))
    parts += draw(st.lists(_flag_unit(), min_size=3, max_size=6, unique=True))
    return " ".join(parts)


@st.composite
def capabilities(draw, binary=None):
    return Capability(
        binary=binary or draw(st.sampled_from(["schtasks", "reg", "wmic", "certutil", "foo"])),
        option_chars=tuple(
            draw(st.lists(st.sampled_from(["/", "-", "\u2014", "\u2013"]), max_size=3, unique=True))
        ),
        quote_insertion=draw(st.booleans()),
        char_insertion=draw(st.booleans()),
        reorder=draw(st.booleans()),
        ip_to_hex=draw(st.booleans()),
        # keys stay alphabetic, as _parse_sed guarantees for real models.
        homoglyphs=draw(
            st.dictionaries(
                st.sampled_from(list("abcdeorsu")), st.sampled_from(["\u1d49", "\u1d43"]), max_size=3
            )
        ),
        shorthands=draw(st.dictionaries(_NAME, _NAME, max_size=2)),
    )


def _base_event(command: str) -> Event:
    return Event(
        event_id="t-b01",
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=command,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        label="attack",
        technique="T1053.005",
        transform="none",
        base_id="t-b01",
        split="tune",
    )


@given(commands(), capabilities())
@SETTINGS
def test_deterministic(command, cap):
    assert mutate_command(command, cap) == mutate_command(command, cap)


@given(commands(), capabilities())
@SETTINGS
def test_variants_are_distinct_bounded_and_not_the_original(command, cap):
    for variants in mutate_command(command, cap).values():
        assert command not in variants
        assert len(variants) == len(set(variants))
        assert len(variants) <= MAX_PER_TRANSFORM
        assert all(isinstance(v, str) for v in variants)


@given(
    st.text(
        alphabet=st.characters(blacklist_categories=("Cc", "Cs"), blacklist_characters="\n\r"),
        max_size=60,
    ),
    capabilities(),
)
@SETTINGS
def test_never_raises_on_arbitrary_text(command, cap):
    out = mutate_command(command, cap)
    assert isinstance(out, dict)
    assert all(isinstance(v, str) for vs in out.values() for v in vs)


@given(reorderable_commands(), capabilities())
@settings(deadline=None, max_examples=300)
def test_reordering_preserves_tokens_and_keeps_the_binary_fixed(command, cap):
    out = mutate_command(command, cap)
    original = _tokens(command)
    first_flag = (_verb_index(original) or 0) + 1
    assert out["reordering"]  # strategy guarantees a real swap
    for variant in out["reordering"]:
        toks = _tokens(variant)
        assert sorted(toks) == sorted(original)  # nothing invented or lost, quoted junk included
        assert toks[:first_flag] == original[:first_flag]  # image (and any verb) never moves


@given(st.text(alphabet=string.ascii_letters + string.digits + " ", min_size=1, max_size=20))
@SETTINGS
def test_powershell_recoding_round_trips(script):
    cap = Capability(binary="powershell")
    out = mutate_command(f'powershell.exe -Command "{script}"', cap)
    encoded = out["recoding"][0].split("-EncodedCommand ")[1].strip()
    assert base64.b64decode(encoded).decode("utf-16-le") == script


@given(st.integers(0, 255), st.integers(0, 255), st.integers(0, 255), st.integers(0, 255))
@SETTINGS
def test_ip_recoding_round_trips(a, b, c, d):
    ip = f"{a}.{b}.{c}.{d}"
    cap = Capability(binary="certutil", ip_to_hex=True)
    out = mutate_command(f"certutil -urlcache -f http://{ip}/x out", cap)
    packed = int(ipaddress.IPv4Address(ip))
    assert any(str(packed) in v for v in out["recoding"])
    assert any(f"0x{packed:08x}" in v for v in out["recoding"])


@given(commands(), capabilities())
@SETTINGS
def test_mutate_event_keeps_base_fields_and_unique_ids(command, cap):
    base = _base_event(command)
    events = mutate_event(base, cap)
    assert len({e.event_id for e in events}) == len(events)
    for e in events:
        assert e.base_id == "t-b01"
        assert e.event_id.startswith("t-b01-")
        assert e.transform != "none"
        assert e.split == SPLIT_OF[e.transform]
        assert e.command_line != command
        assert (e.label, e.technique, e.image) == (base.label, base.technique, base.image)
