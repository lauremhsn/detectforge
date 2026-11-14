import base64

import pytest

from detectforge.dataset.argfuscator import Capability, capability_from_model
from detectforge.dataset.mutate import SPLIT_OF, _tokens, mutate_command, mutate_event
from detectforge.schemas import TRANSFORMS, Event

SCHTASKS = Capability(binary="schtasks", option_chars=("-", "/"), quote_insertion=True, ip_to_hex=False)
POWERSHELL = Capability(binary="powershell", option_chars=("/", "-"), reorder=True)
REG = Capability(
    binary="reg",
    option_chars=("-", "/"),
    quote_insertion=True,
    char_insertion=True,
    homoglyphs={"e": "\u1d49"},
)


def base_event(command: str, image: str = "C:\\Windows\\System32\\schtasks.exe") -> Event:
    return Event(
        event_id="t-b01",
        image=image,
        command_line=command,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        label="attack",
        technique="T1053.005",
        transform="none",
        base_id="t-b01",
        split="tune",
    )


def test_tokenizer_keeps_quoted_value_with_space_as_one_token():
    assert _tokens('auditpol /set /category:"Account Logon" /success:disable') == [
        "auditpol",
        "/set",
        '/category:"Account Logon"',
        "/success:disable",
    ]


def test_substitution_swaps_option_char():
    out = mutate_command("schtasks /create /sc onlogon", SCHTASKS)
    assert "schtasks -create -sc onlogon" in out["substitution"]


def test_insertion_quotes_a_flag_name():
    out = mutate_command("schtasks /create /sc onlogon", SCHTASKS)
    assert any('/"create"' in v for v in out["insertion"])


def test_omission_drops_exe():
    out = mutate_command("schtasks.exe /create", SCHTASKS)
    assert "schtasks /create" in out["omission"]


def test_powershell_recoding_round_trips():
    out = mutate_command('powershell.exe -Command "Write-Host hi"', POWERSHELL)
    encoded = next(v for v in out["recoding"])
    b64 = encoded.split("-EncodedCommand ")[1].strip()
    assert base64.b64decode(b64).decode("utf-16-le") == "Write-Host hi"


def test_reordering_preserves_token_multiset():
    cmd = "schtasks /create /tn X /sc onlogon /tr Y"
    out = mutate_command(cmd, SCHTASKS)
    assert out["reordering"]
    for variant in out["reordering"]:
        assert sorted(_tokens(variant)) == sorted(_tokens(cmd))


def test_reordering_keeps_a_true_verb_fixed_and_skips_positionals():
    # `reg export HKLM\sam file` has a verb and positional args: not safe to reorder.
    reg_cmd = "reg export HKLM\\sam C:\\out\\sam"
    assert "reordering" not in mutate_command(reg_cmd, REG)


def test_reordering_needs_three_flag_units():
    # Only two flag units -> no safe swap that leaves the first (verb-like) flag in place.
    assert "reordering" not in mutate_command("auditpol /clear /y", Capability(binary="auditpol"))


def test_homoglyph_only_targets_a_real_verb():
    # schtasks has no verb token (first token after image is an option), so no homoglyph substitution.
    out = mutate_command("schtasks /create", REG)
    assert all("\u1d49" not in v for v in out.get("substitution", []))
    # reg export: the verb `export` is eligible.
    out = mutate_command("reg export HKLM\\sam", REG)
    assert any("\u1d49" in v for v in out["substitution"])


def test_unmodeled_binary_still_drops_exe_only():
    cap = Capability(binary="rundll32")
    out = mutate_command("rundll32.exe url.dll,OpenURL x", cap)
    assert set(out) == {"omission"}
    assert out["omission"] == ["rundll32 url.dll,OpenURL x"]


@pytest.mark.parametrize("transform", TRANSFORMS)
def test_split_assignment(transform):
    if transform == "none":
        assert transform not in SPLIT_OF
    else:
        assert SPLIT_OF[transform] in ("tune", "heldout")


def test_mutate_event_sets_ids_base_and_split():
    events = mutate_event(base_event("schtasks /create /sc onlogon"), SCHTASKS)
    assert events
    for e in events:
        assert e.base_id == "t-b01"
        assert e.event_id.startswith("t-b01-")
        assert e.command_line != "schtasks /create /sc onlogon"
        assert e.split == SPLIT_OF[e.transform]
    assert len({e.event_id for e in events}) == len(events)


def test_capability_from_model_reads_modifiers():
    model = {
        "profiles": [
            {
                "parameters": {
                    "modifiers": {
                        "OptionCharSubstitution": {"OutputOptionChars": ["-", "/"]},
                        "QuoteInsertion": {},
                        "Sed": {"SedStatements": "s/a/\u1d43/i\ns/encodedcommand/ec/i"},
                        "UrlTransformer": {"IpToHex": True},
                    }
                }
            }
        ]
    }
    cap = capability_from_model("demo", model)
    assert cap.option_chars == ("-", "/")
    assert cap.quote_insertion and cap.ip_to_hex
    assert cap.homoglyphs == {"a": "\u1d43"}
    assert cap.shorthands == {"encodedcommand": "ec"}
