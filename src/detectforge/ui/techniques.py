"""What an ATT&CK technique id means, in words a non-specialist can follow.

"T1053.005" helps nobody who doesn't know ATT&CK by heart. Everywhere the UI shows a technique it
shows a plain name, the attacker goal (tactic) it serves, and an icon, with the id kept for experts.
The names are plain-language descriptions of the behaviour, not ATT&CK's official titles.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Goal:
    """An attacker goal (an ATT&CK tactic), as a person would say it."""

    key: str
    label: str
    icon: str
    color: str


GOALS = {
    "credential-access": Goal("credential-access", "Stealing credentials", "🔑", "#E11D48"),
    "execution": Goal("execution", "Running malicious code", "⚙️", "#F59E0B"),
    "persistence": Goal("persistence", "Staying on the machine", "📌", "#8B5CF6"),
    "privilege-escalation": Goal("privilege-escalation", "Gaining admin rights", "⬆️", "#EC4899"),
    "defense-evasion": Goal("defense-evasion", "Hiding from defenders", "🫥", "#06B6D4"),
    "stealth": Goal("stealth", "Hiding from defenders", "🫥", "#06B6D4"),
    "defense-impairment": Goal("defense-impairment", "Switching off defenses", "🛡️", "#14B8A6"),
    "command-and-control": Goal("command-and-control", "Bringing in tools", "📥", "#3B82F6"),
    "impact": Goal("impact", "Ransomware preparation", "💥", "#EF4444"),
}
OTHER = Goal("other", "Other", "•", "#64748B")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str  # plain language
    behaviour: str  # one line: what the attacker does
    goal: str  # main GOALS key


TECHNIQUES = {
    t.id: t
    for t in [
        Technique(
            "T1003.001",
            "Dumping LSASS memory",
            "copies the memory of the process that holds Windows logins",
            "credential-access",
        ),
        Technique(
            "T1003.002",
            "Dumping the SAM registry hive",
            "saves the registry hives that store local password hashes",
            "credential-access",
        ),
        Technique(
            "T1555.003",
            "Stealing browser passwords",
            "copies the browser's saved-credential databases",
            "credential-access",
        ),
        Technique(
            "T1027",
            "Hiding a download in a trusted tool",
            "abuses certutil to fetch a file past filters",
            "defense-evasion",
        ),
        Technique(
            "T1036.003",
            "Downloading with a built-in tool",
            "uses bitsadmin, a Windows updater, to fetch a payload",
            "defense-evasion",
        ),
        Technique(
            "T1218.005",
            "Running a remote script via mshta",
            "makes a signed Windows binary run a script from the internet",
            "defense-evasion",
        ),
        Technique(
            "T1218.007",
            "Installing from the internet via msiexec",
            "quietly installs a package straight from a URL",
            "defense-evasion",
        ),
        Technique(
            "T1218.010",
            "Running a remote script via regsvr32",
            "makes regsvr32 load a scriptlet from a URL",
            "defense-evasion",
        ),
        Technique(
            "T1218.011", "Running code via rundll32", "makes rundll32 run attacker code", "defense-evasion"
        ),
        Technique(
            "T1047",
            "Running programs through WMI",
            "starts processes through wmic, often remotely",
            "execution",
        ),
        Technique("T1059.001", "Malicious PowerShell", "runs encoded or downloaded PowerShell", "execution"),
        Technique("T1059.003", "Malicious command-shell scripts", "feeds a script to cmd.exe", "execution"),
        Technique(
            "T1053.005",
            "Persistence with scheduled tasks",
            "creates a task that reruns the malware",
            "persistence",
        ),
        Technique(
            "T1543.003",
            "Persistence with a new service",
            "installs a Windows service that runs the malware",
            "persistence",
        ),
        Technique("T1547.001", "Persistence with Run keys", "adds an autorun registry entry", "persistence"),
        Technique(
            "T1105",
            "Downloading attacker tools",
            "fetches tools with curl or Defender's own updater",
            "command-and-control",
        ),
        Technique(
            "T1490",
            "Deleting backups before ransomware",
            "deletes shadow copies and disables recovery",
            "impact",
        ),
        Technique(
            "T1685", "Switching off the antivirus", "stops or disables Windows Defender", "defense-impairment"
        ),
        Technique(
            "T1685.001",
            "Tampering with logs and auditing",
            "clears event logs or turns auditing off",
            "defense-impairment",
        ),
    ]
}


def technique(tid: str) -> Technique:
    return TECHNIQUES.get(tid) or Technique(tid, tid, "", "other")


def goal(tid: str) -> Goal:
    return GOALS.get(technique(tid).goal, OTHER)


def label(tid: str, with_id: bool = True) -> str:
    """'⚙️ Persistence with scheduled tasks (T1053.005)': for dropdowns, captions and headings."""
    t = technique(tid)
    if t.name == tid:
        return tid
    return f"{goal(tid).icon} {t.name}" + (f" ({tid})" if with_id else "")
