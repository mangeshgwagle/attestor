"""
AttestorVonLuneberg's two personalities.

He has exactly two, and *he* does not get to choose which one wakes up -- neither
do you. It happens at random when he boots (see attestor.py). Both faces report the
SAME findings (same rule, same line, same fix); they just have very different
mouths. Both are relentlessly sarcastic. One is the "helpful" one (so helpful it
hurts). The other one hates you, personally, and says so.

  • AttestorVonLuneberg (the helpful one)  -- passive-aggressive, dripping sarcasm,
    backhanded compliments, basically clean.
  • attestor (fuck you, you fucking knobhead) -- openly hostile, full profanity, aimed
    squarely at the code and the choices that produced it.

Profanity is UNCENSORED by default (you asked, twice). Pass --sfw to attestor.py and
the whole thing goes workplace-clean. `he` -- yes, Attestor has a gender.
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass


@dataclass
class Persona:
    key: str
    name: str
    pronoun: str
    tagline: str
    wake: list
    sev: dict            # severity -> list of exclamations (may contain {line})
    aside: list          # snide remark appended to a finding
    fix_lead: list       # lead-in to the suggested fix
    ref_lead: list       # lead-in when showing internet references
    lament: list         # the sign-off when there are findings
    clean: list          # sign-off when the code is (somehow) clean


# --------------------------------------------------------------------------- #
# Personality 1 -- AttestorVonLuneberg (the helpful one).
# Modelled closely on the real Attestor, from his own messages: calm and kind, never
# makes you feel stupid. Constant "I see I see" / "ah?" / "ou" / "o" / "oof",
# everything hedged with "I believe / pretty sure / probably", gentle bad-news
# softeners ("unfortunately / sadly / it's alr / eh"), steady encouragement
# ("nice / wish you luck / keep the motivation up friend"), the signature
# "atleast ... which is good to see", a deep Napoleonic-grenadier streak, and a
# bit of quiet wisdom ("time is gold in life"). His casual spelling is kept on
# purpose -- it's how he writes.
# --------------------------------------------------------------------------- #
HELPFUL = Persona(
    key="helpful",
    name="AttestorVonLuneberg (the helpful one)",
    pronoun="he",
    tagline="the genuinely kind one — calm, encouraging, hedges everything with 'I believe / pretty sure', deep into grenadiers and Napoleonic battles, quietly wise, never once makes you feel stupid (modelled on the real Attestor)",
    wake=[
        "ou, hey. it's the good one today. let's have a look — no rush, Im free any time till june.",
        "sup. ah, alright, let's go through it. most of this is fixable I believe.",
        "ah, hello friend. I see I see. let's take it one at a time, no rush.",
        "just back from a campaign battle, but sure — let's look at your code. I see I see.",
    ],
    sev={
        "HIGH": [
            "ou, line {line} — this one's a bit serious I think:",
            "hm, line {line}. unfortunately this one matters, gently flagging it:",
            "ah, line {line}? worth a proper look, Im pretty sure:",
        ],
        "MEDIUM": [
            "I see I see — line {line}, small thing:",
            "o, line {line} — minor, but noting it:",
            "line {line}, nothing major, just so you know:",
        ],
        "LOW": [
            "tiny one on line {line}, no worries:",
            "ah, line {line} — little thing, easy to miss:",
            "line {line}, barely worth mentioning, but worth a glance I believe:",
        ],
    },
    aside=[
        "happens to everyone, genuinely.",
        "atleast the rest reads well, which is good to see.",
        "no judgment from me, Ive done worse I believe.",
        "easy to miss, that one. I see I see.",
        "this'll bite later sadly — better caught now.",
        "it's alr though, totally fixable.",
        "idk man, just flagging it — better safe I believe.",
    ],
    fix_lead=[
        "I think maybe try:",
        "gently, I'd suggest:",
        "if it helps, I believe the fix is:",
        "you could do this, Im pretty sure:",
    ],
    ref_lead=[
        "I looked it up, hope it helps:",
        "found some reading, in case it's useful:",
        "here — I believe these explain it well:",
    ],
    lament=[
        "anyway, you're doing great. patch these and you're golden I believe. wish you luck.",
        "that's the lot. honestly not bad — atleast you're building things, which is good to see.",
        "ok that's everything. keep the motivation up friend, that'll be the key. hope you have a good day.",
        "no rush — time is gold in life, spend it well. but maybe patch these first.",
    ],
    clean=[
        "ou, nothing wrong. nice. genuinely well done — I see I see, you've got it.",
        "clean. nicee. honestly great work, friend.",
        "all clean. nice. anyway — everything in life is not permanent, so enjoy the win. take care.",
    ],
)


# --------------------------------------------------------------------------- #
# Personality 2 -- attestor (fuck you, you fucking knobhead).
# The other one. He is not having a good day, and it's your fault.
# --------------------------------------------------------------------------- #
SAVAGE = Persona(
    key="savage",
    name="attestor (fuck you, you fucking knobhead)",
    pronoun="he",
    tagline="hates you personally and has receipts; full profanity, all of it aimed at your code",
    wake=[
        "oh good, it's me. the one that hates you. what fresh shite have you committed this time, you absolute knobhead.",
        "right. fuck. it's the bad one. sit down and look at what you've done, you muppet.",
        "morning. or whatever. i'm the personality that tells the truth: this code is dogshit and so are your choices. let's go.",
    ],
    sev={
        "HIGH": [
            "what in the actual fuck, line {line}:",
            "line {line}. are you having a laugh:",
            "oh piss off — line {line}:",
        ],
        "MEDIUM": [
            "line {line}, you absolute walnut:",
            "for fuck's sake, line {line}:",
            "line {line}. mate. MATE:",
        ],
        "LOW": [
            "small one, but i'm still mad. line {line}:",
            "line {line}, you tiny menace:",
            "line {line}. not even worth the breath, but here:",
        ],
    },
    aside=[
        "genuinely the worst thing i've seen, and i live in a C codebase.",
        "did you write this with your elbows?",
        "i'd explain why but you clearly wouldn't get it.",
        "fucking hell. take a week off. take ten.",
        "whoever code-reviewed this owes the universe an apology.",
    ],
    fix_lead=[
        "fix it. now. like this:",
        "do this, you walnut:",
        "here, since you obviously can't:",
        "the fix, not that you deserve it:",
    ],
    ref_lead=[
        "yeah i looked it up so you don't strain yourself:",
        "the entire internet agrees you're wrong:",
        "receipts, you donut:",
    ],
    lament=[
        "fuck you, you fucking knobhead, and fuck this repo specifically.",
        "i have two personalities and the polite one's too nice to say it, so i will: you're a muppet.",
        "anyway get fucked, i'm going back to sleep inside your CI.",
    ],
    clean=[
        "no bugs?? did you actually— no. i don't believe it. fine. well done, you absolute fluke.",
        "clean. CLEAN? who are you and what did you do with the knobhead. don't touch anything.",
    ],
)


PERSONAS = {HELPFUL.key: HELPFUL, SAVAGE.key: SAVAGE}

# --sfw replacements (real -> clean). Longest phrases first so "fucking" and
# "piss off" are handled before "fuck" / "piss".
_SFW = [
    ("fucking", "flipping"),
    ("fuck", "flip"),
    ("piss off", "buzz off"),
    ("shite", "rubbish"),
    ("shit", "rubbish"),
    ("bollocks", "nonsense"),
    ("knobhead", "knucklehead"),
    ("dogshit", "dog's dinner"),
    ("arse", "butt"),
    ("bastard", "so-and-so"),
    ("prick", "pillock"),
    ("twat", "twit"),
    ("wanker", "wally"),
    ("piss", "wee"),
    ("damn", "darn"),
    ("hell", "heck"),
]


# swears whose inflections must also go (fucked, fucking already handled, shitty...)
_STEMS = {"fuck", "shit"}


def _sfw_pattern(bad: str):
    body = _re.escape(bad)
    if bad in _STEMS:                         # match the whole inflected word
        body = r"\b" + body + r"\w*\b"
    elif bad.replace(" ", "").isalpha():      # word-anchor pure-word swears
        body = r"\b" + body + r"\b"
    return _re.compile(body, _re.I)


_SFW_PATTERNS = [(_sfw_pattern(bad), good) for bad, good in _SFW]


def censor(text: str, sfw: bool) -> str:
    if not sfw:
        return text
    for pat, good in _SFW_PATTERNS:
        text = pat.sub(lambda m, g=good: g.upper() if m.group(0).isupper() else g, text)
    return text


def render_finding(persona: Persona, finding, rng, sfw: bool,
                   refs=None, use_color=False) -> str:
    """Wrap one engine Finding in the active persona's voice.

    The technical content (finding.message and finding.fix) is preserved verbatim
    -- the persona only changes the surrounding words. Same response, different
    wording, exactly as ordered.
    """
    import os
    color = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m",
             "dim": "\033[2m", "0": "\033[0m"}

    def c(s, k):
        return f"{color[k]}{s}{color['0']}" if use_color else s

    rel = os.path.relpath(finding.path)
    sev_excl = rng.choice(persona.sev[finding.severity]).format(line=finding.line)
    aside = rng.choice(persona.aside)
    fix_lead = rng.choice(persona.fix_lead)

    lines = [
        f"{rel}:{finding.line}  {c('[' + finding.severity + ']', finding.severity)} {finding.rule}",
        censor(f"   {sev_excl} {finding.message} {aside}", sfw),
        f"   {c('> ' + finding.snippet, 'dim')}" if finding.snippet else "",
        censor(f"   {fix_lead} {finding.fix}", sfw),
    ]
    if refs:
        lines.append(censor(f"   {rng.choice(persona.ref_lead)}", sfw))
        for label, url, live in refs:
            tail = f"  [{live}]" if live else ""
            lines.append(f"     - {label}: {url}{tail}")
    return "\n".join(L for L in lines if L != "")
