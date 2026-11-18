"""A tiny, safe expression language for alert rules (no eval).

    cpu.percent > 90
    disk.*.percent > 85 and disk.*.percent <= 95
    service.*.up == 0
    check.ntp_synced == "no" or load.per_core > 2
    not (up == 1)

Names are metric keys. A `*` in a key is a wildcard: the rule is evaluated once
per target (mount point, service name ...) and every `*` in one rule binds to the
same target, so `disk.*.percent` produces one alert per mount.

Evaluation returns True / False, or None when a metric is missing ("no data"),
which the alert engine treats differently from False.
"""
import re
from dataclasses import dataclass

TOKEN_RE = re.compile(r"""
    \s*(?:
      (?P<num>-?\d+(?:\.\d+)?)
    | (?P<str>"[^"]*"|'[^']*')
    | (?P<op>==|!=|>=|<=|>|<)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<name>[A-Za-z_][A-Za-z0-9_./*:@-]*)
    )""", re.VERBOSE)
KEYWORDS = {"and", "or", "not"}
COMPARE = {
    "==": lambda a, b: a == b, "!=": lambda a, b: a != b,
    ">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
}


class ExprError(ValueError):
    pass


class NoData(Exception):
    pass


@dataclass(frozen=True)
class Node:
    kind: str            # num | str | key | cmp | and | or | not
    value: object = None
    left: "Node | None" = None
    right: "Node | None" = None


def tokenize(text: str) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise ExprError(f"Unexpected character at {pos}: {text[pos:pos + 10]!r}")
        kind = m.lastgroup
        value = m.group(kind)
        if kind == "name" and value in KEYWORDS:
            kind = value
        tokens.append((kind, value))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i = tokens, 0

    def peek(self):
        return self.tokens[self.i][0] if self.i < len(self.tokens) else None

    def take(self, kind=None):
        if self.i >= len(self.tokens):
            raise ExprError("Unexpected end of expression")
        tok = self.tokens[self.i]
        if kind and tok[0] != kind:
            raise ExprError(f"Expected {kind}, got {tok[1]!r}")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.or_()
        if self.i != len(self.tokens):
            raise ExprError(f"Unexpected {self.tokens[self.i][1]!r}")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == "or":
            self.take()
            node = Node("or", left=node, right=self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek() == "and":
            self.take()
            node = Node("and", left=node, right=self.not_())
        return node

    def not_(self):
        if self.peek() == "not":
            self.take()
            return Node("not", left=self.not_())
        return self.compare()

    def compare(self):
        left = self.atom()
        if self.peek() == "op":
            op = self.take()[1]
            right = self.atom()
            return Node("cmp", value=op, left=left, right=right)
        if left.kind != "cmp" and left.kind not in ("and", "or", "not"):
            raise ExprError("A bare value is not a condition; compare it, e.g. `up == 1`")
        return left

    def atom(self):
        kind, value = self.take()
        if kind == "num":
            return Node("num", float(value))
        if kind == "str":
            return Node("str", value[1:-1])
        if kind == "name":
            return Node("key", value)
        if kind == "lparen":
            node = self.or_()
            self.take("rparen")
            return node
        raise ExprError(f"Unexpected {value!r}")


def parse(text: str) -> Node:
    if not text or not text.strip():
        raise ExprError("Empty expression")
    return _Parser(tokenize(text)).parse()


def keys(node: Node) -> list[str]:
    """Metric keys used, in order of appearance (duplicates removed)."""
    found = []

    def walk(n):
        if n is None:
            return
        if n.kind == "key" and n.value not in found:
            found.append(n.value)
        walk(n.left)
        walk(n.right)
    walk(node)
    return found


def evaluate(node: Node, values: dict, target: str = "") -> bool | None:
    """True/False, or None if a needed metric is missing.

    Three-valued (Kleene) logic, like SQL NULL: `False and <no data>` is False and
    `True or <no data>` is True, because the missing part cannot change the result.
    Otherwise a missing metric gives None, which never resolves an alert by accident.
    """
    return _tri(node, values, target)


def _tri(node: Node, values: dict, target: str) -> bool | None:
    if node.kind == "and":
        left = _tri(node.left, values, target)
        if left is False:
            return False
        right = _tri(node.right, values, target)
        if right is False:
            return False
        return None if left is None or right is None else True
    if node.kind == "or":
        left = _tri(node.left, values, target)
        if left is True:
            return True
        right = _tri(node.right, values, target)
        if right is True:
            return True
        return None if left is None or right is None else False
    if node.kind == "not":
        inner = _tri(node.left, values, target)
        return None if inner is None else not inner
    try:
        return bool(_eval(node, values, target))
    except NoData:
        return None


def _eval(node: Node, values: dict, target: str):
    kind = node.kind
    if kind in ("num", "str"):
        return node.value
    if kind == "key":
        key = node.value.replace("*", target)
        if key not in values or values[key] is None:
            raise NoData(key)
        return values[key]
    if kind == "not":
        return not _eval(node.left, values, target)
    if kind == "and":
        # no data on either side => no data, so a missing metric never resolves an alert by accident
        left = _eval(node.left, values, target)
        right = _eval(node.right, values, target)
        return bool(left) and bool(right)
    if kind == "or":
        left = _eval(node.left, values, target)
        right = _eval(node.right, values, target)
        return bool(left) or bool(right)
    if kind == "cmp":
        a, b = _eval(node.left, values, target), _eval(node.right, values, target)
        if isinstance(a, str) != isinstance(b, str):
            if node.value in ("==", "!="):
                return COMPARE[node.value](str(a), str(b))
            raise NoData(f"cannot order {a!r} and {b!r}")
        return COMPARE[node.value](a, b)
    raise ExprError(f"Unknown node {kind}")


def wildcard_targets(node: Node, available_keys) -> set[str]:
    """All values `*` can take given the keys present in a sample."""
    patterns = [k for k in keys(node) if "*" in k]
    targets = set()
    for pattern in patterns:
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", "(.+?)") + "$")
        for key in available_keys:
            m = regex.match(key)
            if m and len(set(m.groups())) == 1:
                targets.add(m.group(1))
    return targets


def has_wildcard(node: Node) -> bool:
    return any("*" in k for k in keys(node))
