# A deliberately buggy "real-world" Python module -- the kind of mistakes that
# actually ship in small/medium-company codebases. AttestorVonLuneberg finds them.
# (Do not import this; it is sample input for the detector.)
import sqlite3

# 1) hardcoded-secret: a live-looking API key committed to source control.
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"


# 2) py-mutable-default: `cart=[]` is created once and shared across every call.
def add_item(item, cart=[]):
    cart.append(item)
    return cart


# 3) py-sql-injection: the query is built with an f-string from user input.
def find_user(db, name):
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchone()


def process(user, charge):
    # 4) py-eq-none: should be `user is None`.
    if user == None:
        return
    # 5) py-eq-bool: matches only the literal True, not other truthy values.
    if user.active == True:
        charge(user)
    try:
        charge(user)
    # 6) py-bare-except + 7) py-except-pass: the failure is swallowed whole.
    except:
        pass


# 8) py-is-literal: identity comparison against an int literal (works by luck).
def classify(x):
    if x is 0:
        return "zero"
    return "nonzero"
