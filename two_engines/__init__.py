"""two_engines - a two-engine decompiler witness provider.

Runs two independent open-source decompilers (Kuna and Ghidra) over the
same binary, identifies library functions with Function ID hashes and
BSim similarity against a harvested corpus, and emits an evidence-graded
record of where the two engines agree and where they disagree.

Apache-2.0. See README.md.
"""

__version__ = "0.1.0"
PROVIDER_ID = "two-engines"
