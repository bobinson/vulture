"""Deterministic, offline diagnostics for the audit pipeline.

Nothing here calls a model or the network. These tools exist so a claim about the
pipeline can be checked by inspecting an artefact rather than by running a
non-reproducible tier and hoping the difference is the fix.
"""
