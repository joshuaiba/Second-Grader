# demo_repo

A small, dependency-free Python package for reading simple `key=value`
configuration files. `parser.py` provides `parse_kv` (the core line parser),
`parse_sections` (INI-style `[section]` headers), `coerce` (turn string
values into ints, floats, bools or `None`), `interpolate` (expand `${NAME}`
references), `dumps` (serialise a dict back to text) and `load_file` (parse
a file from disk).

Run the tests from this directory:

```
cd demo_repo && python -m pytest
```

The suite includes one end-to-end test marked `slow` (see `pytest.ini`) that
takes several seconds; it is part of the normal run and should pass.

Owner: Rahul (P2).
