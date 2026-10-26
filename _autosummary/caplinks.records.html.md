# caplinks.records

Link records as JSON text in a store of text: a mapping from token to dict.

`CapabilityLinks` keeps its records in any `MutableMapping` of token to dict.
[`JsonRecords`](#caplinks.records.JsonRecords) makes one from a mapping of *text* (`<token>.json` to the JSON of
the record), and [`FileTexts`](#caplinks.records.FileTexts) is that text mapping over a local folder, written
atomically and readable by the owner only (a record holds a password hash). A host whose
text lives elsewhere (ssh, S3) passes its own mapping of text.

```pycon
>>> import tempfile
>>> from caplinks import CapabilityLinks
>>> links = CapabilityLinks(JsonRecords(FileTexts(tempfile.mkdtemp())))
>>> token = links.create({"doc": "d1"})["token"]
>>> links.status(token)[1]["doc"]
'd1'
```

### Classes

| [`FileTexts`](#caplinks.records.FileTexts)(folder)                                  | `{name: text}` over the files of one local folder (created on first write).   |
|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [`JsonRecords`](#caplinks.records.JsonRecords)(texts, \*[, valid, deletable, indent]) | `{token: dict}` over a mapping of text, `<token>.json` to its JSON.           |

### *class* caplinks.records.FileTexts(folder)

Bases: [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)

`{name: text}` over the files of one local folder (created on first write).

Names are plain file names (no path separator, no leading dot, no NUL); a name whose
file is a symlink out of the folder is missing. The folder is private (mode 0700:
the names are link tokens) and a write goes to a hidden temporary file (mode 0600)
that replaces the target, so a reader never sees half a record.

### *class* caplinks.records.JsonRecords(texts, , valid=None, deletable=True, indent=None)

Bases: [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)

`{token: dict}` over a mapping of text, `<token>.json` to its JSON.

A record that cannot be read, is not a JSON object, or fails `valid` raises
`KeyError`: the link is then missing (every failure closes the link). `valid`
takes the host’s own check of its fields. `deletable=False` refuses `del`: a
host that keeps a revoked link as a tombstone says so. `indent` pretty-prints.

The contract of `texts`: reading a missing name raises `KeyError`.
