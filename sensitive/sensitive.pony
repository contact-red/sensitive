"""
A package to help you manage sensitive data.

A common pattern we see while doing security audits is that programmers will
unintentionally output sensitive data to logfiles, or other destinations
where it may not be appropriate to write to. The purpose of this package is
to provide a mechanism to "tag" sensitive variables in such a way that
accessing them becomes a deliberate act, and simply calling .string() will
return "[REDACTED]".

Applications are commonly handed their secrets through environment variables
or a `.env` file. [EnvSecrets](sensitive-EnvSecrets.md) holds both and returns
each value as a Sensitive[String], so the environment is read once, at
startup. [ReadEnvSecrets](sensitive-ReadEnvSecrets.md) builds one from a `.env`
file and the environment together, where an environment variable overrides the
`.env` file.

What this package does not do: it keeps a value out of string output, and
nothing more. A wrapped value is an ordinary string on the heap, not pinned,
not encrypted, and not overwritten when it is collected, so it is still
readable in a core dump or by a debugger attached to the process. Reading a
`.env` file holds its whole contents in memory for the length of the call.
Use it to stop a secret reaching a log; do not rely on it against an attacker
who can already read the process.

Documentation: [https://sensitive.contact.red/](https://sensitive.contact.red/)
"""

class val Sensitive[A: Stringable val]
  """
  Wraps a sensitive value so that printing it gives `[REDACTED]` and reading
  the value takes a deliberate call.
  """
  let _value: A

  new val create(value: A) =>
    _value = value

  fun expose(): A =>
    """
    The wrapped value. Every use of a sensitive value goes through this, so a
    search for `expose` finds them all.
    """
    _value

  fun string(): String iso^ =>
    """
    `"[REDACTED]"`, whatever the wrapped value is.
    """
    "[REDACTED]".clone()
