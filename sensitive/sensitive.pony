"""
A package to help you manage sensitive data.

A common pattern we see while doing security audits is that programmers will
unintentionally output sensitive data to logfiles, or other destinations
where it may not be appropriate to write to. The purpose of this package is
to provide a mechanism to "tag" sensitive variables in such a way that
accessing them becomes a deliberate act, and simply calling .string() will
return "[REDACTED]".

There is an additional helpful constructor which reads a specified
Environmental Variable into a Sensitive[String], a very common pattern
when passing sensitive data into applications.

Documentation: [https://sensitive.contact.red/](https://sensitive.contact.red/)
"""

class val Sensitive[A: Stringable val]
  """
  Wraps a sensitive value so it never appears in logs or string output.

  `.string()` always returns `"[REDACTED]"`.
  `.expose()` returns the underlying value — call it deliberately.
  """
  let _value: A

  new val create(value: A) =>
    _value = value

  new val from_env(vars: Array[String] val, name: String) ? =>
    iftype A <: String val then
      _value = _lookup(vars, name)?
    else
      error
    end

  fun tag _lookup(vars: Array[String] val, name: String): String ? =>
    for v in vars.values() do
      let eqpos = v.find("=" where nth = 0)?
      if v.substring(0, eqpos) == name then
        return v.substring(eqpos + 1)
      end
    end
    error

  fun expose(): A =>
    _value

  fun string(): String iso^ =>
    "[REDACTED]".clone()
