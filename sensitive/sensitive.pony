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
