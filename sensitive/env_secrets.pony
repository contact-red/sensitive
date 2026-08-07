use "collections"
use "files"

primitive DotEnvUnreadable
  """
  A `DotEnvError` reported when a file is at the given path but its contents
  could not be read. The `FilePath` may deny `FileRead` or `FileStat`, the
  filesystem permissions may deny it, the path may not name a regular file,
  the file may be larger than `ReadEnvSecrets` will read, or the read may have
  returned less than the whole file. Which of those it was is not reported.
  """
  fun string(): String iso^ =>
    "the .env file could not be read".clone()

class val DotEnvMalformed
  """
  A `DotEnvError` reported for a line that is neither blank, nor a comment,
  nor a `NAME=VALUE` pair. One such line discards the whole file: no entry
  from it reaches the caller, including the entries that did parse.

  The offending line is deliberately not carried: a malformed line is often a
  secret with a formatting mistake, so putting its text in an error puts the
  secret somewhere it can be printed. Report the number rather than the line.
  """
  let line_number: USize
    """
    The 1-based number of the offending line. Blank and comment lines are
    counted, so it matches what an editor shows.
    """

  new val _create(line_number': USize) =>
    line_number = line_number'

  fun string(): String iso^ =>
    "line " + line_number.string() + " of the .env file is malformed"

type DotEnvError is (DotEnvUnreadable | DotEnvMalformed)
  """
  The reasons a `.env` file cannot be used. Both mean secrets the file was
  meant to supply are absent, so neither is safe to carry on from. Both
  describe themselves, so a caller can report one without matching on it.

  A path with no file at it is not one of them. `ReadEnvSecrets` reports that
  as success and returns the process environment alone: a `.env` file is a
  development convenience, and a deployed application is normally handed its
  secrets by the environment.
  """

primitive ReadEnvSecrets
  """
  Read a `.env` file and the process environment into an `EnvSecrets`.

  A path with no file at it is not an error: the result is an `EnvSecrets`
  holding the environment alone. A file that is there but cannot be read, or
  that has a malformed line, is a `DotEnvError`, and neither is safe to carry
  on from.

  Call this once at startup. It reads the file synchronously, so the calling
  actor's scheduler thread waits for the disk.

  Reading the file needs `FileRead` and `FileStat` on `dotenv`. A relative
  path resolves against the working directory, so pass an absolute path when
  that directory is not trusted. A file larger than 1 MiB is not read.

  An environment variable overrides the `.env` file. When a name is set in
  both, the value from `vars` wins and the file's value is discarded, so the
  file supplies only the names the environment leaves unset. A `.env` file is
  a development convenience; that ordering keeps one from shadowing a secret
  a deployment supplies. Where one name is set twice in the same source, the
  first of them wins, which is what `getenv` returns for the environment.

  Names are matched exactly. On Windows, where the environment's own names are
  case-insensitive, a `.env` name that differs from an environment name only
  in case is a second name and is not overridden.

  Each line of the file is one of:

  * blank, or a comment beginning with `#`, both of which are ignored
  * `NAME=VALUE`, split at the first `=`

  A name is one or more letters, digits and underscores, not starting with a
  digit. Anything else is malformed, including the `export NAME=VALUE` that a
  shell would accept.

  Surrounding whitespace is removed from the name and from the value. A value
  wrapped in a matching pair of `"` or `'` has those quotes removed and keeps
  the whitespace inside them. Everything else is part of the value: there is
  no escaping, no `${...}` substitution, no value spanning two lines, and no
  comment after a value, so `A=b # note` binds `b # note`.

  An environment variable's value is taken verbatim instead, so the same text
  can mean different things depending on which source supplied it. `A=hunter2 `
  keeps its trailing space from the environment and loses it from the file.

  Nothing is written back into the process environment. A name read from the
  file is visible through the returned `EnvSecrets` and nowhere else, so it
  does not reach a subprocess.

  ```pony
  use "files"
  use "sensitive"

  actor Main
    new create(env: Env) =>
      let dotenv = FilePath(
        FileAuth(env.root),
        ".env",
        recover val FileCaps .> set(FileRead) .> set(FileStat) end)

      let secrets =
        match ReadEnvSecrets(env.vars, dotenv)
        | let s: EnvSecrets => s
        | let e: DotEnvError =>
          env.err.print(e.string())
          env.exitcode(1)
          return
        end

      try
        let password = secrets("DB_PASSWORD")?
        env.out.print("The password is " + password.string())
      else
        env.out.print("DB_PASSWORD is not set")
      end
  ```
  """
  fun apply(vars: Array[String] val, dotenv: FilePath)
    : (EnvSecrets | DotEnvError) =>
    """
    Read `dotenv` and `vars` into an `EnvSecrets`, or report why the file
    could not be used.
    """
    if not (dotenv.caps(FileRead) and dotenv.caps(FileStat)) then
      return DotEnvUnreadable
    end

    if not dotenv.exists() then
      return EnvSecrets(vars)
    end

    let file =
      match OpenFile(dotenv)
      | let f: File => f
      else
        return DotEnvUnreadable
      end

    let wanted = file.size()
    if wanted > _MaxDotEnvSize() then
      file.dispose()
      return DotEnvUnreadable
    end

    let content: String val = file.read_string(wanted)
    file.dispose()

    // read_string returns up to `wanted` bytes and reports a failure only
    // through errno, so a short read arrives looking like a whole file.
    if content.size() != wanted then
      return DotEnvUnreadable
    end

    _DotEnv.parse_all(content, vars)

primitive _MaxDotEnvSize
  fun apply(): USize => 1_048_576

class val EnvSecrets
  """
  Sensitive values supplied by the process environment and, optionally, a
  `.env` file.

  Build one from `Env.vars` at startup, and hand each component the values it
  needs. It is `val`, so it can be shared between actors, and every value it
  returns is already wrapped in a `Sensitive[String]`.

  Every environment value is wrapped, whether or not it is a secret, because
  which names are secret is not something this package can know. `PATH` and
  `LOG_LEVEL` come back as `Sensitive[String]` too, and exposing them costs
  the same deliberate act as exposing a password. Read ordinary configuration
  from `Env.vars` directly, so that a call to `expose` stays a signal.

  Use [ReadEnvSecrets](sensitive-ReadEnvSecrets.md) to take a `.env` file into
  account as well.

  ```pony
  use "sensitive"

  actor Main
    new create(env: Env) =>
      let secrets = EnvSecrets(env.vars)

      try
        let password = secrets("DB_PASSWORD")?
        env.out.print("The password is " + password.string())
      else
        env.out.print("DB_PASSWORD is not set")
      end
  ```
  """
  let _values: Map[String, Sensitive[String]] val

  new val create(vars: Array[String] val) =>
    """
    Read the `NAME=VALUE` entries of `vars`, which is `Env.vars` in the usual
    case. The value is everything after the first `=`, taken verbatim. An
    entry with no `=`, or with an empty name, is ignored. Where one name is
    set twice, the first of them wins, which is what `getenv` returns.
    """
    _values = _EnvVars(vars)

  new val _from_values(values: Map[String, Sensitive[String]] iso) =>
    _values = consume values

  fun apply(name: String): Sensitive[String] ? =>
    """
    The value bound to `name`. Raises an error if `name` is not bound.
    """
    _values(name)?

primitive _EnvVars
  """
  The `NAME=VALUE` entries of an environment, as a map. The value is taken
  verbatim, an entry with no `=` or an empty name is skipped, and the first of
  a repeated name wins.
  """
  fun apply(vars: Array[String] val): Map[String, Sensitive[String]] iso^ =>
    let values = recover Map[String, Sensitive[String]](vars.size()) end

    for entry in vars.values() do
      try
        let eq = entry.find("=")?.usize()
        // `trim` on a val shares the entry's bytes rather than copying them,
        // and name + "=" + value is the whole entry, so nothing extra is held.
        let name: String val = entry.trim(0, eq)
        if (name.size() > 0) and (not values.contains(name)) then
          values(name) = Sensitive[String](entry.trim(eq + 1))
        end
      end
    end

    consume values

primitive _DotEnv
  fun parse_all(content: String box, vars: Array[String] val)
    : (EnvSecrets | DotEnvMalformed) =>
    // The environment goes in first and nothing already bound is replaced, so
    // the environment wins over the file and the first of a repeated name
    // wins within each source.
    let values = _EnvVars(vars)

    let lines: Array[String] val = content.split_by("\n")
    var number: USize = 0

    for raw in lines.values() do
      number = number + 1

      let line: String ref = raw.clone()
      line.strip()

      if (line.size() > 0) and (not line.at("#")) then
        (let name: String val, let value: String val) =
          try
            parse(line)?
          else
            return DotEnvMalformed._create(number)
          end

        if not values.contains(name) then
          values(name) = Sensitive[String](value)
        end
      end
    end

    EnvSecrets._from_values(consume values)

  fun parse(line: String box): (String val, String val) ? =>
    // `line` must already be stripped: this removes whitespace between the
    // name and the `=` and between the `=` and the value, but not whitespace
    // at either end of the line.
    let eq = line.find("=")?

    let trimmed = line.substring(0, eq)
    trimmed.rstrip()

    let name: String val = consume trimmed
    if not _valid_name(name) then
      error
    end

    let value = line.substring(eq + 1)
    value.lstrip()

    (name, _unquote(consume value))

  fun _valid_name(name: String box): Bool =>
    var i: USize = 0

    while i < name.size() do
      let c = try name(i)? else return false end

      let ok =
        ((c >= 'A') and (c <= 'Z')) or
        ((c >= 'a') and (c <= 'z')) or
        (c == '_') or
        ((i > 0) and (c >= '0') and (c <= '9'))

      if not ok then
        return false
      end

      i = i + 1
    end

    name.size() > 0

  fun _unquote(quoted: String iso): String val =>
    let value = consume quoted

    if value.size() >= 2 then
      let last = (value.size() - 1).isize()
      if (value.at("\"") and value.at("\"", last))
        or (value.at("'") and value.at("'", last))
      then
        return value.substring(1, last)
      end
    end
    consume value
