use "files"
use "pony_test"
use "pony_check"

actor \nodoc\ Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)

  fun tag tests(test: PonyTest) =>
    test(Property1UnitTest[String](_PropertyExposeRoundtrip))
    test(Property1UnitTest[String](_PropertyStringAlwaysRedacted))
    test(Property1UnitTest[U64](_PropertyExposeRoundtripU64))
    test(Property1UnitTest[U64](_PropertyStringAlwaysRedactedU64))
    test(Property1UnitTest[String](_PropertyEnvRoundtrip))
    test(Property1UnitTest[String](_PropertyDotEnvQuotedRoundtrip))
    test(_TestEnvUnsetName)
    test(_TestEnvEntryWithoutEquals)
    test(_TestEnvEntryWithEmptyName)
    test(_TestEnvValueVerbatim)
    test(_TestEnvDuplicateNameFirstWins)
    test(_TestEnvValueContainsEquals)
    test(_TestEnvBeatsDotEnv)
    test(_TestDotEnvMissingFile)
    test(_TestDotEnvUnreadableFile)
    test(_TestDotEnvUnstattableFile)
    test(_TestDotEnvReadsFile)
    test(_TestDotEnvPathIsDirectory)
    test(_TestDotEnvSuppliesUnsetName)
    test(_TestDotEnvBlanksAndComments)
    test(_TestDotEnvWhitespaceTrimmed)
    test(_TestDotEnvQuotesStripped)
    test(_TestDotEnvQuotesKeptWhenUnmatched)
    test(_TestDotEnvCarriageReturns)
    test(_TestDotEnvValueContainsEquals)
    test(_TestDotEnvEmptyFile)
    test(_TestDotEnvNoTrailingNewline)
    test(_TestDotEnvDuplicateNameFirstWins)
    test(_TestDotEnvValueContainsHash)
    test(_TestDotEnvMultiLineValueIsMalformed)
    test(_TestDotEnvInvalidName)
    test(_TestDotEnvLineWithoutEquals)
    test(_TestDotEnvLineWithEmptyName)
    test(_TestDotEnvMalformedLineNumber)

primitive \nodoc\ _NoVars
  fun apply(): Array[String] val =>
    recover val Array[String] end

primitive \nodoc\ _DotEnvValues
  """
  Strings a `.env` file can carry: digits, letters, punctuation, and every
  whitespace byte other than the `\n` that ends an entry.
  """
  fun apply(): Generator[String] =>
    let alphabet: String val =
      ASCIIDigits() + ASCIILetters() + ASCIIPunctuation() + " \t\r\x0b\x0c"

    Generators.byte_string(
      Generators.usize(0, alphabet.size() - 1)
        .map[U8]({(i: USize)(alphabet): U8 =>
          try alphabet(i)? else ' ' end }))

primitive \nodoc\ _DotEnvSecrets
  """
  Parse `content` as a `.env` file together with `vars`, raising an error
  rather than reporting a `DotEnvMalformed`. No filesystem is involved: the
  tests that write a real file are the ones testing the read itself.
  """
  fun apply(vars: Array[String] val, content: String): EnvSecrets ? =>
    match _DotEnv.parse_all(content, vars)
    | let secrets: EnvSecrets => secrets
    else
      error
    end

class \nodoc\ iso _PropertyExposeRoundtrip is Property1[String]
  fun name(): String => "sensitive/expose roundtrips for String"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let s = Sensitive[String](arg1)
    ph.assert_eq[String](arg1, s.expose())

class \nodoc\ iso _PropertyStringAlwaysRedacted is Property1[String]
  fun name(): String => "sensitive/string is always [REDACTED] for String"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let s = Sensitive[String](arg1)
    let redacted: String val = s.string()
    ph.assert_eq[String]("[REDACTED]", redacted)

class \nodoc\ iso _PropertyExposeRoundtripU64 is Property1[U64]
  fun name(): String => "sensitive/expose roundtrips for U64"

  fun gen(): Generator[U64] =>
    Generators.u64()

  fun ref property(arg1: U64, ph: PropertyHelper) =>
    let s = Sensitive[U64](arg1)
    ph.assert_eq[U64](arg1, s.expose())

class \nodoc\ iso _PropertyStringAlwaysRedactedU64 is Property1[U64]
  fun name(): String => "sensitive/string is always [REDACTED] for U64"

  fun gen(): Generator[U64] =>
    Generators.u64()

  fun ref property(arg1: U64, ph: PropertyHelper) =>
    let s = Sensitive[U64](arg1)
    let redacted: String val = s.string()
    ph.assert_eq[String]("[REDACTED]", redacted)

class \nodoc\ iso _PropertyEnvRoundtrip is Property1[String]
  fun name(): String => "env_secrets/an env var value is exposed verbatim"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let vars: Array[String] val = ["MY_SECRET=" + arg1]
    try
      ph.assert_eq[String](arg1, EnvSecrets(vars)("MY_SECRET")?.expose())
    else
      ph.fail("MY_SECRET was not found")
    end

class \nodoc\ iso _PropertyDotEnvQuotedRoundtrip is Property1[String]
  fun name(): String => "env_secrets/a quoted .env value is exposed verbatim"

  fun gen(): Generator[String] =>
    _DotEnvValues()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    // Quoting is what preserves a value exactly: without it the surrounding
    // whitespace of a generated value is trimmed away.
    let content: String val = "MY_SECRET=\"" + arg1 + "\"\n"
    try
      let secrets = _DotEnvSecrets(_NoVars(), content)?
      ph.assert_eq[String](arg1, secrets("MY_SECRET")?.expose())
    else
      ph.fail("MY_SECRET was not read from the .env file")
    end

class \nodoc\ iso _TestEnvBeatsDotEnv is UnitTest
  fun name(): String => "env_secrets/an env var wins over the .env file"

  fun ref apply(h: TestHelper) =>
    // The environment's value is padded and the file's is quoted, so a parser
    // that took the file's entry, or that trimmed the environment's, fails.
    let vars: Array[String] val = ["MY_SECRET=  from-env  "]
    try
      let secrets = _DotEnvSecrets(vars, "MY_SECRET=\"from-file\"\n")?
      h.assert_eq[String]("  from-env  ", secrets("MY_SECRET")?.expose())
    else
      h.fail("MY_SECRET was not found")
    end

class \nodoc\ iso _TestEnvUnsetName is UnitTest
  fun name(): String => "env_secrets/an unset name raises an error"

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["OTHER=value"]
    try
      EnvSecrets(vars)("MISSING")?
      h.fail("MISSING should have raised an error")
    end

class \nodoc\ iso _TestEnvEntryWithoutEquals is UnitTest
  fun name(): String => "env_secrets/an env entry without = is ignored"

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["MALFORMED"; "GOOD=value"]
    try
      h.assert_eq[String]("value", EnvSecrets(vars)("GOOD")?.expose())
    else
      h.fail("GOOD was not found alongside a malformed entry")
    end

    try
      EnvSecrets(vars)("MALFORMED")?
      h.fail("MALFORMED should not be bound")
    end

class \nodoc\ iso _TestEnvEntryWithEmptyName is UnitTest
  fun name(): String => "env_secrets/an env entry with an empty name is ignored"

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["=orphan"; "GOOD=value"]
    try
      h.assert_eq[String]("value", EnvSecrets(vars)("GOOD")?.expose())
    else
      h.fail("GOOD was not found alongside an empty-name entry")
    end

    try
      EnvSecrets(vars)("")?
      h.fail("the empty name should not be bound")
    end

class \nodoc\ iso _TestEnvValueVerbatim is UnitTest
  fun name(): String => "env_secrets/an env value keeps its spaces and quotes"

  fun ref apply(h: TestHelper) =>
    // The .env parser trims and unquotes; the environment must not, or a
    // value that round-trips in development changes in deployment.
    let vars: Array[String] val =
      ["QUOTED=\"  spaced  \""; "PADDED=  value  "]
    try
      let secrets = EnvSecrets(vars)
      h.assert_eq[String]("\"  spaced  \"", secrets("QUOTED")?.expose())
      h.assert_eq[String]("  value  ", secrets("PADDED")?.expose())
    else
      h.fail("an env entry was not found")
    end

class \nodoc\ iso _TestEnvDuplicateNameFirstWins is UnitTest
  fun name(): String => "env_secrets/the first of a repeated env name wins"

  fun ref apply(h: TestHelper) =>
    // getenv returns the first, so this must agree with it.
    let vars: Array[String] val = ["MY_SECRET=first"; "MY_SECRET=second"]
    try
      h.assert_eq[String]("first", EnvSecrets(vars)("MY_SECRET")?.expose())
    else
      h.fail("MY_SECRET was not found")
    end

class \nodoc\ iso _TestEnvValueContainsEquals is UnitTest
  fun name(): String => "env_secrets/an env entry splits at the first ="

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["DSN=user=me;pass=secret"; "OTHER=plain"]
    try
      h.assert_eq[String]("plain", EnvSecrets(vars)("OTHER")?.expose())
      h.assert_eq[String](
        "user=me;pass=secret", EnvSecrets(vars)("DSN")?.expose())
    else
      h.fail("DSN was not found")
    end

class \nodoc\ iso _TestDotEnvMissingFile is UnitTest
  fun name(): String =>
    "env_secrets/a missing .env file returns the environment alone"

  fun ref apply(h: TestHelper) ? =>
    let dir = FilePath.mkdtemp(FileAuth(h.env.root), "sensitive")?
    let missing = FilePath.from(dir, ".env")?
    let vars: Array[String] val = ["MY_SECRET=from-env"]

    match ReadEnvSecrets(vars, missing)
    | let secrets: EnvSecrets =>
      try
        h.assert_eq[String]("from-env", secrets("MY_SECRET")?.expose())
      else
        h.fail("MY_SECRET was not read from the environment")
      end
    else
      h.fail("a missing .env file should not have reported a DotEnvError")
    end

    dir.remove()

class \nodoc\ iso _TestDotEnvUnstattableFile is UnitTest
  fun name(): String =>
    "env_secrets/a .env file that cannot be stat'ed reports DotEnvUnreadable"

  fun ref apply(h: TestHelper) ? =>
    let dir = FilePath.mkdtemp(FileAuth(h.env.root), "sensitive")?
    let path = FilePath.from(dir, ".env")?

    let file = File(path)
    h.assert_true(file.write("MY_SECRET=value\n"))
    file.dispose()

    // Without FileStat, FilePath.exists() is false for a file that is there,
    // so the read has to reject the path rather than read the environment
    // alone and report success.
    let unstattable = FilePath(
      FileAuth(h.env.root),
      path.path,
      recover val FileCaps .> all() .> unset(FileStat) end)

    match ReadEnvSecrets(_NoVars(), unstattable)
    | DotEnvUnreadable => None
    else
      h.fail("a .env file denying FileStat should have been unreadable")
    end

    dir.remove()

class \nodoc\ iso _TestDotEnvUnreadableFile is UnitTest
  fun name(): String =>
    "env_secrets/an unreadable .env file reports DotEnvUnreadable"

  fun ref apply(h: TestHelper) ? =>
    let dir = FilePath.mkdtemp(FileAuth(h.env.root), "sensitive")?
    let path = FilePath.from(dir, ".env")?

    let file = File(path)
    h.assert_true(file.write("MY_SECRET=value\n"))
    file.dispose()

    // Root ignores mode bits, so a mode of 000 would still be readable.
    // Denying FileRead on the FilePath is what makes the open fail.
    let unreadable = FilePath(
      FileAuth(h.env.root),
      path.path,
      recover val FileCaps .> all() .> unset(FileRead) end)

    match ReadEnvSecrets(_NoVars(), unreadable)
    | DotEnvUnreadable => None
    else
      h.fail("an unreadable .env file should have reported DotEnvUnreadable")
    end

    dir.remove()

class \nodoc\ iso _TestDotEnvReadsFile is UnitTest
  fun name(): String => "env_secrets/a .env file on disk is read"

  fun ref apply(h: TestHelper) ? =>
    // The parsing tests hand `_DotEnv.parse_all` a string, so this is the one
    // that proves the bytes make it off the disk and into an `EnvSecrets`.
    let dir = FilePath.mkdtemp(FileAuth(h.env.root), "sensitive")?
    let path = FilePath.from(dir, ".env")?

    let file = File(path)
    h.assert_true(file.write("MY_SECRET=from-file\n"))
    file.dispose()

    match ReadEnvSecrets(["OTHER=from-env"], path)
    | let secrets: EnvSecrets =>
      try
        h.assert_eq[String]("from-file", secrets("MY_SECRET")?.expose())
        h.assert_eq[String]("from-env", secrets("OTHER")?.expose())
      else
        h.fail("a name was not bound after reading the .env file")
      end
    else
      h.fail("a readable .env file should not have reported a DotEnvError")
    end

    dir.remove()

class \nodoc\ iso _TestDotEnvPathIsDirectory is UnitTest
  fun name(): String =>
    "env_secrets/a directory at the .env path reports DotEnvUnreadable"

  fun ref apply(h: TestHelper) ? =>
    // A directory exists and can be stat'ed, so only the open rejects it.
    let dir = FilePath.mkdtemp(FileAuth(h.env.root), "sensitive")?

    match ReadEnvSecrets(_NoVars(), dir)
    | DotEnvUnreadable => None
    else
      h.fail("a directory at the .env path should have been unreadable")
    end

    dir.remove()

class \nodoc\ iso _TestDotEnvSuppliesUnsetName is UnitTest
  fun name(): String => "env_secrets/the .env file supplies names the env lacks"

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["OTHER=value"]
    try
      let secrets = _DotEnvSecrets(vars, "MY_SECRET=from-file\n")?
      h.assert_eq[String]("from-file", secrets("MY_SECRET")?.expose())
      h.assert_eq[String]("value", secrets("OTHER")?.expose())
    else
      h.fail("MY_SECRET was not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvBlanksAndComments is UnitTest
  fun name(): String => "env_secrets/.env blank and comment lines are ignored"

  fun ref apply(h: TestHelper) =>
    let content: String val =
      "# a leading comment\n" +
      "\n" +
      "   \n" +
      "  # an indented comment\n" +
      "MY_SECRET=value\n"
    try
      let secrets = _DotEnvSecrets(_NoVars(), content)?
      h.assert_eq[String]("value", secrets("MY_SECRET")?.expose())
    else
      h.fail("blank and comment lines were not ignored")
    end

class \nodoc\ iso _TestDotEnvWhitespaceTrimmed is UnitTest
  fun name(): String => "env_secrets/.env trims around the name and the value"

  fun ref apply(h: TestHelper) =>
    try
      let secrets = _DotEnvSecrets(
        _NoVars(), "  MY_SECRET  =  value  \n")?
      h.assert_eq[String]("value", secrets("MY_SECRET")?.expose())
    else
      h.fail("MY_SECRET was not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvQuotesStripped is UnitTest
  fun name(): String => "env_secrets/.env strips a matching pair of quotes"

  fun ref apply(h: TestHelper) =>
    let content: String val =
      "DOUBLE=\"  spaced  \"\n" +
      "SINGLE='  spaced  '\n" +
      "EMPTY=\"\"\n"
    try
      let secrets = _DotEnvSecrets(_NoVars(), content)?
      h.assert_eq[String]("  spaced  ", secrets("DOUBLE")?.expose())
      h.assert_eq[String]("  spaced  ", secrets("SINGLE")?.expose())
      h.assert_eq[String]("", secrets("EMPTY")?.expose())
    else
      h.fail("quoted values were not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvQuotesKeptWhenUnmatched is UnitTest
  fun name(): String => "env_secrets/.env keeps quotes that are not a pair"

  fun ref apply(h: TestHelper) =>
    let content: String val =
      "MIXED=\"abc'\n" +
      "OPENING=\"abc\n" +
      "LONE=\"\n"
    try
      let secrets = _DotEnvSecrets(_NoVars(), content)?
      h.assert_eq[String]("\"abc'", secrets("MIXED")?.expose())
      h.assert_eq[String]("\"abc", secrets("OPENING")?.expose())
      h.assert_eq[String]("\"", secrets("LONE")?.expose())
    else
      h.fail("unmatched quotes were not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvCarriageReturns is UnitTest
  fun name(): String => "env_secrets/.env reads CRLF line endings"

  fun ref apply(h: TestHelper) =>
    try
      let secrets = _DotEnvSecrets(
        _NoVars(), "MY_SECRET=value\r\nOTHER=second\r\n")?
      h.assert_eq[String]("value", secrets("MY_SECRET")?.expose())
      h.assert_eq[String]("second", secrets("OTHER")?.expose())
    else
      h.fail("CRLF line endings were not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvValueContainsEquals is UnitTest
  fun name(): String => "env_secrets/a .env line splits at the first ="

  fun ref apply(h: TestHelper) =>
    try
      let secrets = _DotEnvSecrets(_NoVars(), "DSN=user=me;pass=secret\n")?
      h.assert_eq[String]("user=me;pass=secret", secrets("DSN")?.expose())
    else
      h.fail("DSN was not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvEmptyFile is UnitTest
  fun name(): String => "env_secrets/an empty .env file leaves the env alone"

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["MY_SECRET=from-env"]
    try
      let secrets = _DotEnvSecrets(vars, "")?
      h.assert_eq[String]("from-env", secrets("MY_SECRET")?.expose())
    else
      h.fail("an empty .env file should not have been malformed")
    end

class \nodoc\ iso _TestDotEnvNoTrailingNewline is UnitTest
  fun name(): String => "env_secrets/a .env file need not end with a newline"

  fun ref apply(h: TestHelper) =>
    try
      let secrets = _DotEnvSecrets(_NoVars(), "FIRST=one\nLAST=two")?
      h.assert_eq[String]("one", secrets("FIRST")?.expose())
      h.assert_eq[String]("two", secrets("LAST")?.expose())
    else
      h.fail("the last line was not read without a trailing newline")
    end

class \nodoc\ iso _TestDotEnvDuplicateNameFirstWins is UnitTest
  fun name(): String => "env_secrets/the first of a repeated .env name wins"

  fun ref apply(h: TestHelper) =>
    try
      let secrets = _DotEnvSecrets(
        _NoVars(), "MY_SECRET=first\nMY_SECRET=second\n")?
      h.assert_eq[String]("first", secrets("MY_SECRET")?.expose())
    else
      h.fail("MY_SECRET was not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvValueContainsHash is UnitTest
  fun name(): String => "env_secrets/a .env value keeps a # that follows it"

  fun ref apply(h: TestHelper) =>
    // Only a line starting with # is a comment, so there is no way to write
    // a trailing one and the text becomes part of the secret.
    try
      let secrets = _DotEnvSecrets(_NoVars(), "MY_SECRET=value # note\n")?
      h.assert_eq[String]("value # note", secrets("MY_SECRET")?.expose())
    else
      h.fail("MY_SECRET was not read from the .env file")
    end

class \nodoc\ iso _TestDotEnvMultiLineValueIsMalformed is UnitTest
  fun name(): String => "env_secrets/a .env value cannot span two lines"

  fun ref apply(h: TestHelper) =>
    let content: String val = "KEY=\"first\nsecond\"\n"

    match _DotEnv.parse_all(content, _NoVars())
    | let e: DotEnvMalformed => h.assert_eq[USize](2, e.line_number)
    else
      h.fail("a value spanning two lines should have been malformed")
    end

class \nodoc\ iso _TestDotEnvInvalidName is UnitTest
  fun name(): String =>
    "env_secrets/a .env name outside the allowed set is malformed"

  fun ref apply(h: TestHelper) =>
    // `export NAME=VALUE` is the shape a shell accepts, and binding it as the
    // name "export MY_SECRET" would leave MY_SECRET unset with no error.
    let rejected: Array[String] val =
      ["export MY_SECRET=value\n"; "MY SECRET=value\n"; "1ABC=value\n"]

    for content in rejected.values() do
      match _DotEnv.parse_all(content, _NoVars())
      | let e: DotEnvMalformed => h.assert_eq[USize](1, e.line_number)
      else
        h.fail("a .env name should have been rejected: " + content)
      end
    end

class \nodoc\ iso _TestDotEnvLineWithoutEquals is UnitTest
  fun name(): String => "env_secrets/a .env line without = is malformed"

  fun ref apply(h: TestHelper) =>
    match _DotEnv.parse_all("MY_SECRET\n", _NoVars())
    | let e: DotEnvMalformed => h.assert_eq[USize](1, e.line_number)
    else
      h.fail("a line without = should have reported DotEnvMalformed")
    end

class \nodoc\ iso _TestDotEnvLineWithEmptyName is UnitTest
  fun name(): String =>
    "env_secrets/a .env line with an empty name is malformed"

  fun ref apply(h: TestHelper) =>
    match _DotEnv.parse_all("  =value\n", _NoVars())
    | let e: DotEnvMalformed => h.assert_eq[USize](1, e.line_number)
    else
      h.fail("a line with an empty name should have reported DotEnvMalformed")
    end

class \nodoc\ iso _TestDotEnvMalformedLineNumber is UnitTest
  fun name(): String => "env_secrets/a malformed .env line reports its number"

  fun ref apply(h: TestHelper) =>
    // Blank and comment lines are skipped but still counted, so the reported
    // number matches what an editor shows.
    let content: String val =
      "GOOD=value\n" +
      "\n" +
      "# a comment\n" +
      "BROKEN\n" +
      "ALSO BROKEN\n"

    match _DotEnv.parse_all(content, _NoVars())
    | let e: DotEnvMalformed => h.assert_eq[USize](4, e.line_number)
    else
      h.fail("the first malformed line should have been the fourth")
    end
