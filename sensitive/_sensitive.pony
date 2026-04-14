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
    test(Property1UnitTest[String](_PropertyFromEnvRoundtrip))
    test(Property1UnitTest[String](_PropertyFromEnvRedacted))
    test(_TestFromEnvMissing)

class iso _PropertyExposeRoundtrip is Property1[String]
  fun name(): String => "sensitive/expose roundtrips for String"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let s = Sensitive[String](arg1)
    ph.assert_eq[String](arg1, s.expose())

class iso _PropertyStringAlwaysRedacted is Property1[String]
  fun name(): String => "sensitive/string is always [REDACTED] for String"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let s = Sensitive[String](arg1)
    let redacted: String val = s.string()
    ph.assert_eq[String]("[REDACTED]", redacted)

class iso _PropertyExposeRoundtripU64 is Property1[U64]
  fun name(): String => "sensitive/expose roundtrips for U64"

  fun gen(): Generator[U64] =>
    Generators.u64()

  fun ref property(arg1: U64, ph: PropertyHelper) =>
    let s = Sensitive[U64](arg1)
    ph.assert_eq[U64](arg1, s.expose())

class iso _PropertyStringAlwaysRedactedU64 is Property1[U64]
  fun name(): String => "sensitive/string is always [REDACTED] for U64"

  fun gen(): Generator[U64] =>
    Generators.u64()

  fun ref property(arg1: U64, ph: PropertyHelper) =>
    let s = Sensitive[U64](arg1)
    let redacted: String val = s.string()
    ph.assert_eq[String]("[REDACTED]", redacted)

class iso _PropertyFromEnvRoundtrip is Property1[String]
  fun name(): String => "sensitive/from_env exposes the env var value"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let vars: Array[String] val = ["MY_SECRET=" + arg1]
    try
      let s = Sensitive[String].from_env(vars, "MY_SECRET")?
      ph.assert_eq[String](arg1, s.expose())
    else
      ph.fail("from_env raised error for existing var")
    end

class iso _PropertyFromEnvRedacted is Property1[String]
  fun name(): String => "sensitive/from_env string is always [REDACTED]"

  fun gen(): Generator[String] =>
    Generators.ascii_printable()

  fun ref property(arg1: String, ph: PropertyHelper) =>
    let vars: Array[String] val = ["MY_SECRET=" + arg1]
    try
      let s = Sensitive[String].from_env(vars, "MY_SECRET")?
      let redacted: String val = s.string()
      ph.assert_eq[String]("[REDACTED]", redacted)
    else
      ph.fail("from_env raised error for existing var")
    end

class iso _TestFromEnvMissing is UnitTest
  fun name(): String => "sensitive/from_env errors on missing var"

  fun ref apply(h: TestHelper) =>
    let vars: Array[String] val = ["OTHER=value"]
    try
      Sensitive[String].from_env(vars, "MISSING")?
      h.fail("from_env should have raised error for missing var")
    end
