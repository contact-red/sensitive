## Add EnvSecrets for reading secrets from the environment and .env files

`EnvSecrets` holds the process environment and, if you read one, a `.env` file, and returns each value as a `Sensitive[String]`. Build it once at startup and hand each component the values it needs: it is `val`, so it can be shared between actors, and nothing downstream needs `Env.vars`. Every environment value is wrapped, whether or not it is a secret, so read ordinary configuration from `Env.vars` directly and keep a call to `expose` meaningful.

`EnvSecrets(env.vars)` reads the environment alone. `ReadEnvSecrets` takes a `.env` file into account as well. A path with no file at it is not an error — you get the environment alone. A file that is there but cannot be read, or that has a malformed line, means secrets the file was meant to supply are absent, so neither is safe to carry on from.

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

Reading the file needs `FileRead` and `FileStat` on the `FilePath`. A relative path resolves against the working directory, so pass an absolute path when that directory is not trusted.

An environment variable overrides the `.env` file. When a name is set in both, the value from the environment wins and the file's value is discarded, so the file supplies only the names the environment leaves unset. A `.env` file is a development convenience; that ordering keeps one from shadowing a secret a deployment supplies.

An entry in a `.env` file is `NAME=VALUE`. Blank lines and lines starting with `#` are ignored, whitespace around the name and the value is trimmed, and a value wrapped in a matching pair of `"` or `'` keeps the whitespace inside the quotes. A name is letters, digits and underscores, not starting with a digit; anything else is malformed, including the `export NAME=VALUE` a shell would accept. There is no escaping, no `${...}` substitution, no value spanning two lines, and no comment after a value.

An environment variable's value is taken verbatim instead of trimmed and unquoted, so the same text can mean different things depending on which source supplied it. Where one name is set twice in the same source, the first of them wins, which is what `getenv` returns for the environment.

## Remove Sensitive.from_env

`EnvSecrets` now reads environment variables, so `Sensitive.from_env` is gone. It required `Env.vars` at every place a secret was extracted, and because it was a constructor on a generic class, `Sensitive[U64].from_env(...)` compiled and then raised an error at runtime.

Before:

```pony
let user = Sensitive[String].from_env(env.vars, "USER")?
```

After:

```pony
let secrets = EnvSecrets(env.vars)
let user = secrets("USER")?
```
