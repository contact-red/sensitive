# sensitive

A package to help you manage sensitive data. It wraps a value so that printing it gives `[REDACTED]`, and getting the real thing takes a deliberate call to `expose()`.

## Status

sensitive is 0.x software. It is small and simple, but the public API can still change — the next release removes `Sensitive.from_env`. You should feel comfortable using it in your projects.

## Installation

* Install [corral](https://github.com/ponylang/corral)
* `corral add github.com/contact-red/sensitive.git --version 0.1.1`
* `corral fetch` to fetch your dependencies
* `use "sensitive"` to include this package
* `corral run -- ponyc` to compile your application

## Usage

A common pattern we see while doing security audits is that programmers will unintentionally output sensitive data to logfiles, or other destinations where it may not be appropriate to write to. The purpose of this package is to provide a mechanism to "tag" sensitive variables in such a way that accessing them becomes a deliberate act, and simply calling .string() will return "\[REDACTED\]".

Applications are commonly handed their secrets through environment variables or a `.env` file. EnvSecrets returns each value as a Sensitive\[String\], so the environment is read once, at startup. ReadEnvSecrets builds one from a `.env` file and the environment together.

```pony
use "files"
use "sensitive"

actor Main
  let life_the_universe_and_everything: Sensitive[U8]

  new create(env: Env) =>
// Secrets passed via direct assignment:
    life_the_universe_and_everything = Sensitive[U8](42)
    env.out.print("The secret to Life, the Universe, and Everything is… "
      + life_the_universe_and_everything.string())

    if (life_the_universe_and_everything.expose() == 42) then
      env.out.print("… yet internally, I know the score.")
    end

// Secrets passed via Environmental Variable or a .env file:
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
      env.out.print("I read DB_PASSWORD, and it's: " + password.string())

      if password.expose() == "hunter2" then
        env.out.print("… yet exposing it deliberately gives the real thing.")
      end
    else
      env.out.print("DB_PASSWORD is not set."
        + " Copy .env.example to .env to set it.")
    end
```

This program is in [`examples/`](examples/). Copy `.env.example` to `.env` to give it a secret to read.

A path with no `.env` file at it is not an error — ReadEnvSecrets returns the environment alone. A file that is there but cannot be read, or that has a malformed line, means secrets you expected are absent, so neither is safe to carry on from.

An environment variable overrides the `.env` file, so the file supplies only the names the environment leaves unset. Reading the file needs `FileRead` and `FileStat`, and a relative path resolves against the working directory. The API documentation gives the full `.env` syntax and what it deliberately leaves out.

Wrapping a value keeps it out of string output and does nothing more. It is an ordinary string on the heap, still readable in a core dump or by an attached debugger, so use this to stop a secret reaching a log rather than to defend against someone who can already read the process.

## API Documentation

[https://sensitive.contact.red/](https://sensitive.contact.red/)
