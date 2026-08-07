use "../../sensitive"
use "files"

actor Main
  let life_the_universe_and_everything: Sensitive[U8]

  new create(env: Env) =>
    life_the_universe_and_everything = Sensitive[U8](42)
    env.out.print("The secret to Life, the Universe, and Everything is… "
      + life_the_universe_and_everything.string())

    if (life_the_universe_and_everything.expose() == 42) then
      env.out.print("… yet internally, I know the score.")
    end

    // Secrets arrive by environmental variable or by a .env file in the
    // working directory. An environmental variable overrides the file.
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
