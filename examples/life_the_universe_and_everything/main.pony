use "../../sensitive"

actor Main
  let life_the_universe_and_everything: Sensitive[U8]
  let user: Sensitive[String]

  new create(env: Env) =>
    life_the_universe_and_everything = Sensitive[U8](42)
    env.out.print("The secret to Life, the Universe, and Everything is… "
      + life_the_universe_and_everything.string())

    if (life_the_universe_and_everything.expose() == 42) then
      env.out.print("… yet internally, I know the score.")
    end

    // In many environments, secrets are passed by environmental variables:
    try
      user = Sensitive[String].from_env(env.vars, "USER")?
      env.out.print("I read the contents of $USER, and it's: " + user.string())
      env.out.print("… but it does have " + user.expose().size().string()
        + " characters")
    else
      user = Sensitive[String]("")
      env.out.print("Apparently there is no $USER here")
    end
