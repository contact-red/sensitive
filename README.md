# sensitive

A package to help you manage sensitive data.

A common pattern we see while doing security audits is that programmers will unintentionally output sensitive data to logfiles, or other destinations where it may not be appropriate to write to. The purpose of this package is to provide a mechanism to "tag" sensitive variables in such a way that accessing them becomes a deliberate act, and simply calling .string() will return "\[REDACTED\]".

There is an additional helpful constructor which reads a specified Environmental Variable into a Sensitive[String], a very common pattern when passing sensitive data into applications.

## Example

```pony
use "sensitive"

actor Main
  let life_the_universe_and_everything: Sensitive[U8]
  let user: Sensitive[String]

  new create(env: Env) =>
// Secrets passed via direct assignment:
    life_the_universe_and_everything = Sensitive[U8](42)
    env.out.print("The secret to Life, the Universe, and Everything is… " + life_the_universe_and_everything.string())

    if (life_the_universe_and_everything.expose() == 42) then
      env.out.print("… yet internally, I know the score.")
    end

// Secrets passed via Environmental Variable:
    try
      user = Sensitive[String].from_env(env.vars, "USER")?
      env.out.print("I read the contents of $USER, and it's: " + user.string())
      env.out.print("… but it does have " + user.expose().size().string() + " characters")
    else
      user = Sensitive[String]("")
      env.out.print("Apparently there is no $USER here")
    end
```

## Status

sensitive is small and simple. I don't expect breaking changes. You should feel comfortable using it in your projects.

## Installation

* Install [corral](https://github.com/contact-red/sensitive)
* `corral add github.com/contact-red/sensitive.git --version 0.1.0`
* `corral fetch` to fetch your dependencies
* `use "sensitive"` to include this package
* `corral run -- ponyc` to compile your application

## API Documentation

[https://sensitive.contact.red/](https://sensitive.contact.red/)
