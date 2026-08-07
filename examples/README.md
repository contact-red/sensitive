# Examples

Each subdirectory is a self-contained Pony program demonstrating a different part of the sensitive library.

## [life_the_universe_and_everything](life_the_universe_and_everything/)

Wraps a `U8` and a secret read from the environment, prints both to show that `string()` gives `[REDACTED]`, and calls `expose()` to use the real values. Demonstrates `Sensitive[A]`, `ReadEnvSecrets` with a `FilePath` narrowed to `FileRead` and `FileStat`, and reporting a `DotEnvError` on stderr with a non-zero exit code rather than starting without the secrets the file was meant to supply.

The `.env` file is read from the working directory, not from beside the binary. Copy the repository's `.env.example` to `.env` and run the program from that directory to see it read `DB_PASSWORD` from the file; without a `.env` it reads the environment alone. Start here if you're new to the library.
