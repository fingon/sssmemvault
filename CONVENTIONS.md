# Coding conventions (mainly for Aider use) #

- use 'self' as method receiver in Go methods

- fmt.Printf MUST NOT be used anywhere

- slog should be used for logging

    - use 'err' for errors

- use latest Go version style

- use latest Go conventions

  - use maps.Copy to copy map contents, and maps.Clone to make new copy

  - use 'any' instead of 'interface{}'

- use gotest.tools/v3/assert for test assertions

- do not use github.com/stretchr/testify/assert package

- do not use github.com/stretchr/testify/require package

- if same value repeats multiple times in a code file, make it a constant

- avoid writing comments about obvious actions, such as calling a function
