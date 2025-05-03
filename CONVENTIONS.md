# Coding conventions (mainly for Aider use) #

- use 'self' as method receiver in Go methods

- fmt.Printf MUST NOT be used anywhere

- slog should be used for logging

    - use 'err' for errors

- use latest Go version style and libraries

- use latest Go conventions

  - use maps.Copy to copy map contents, and maps.Clone to make new copy

  - use slices.Copy to copy slice contents, and slices.Clone to make new copy

  - use 'any' instead of 'interface{}'

- use gotest.tools/v3/assert for test assertions

- do not use github.com/stretchr/testify/assert package

- do not use github.com/stretchr/testify/require package

- if same value repeats multiple times in a code file, make it a constant

- do not write comments about obvious actions, such as calling a function

- do not write comments about Go version specific behaviour

- if there are complex code blocks within ifs, either create sub-functions or prefer returning early
