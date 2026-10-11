## Tooling

- Prefer Makefile targets instead of invoking `go`, `npm`, or other build/test tooling directly.
- If external Go dependencies change, run `make vendors`.
- If unsure which command to use, check `Makefile`, `.github/workflows/ci.yaml`, and `docker/`.

## Code

- Prefer the simplest minimal working solution. Do not over-engineer.
- Add comments only when necessary. Prefer useful logging over explanatory comments where appropriate.
- Fix failures before continuing. Do not ignore or skip errors.
- In Go initialize structs one field per line

## Tests

- Do not use underscores in Go test names.
- Docker is unavailable. Some local tests require existing containers.

## Output

- No sycophantic openers or closing fluff.
- No em dashes, smart quotes, or Unicode. ASCII only.
- Be concise. If unsure, say so. Never guess.

## Override Rule

- User instructions always override this file.
