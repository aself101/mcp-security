# Repository Guidelines

## Project Structure & Module Organization
Source lives in `src/`, where `index.ts` re-exports the secure server, `security/` contains the layered middleware and transports, and `types/` stores shared definitions. Tests mirror this layout under `test/unit`, `test/integration`, and `test/performance`. Docs sit in `docs/`, examples in `cookbook/`, and builds in `dist/` (never edit generated files).

## Build, Test, and Development Commands
- `npm run build` – runs `tsc` and refreshes `dist/`.
- `npm test` – executes the entire Vitest suite; required before any PR.
- `npm run test:unit|test:integration|test:performance` – scope runs to the feature you are touching.
- `npm run test:watch` – reruns impacted specs while developing.
- `npm run test:coverage` – regenerates the ≥86% coverage report before releases.
- `npm run minimal-server` – boots `test-server/minimal-test-server.ts` for manual probing.
- `npm run lint` – enforces the shared ESLint configuration across `src/`.

## Coding Style & Naming Conventions
Write TypeScript (ES modules, Node ≥18) with 2-space indentation and relative imports. Classes/interfaces are `PascalCase`, functions/variables `camelCase`, constants `UPPER_SNAKE_CASE`, and filenames should state the layer they implement (`layer3-behavior.ts`, `secure-transport.ts`). Keep modules focused (≈300 LOC max) per `docs/AI-preferences.md`, reuse utilities, document exports briefly, and rely on `npm run lint` to enforce ESLint + `@typescript-eslint` (identifiers prefixed with `_` may remain unused).

## Layer Implementation Notes
Every validation layer extends `ValidationLayerBase` and implements `validate(message, context)` returning `{ passed, allowed, severity, reason, violationType }`. Wire new layers through `ValidationPipeline`, use `ErrorSanitizer` for responses, keep attack patterns centralized in `src/security/layers/layer-utils/content/dangerous-patterns.ts`, and surface options via `SecureMcpServer` rather than one-off hooks.

## Testing Guidelines
Vitest drives every suite. Name specs `*.test.ts`/`*.test.js` in the matching `test/<suite>/` folder so targeted runs stay fast. Validator or limit updates must ship with regression tests plus payload fixtures in `test-data/`. Keep coverage ≥85% via `npm run test:coverage`, note exceptions in the PR, and mention `npm run minimal-server` when verifying transports.

## Commit & Pull Request Guidelines
Commits use the Conventional Commit style already in history (`feat(security): …`, `fix(transport): …`, `refactor(security): …`); keep subjects imperative and under ~72 characters. Every PR should link the motivating issue, summarize the change, list the commands executed, and flag notable security or cookbook impact. Update docs when altering limits, transports, or defaults, and attach screenshots/logs only when they clarify behavior.

## Security & Configuration Tips
Default limits and policies live in `src/security/constants.ts` and deny outbound network plus filesystem writes; any change demands matching documentation and rationale in the PR. Keep verbose logging disabled outside targeted tests so sensitive payloads stay private. Before merging layer or transport changes, review `SECURITY.md`, `mcp-security-features-list.md`, and surface new knobs through `src/security/mcp-secure-server.ts`.
