# Contributing

We welcome contributions! All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to Contribute

- **Code examples** — Add examples in additional languages (Rust, Java, Ruby, etc.)
- **Bug fixes** — Report or fix errors in documentation or code
- **New modules** — Suggest additional auth mechanisms not yet covered
- **Improvements** — Clarify explanations, add Mermaid diagrams, fix typos
- **Translations** — Translate modules into other languages
- **Cheat sheets** — Add or improve quick-reference sheets

## Style Conventions

All content should follow these principles:

1. **Explain why before how** — name the threat or problem first, then the mechanism
2. **Standards-based** — reference RFCs and specifications, not blog posts
3. **Beginner-respectful** — define jargon on first use; no condescension
4. **Accurate over impressive** — prefer correctness over cleverness
5. **No real secrets** — all passwords, keys, and tokens in examples must be fake

### README Format

Each topic README should include:
- Overview of the mechanism and what problem it solves
- Sequence diagram (ASCII or Mermaid) of the protocol flow
- Code examples table linking to Python/TypeScript/Go subdirectories
- Security considerations section
- References to relevant RFCs and standards

### Code Style

- **Python**: Type hints, PEP 8, FastAPI for HTTP servers
- **TypeScript**: ES2022+, no external dependencies where possible, `npx tsx` for execution
- **Go**: `net/http` standard library, `gofmt` formatting
- **All languages**: Clean code with security-conscious patterns (constant-time compare, input validation, no hardcoded secrets)

## Module Structure

```
02-session-cookies/
├── README.md              # Main explanation
├── python/
│   ├── server.py
│   └── client.py
├── typescript/
│   ├── server.ts
│   └── client.ts
└── go/
    ├── server.go
    └── client.go
```

## Pull Request Process

1. Fork the repository
2. Create a branch: `git checkout -b topic/your-feature`
3. Make focused, single-purpose changes
4. Test your code examples before committing
5. Open a Pull Request against `main`
6. Ensure CI checks pass

## Reporting Security Issues

If you find a security vulnerability in any code example, open an issue with the `security` label or contact the maintainers directly. Do not post exploit code publicly.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
