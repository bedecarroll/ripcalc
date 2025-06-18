# Development Workflow

1. **Format**:  
   `cargo fmt --all`

2. **Lint**:  
   `cargo clippy --all-targets -- -D warnings -W clippy::pedantic`

3. **Build**:  
   `cargo build --all-targets`

4. **Test**:  
   `cargo test`

5. **Generate documentation**:  
   `cargo doc --open`

6. **Lint Markdown**:  
   `markdownlint-cli2 "**/*.md"`

7. **Commit messages**:  
   Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

Ensure all steps pass before pushing changes.
