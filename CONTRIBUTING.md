# Contributing to didethresolver

We love your input! We want to make contributing to this project as easy and
transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Running tests

- run all tests (doc, integration, and unit) for the workspace with:

```bash
cargo test --workspace --all-features
```

integration tests require the `all-features` flag,

## We Develop with Github

We use GitHub to host code, to track issues and feature requests, as well as
accept pull requests.

## We Use [Github Flow](https://guides.github.com/introduction/flow/index.html), So All Code Changes Happen Through Pull Requests

Pull requests are the best way to propose changes to the codebase (we use
[Github Flow](https://guides.github.com/introduction/flow/index.html)). We
actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any Contributions You Make Will Be Under the [Software License](LICENSE.md) Used in this Project

In short, when you submit code changes, your submissions are understood to be
under the same [license](LICENSE.md) that covers the project. Feel free to
contact the maintainers if that's a concern.

## Report Bugs Using Github's [Issues](https://github.com/xmtp/didethresolver/issues)

We use GitHub issues to track public bugs. Report a bug by
[opening a new issue](https://github.com/xmtp/didethresolver/issues); it's that
easy!

## Write Bug Reports With Detail, Background, and Sample Code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you
  tried that didn't work)

People _love_ thorough bug reports.

## Use a Consistent Coding Style

- Rust Language
  [Style Guide](https://doc.rust-lang.org/beta/style-guide/index.html)

## Extremely high bar for unit test coverage

- This project requires full test coverage for all changes

## License

By contributing, you agree that your contributions will be licensed as MIT open
source.

## References

This document was adapted from the open-source contribution guidelines for
[Facebook's Draft](https://github.com/facebook/draft-js).
