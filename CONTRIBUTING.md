## Contributing

[fork]: /fork
[pr]: /compare
[code-of-conduct]: CODE_OF_CONDUCT.md

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

Please note that this project is released with a [Contributor Code of Conduct][code-of-conduct]. By participating in this project you agree to abide by its terms.

## Issues and PRs

If you have suggestions for how this project could be improved, or want to report a bug, open an issue! We'd love all and any contributions. If you have questions, too, we'd love to hear them.

We'd also love PRs. We focus on exploit and vulnerability intelligence content. We welcome any contribution that fits this content theme of initial access vulnerability intelligence. If you're interested in sharing your research, we'd love to see it. Look at the links below if you're not sure how to open a PR.

## Submitting a pull request

1. [Fork][fork] and clone the repository.
1. Create a new directory
1. Create a new branch: `git checkout -b my-branch-name`.
1. Create a directory in `feed/` for your target CVE. Every CVE we ship is a self-contained package. Here's what the process looks like end to end:
    1. **Research the vulnerability** — read the advisory, find the affected code, understand the root cause
    2. **Build a vulnerable target** — Docker container running the affected software (or use an existing one)
    3. **Write the exploit** — Go, using the [go-exploit framework](https://github.com/vulncheck-oss/go-exploit)
    4. **Capture PCAPs** — traffic from successful exploitation, both encrypted and unencrypted where applicable
    5. **Write detection rules** — Snort and/or Suricata signatures that detect the exploit in network traffic
    6. **Write YARA rules** — if the exploit drops artifacts to disk (optional, depends on the vuln class)
    7. **Document everything** — write the [README](https://github.com/vulncheck-oss/initial-access-community/blob/main/examples/README.template.md) with usage, detection details, and verification steps
    8. **Submit the package** — PR against initial-access, passing CI checks
1. Push to your fork and [submit a pull request][pr].
1. Check for the CI tests to run. Fix any errors that may have been identified.

## Resources

- [go-exploit API](https://pkg.go.dev/github.com/vulncheck-oss/go-exploit)
- [go-exploit documentation](https://github.com/vulncheck-oss/go-exploit/tree/main/docs)
- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [Using Pull Requests](https://help.github.com/articles/about-pull-requests/)
- [GitHub Help](https://help.github.com)

## License

This repository is published under the [Apache License 2.0](LICENSE). Contributions are released under the [0BSD license](https://opensource.org/license/0bsd).

By submitting a contribution, you affirm that it is your original work, that you have the right to contribute it, and that you release it under the terms of the 0BSD license.
