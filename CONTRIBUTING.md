# Contribution Guidelines

[English](./CONTRIBUTING.md) | [简体中文](./doc/CONTRIBUTING_zh.md)

Thank you for considering contributing to our project! We appreciate your efforts to make our project better.

Before you start contributing, please take a moment to review the following guidelines.

## How Can I Contribute?

### Reporting Bugs

If you encounter a bug in the project, please [open an issue](https://github.com/XiaoMi/ha_xiaomi_home/issues/new/) on GitHub and provide the detailed information about the bug, including the steps to reproduce the bug, the logs of debug level and the time when it occurs.

The [method](https://www.home-assistant.io/integrations/logger/#log-filters) to set the integration's log level:

```
# Set the log level in configuration.yaml

logger:
  default: critical
  logs:
    custom_components.xiaomi_home: debug
```

### Suggesting Enhancements

If you have ideas for enhancements or new features, you are welcomed to [start a discussion on ideas](https://github.com/XiaoMi/ha_xiaomi_home/discussions/new?category=ideas) on GitHub to discuss your ideas.

### Contributing Code

1. Fork the repository and create your branch from `main`.
2. Ensure that your code adheres to the project coding standard.
3. Make sure that your commit messages are descriptive and meaningful.
4. Pull requests should be accompanied by a clear description of the problem and the solution.
5. Update the documents if necessary.
6. Run tests if they are available and ensure they pass.

## Pull Request Guidelines

Before submitting a pull request, please make sure that the following requirements are met:

- Your pull request addresses a single issue or feature.
- You have tested your changes locally.
- Your code follows the project's [code style](#code-style). Run [`pylint`](https://github.com/google/pyink) over your code using this [pylintrc](../.pylintrc).
- All existing tests pass, and you have added new tests if applicable.
- Any dependent changes are documented.

## Code Style

We follow [Google Style](https://google.github.io/styleguide/pyguide.html) for code style and formatting. Please make sure to adhere to this guideline in your contributions.

## Commit Message Format

```
<type>: <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

type: commit type is one of the following

- feat: A new feature.
- fix: A bug fix.
- docs: Documentation only changes.
- style: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc.).
- refactor: A code change that neither fixes a bug nor adds a feature.
- perf: A code change that improves performance.
- test: Adding missing tests or correcting existing tests.
- chore: Changes to the build process or auxiliary tools and libraries.
- revert: Reverting a previous commit.

subject: A short summary in imperative, present tense. Not capitalized. No period at the end.

body: A detailed description of the commit and the motivation for the change. The body is mandatory for all commits except for those of type "docs".

footer: Optional. The footer is the place to reference GitHub issues and PRs that this commit closes or is related to.

## Naming Conventions

### Xiaomi Naming Convention

- When describing Xiaomi, always use "Xiaomi" in full. Variable names can use "xiaomi" or "mi".
- When describing Xiaomi Home, always use "Xiaomi Home". Variable names can use "mihome" or "MiHome".
- When describing Xiaomi IoT, always use "MIoT". Variable names can use "miot" or "MIoT".

### Third-Party Platform Naming Convention

- When describing Home Assistant, always use "Home Assistant". Variables can use "hass" or "hass_xxx".

### Other Naming Conventions

- When using mixed Chinese and English sentences in the document, there must be a space between Chinese and English or the English words must be quoted by Chinese quotation marks. (It is best to write code comments this way too.)

## Licensing

When contributing to this project, you agree that your contributions will be licensed under the project's [LICENSE](../LICENSE.md).


When you submit your first pull request, GitHub Action will prompt you to sign the Contributor License Agreement (CLA). Only after you sign the CLA, your pull request will be merged.

## How to Get Help

If you need help or have questions, feel free to ask in [discussions](https://github.com/XiaoMi/ha_xiaomi_home/discussions/) on GitHub.

You can also contact ha_xiaomi_home@xiaomi.com
