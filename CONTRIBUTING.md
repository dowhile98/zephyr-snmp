# Contributing to Zephyr SNMP

Thank you for your interest in contributing to the Zephyr SNMP Agent module!

## Code of Conduct

This project follows the [Zephyr Project Code of Conduct](https://docs.zephyrproject.org/latest/contribute/index.html#code-of-conduct).

## How to Contribute

### Reporting Bugs

Before opening a new issue, please check if it already exists in the
[issue tracker](https://github.com/daecge/zephyr-snmp/issues).

When reporting a bug, include:

1. **Zephyr version** (e.g., `west --version` or commit hash)
2. **Board/SoC** you're targeting
3. **Kconfig options** used (relevant `CONFIG_SNMP_*` values)
4. **Steps to reproduce** with exact `snmpget`/`snmpwalk` commands
5. **Expected vs actual behavior**
6. **Packet capture** (`.pcap`) if applicable

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

### Suggesting Features

Open a [GitHub Discussion](https://github.com/daecge/zephyr-snmp/discussions) first
to discuss the feature before submitting a PR.

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes following the coding style below
4. Test your changes (see Testing section)
5. Commit with a clear message (see Commit Messages section)
6. Push and open a Pull Request

## Coding Style

This project follows the [Zephyr Coding Style](https://docs.zephyrproject.org/latest/contribute/guidelines/index.html#coding-style)
with these specifics:

- **Indentation**: tabs (not spaces)
- **Line length**: 80 characters (preferably), 100 max
- **Braces**: K&R style (opening brace on same line)
- **Naming**: `snake_case` for functions/variables, `UPPER_SNAKE_CASE` for macros
- **Prefix**: `snmp_` for public API, static for internal functions
- **Comments**: Doxygen-style `/** ... */` for public APIs

### Example

```c
/**
 * @brief Brief description of the function.
 *
 * @param param1 Description of param1.
 * @return 0 on success, negative errno on failure.
 */
int snmp_my_function(const char *param1)
{
	if (!param1) {
		return -EINVAL;
	}

	/* Implementation */
	return 0;
}
```

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): short description

Longer description if needed. Explain WHY, not WHAT.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```
fix(usm): implement RFC 3414 password-to-key correctly

The previous implementation used 1000 iterations instead of
1,000,000 and omitted password concatenation, producing keys
incompatible with all other SNMPv3 implementations.

Fixes #42
```

```
feat(mib): add table support for interface group
```

## Testing

### Unit Tests

Run unit tests from the `tests/` directory:

```bash
west build -b native_posix tests/unit
```

### Integration Tests

Test against Net-SNMP tools:

```bash
# GET
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.1.0

# WALK
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1

# BULK
snmpbulkwalk -v2c -c public <IP> 1.3.6.1.2.1

# SET
snmpset -v2c -c private <IP> 1.3.6.1.2.1.1.4.0 s "new-contact"

# v3 authNoPriv
snmpwalk -v3 -u admin -l authNoPriv -a SHA -A authpass123 <IP> 1.3.6.1.2.1
```

## Branch Strategy

- `main` — stable, release-ready code
- `dev` — development branch for upcoming releases
- `feature/*` — feature branches
- `fix/*` — bug fix branches

## Release Process

1. Update `CHANGELOG.md` with all changes
2. Bump version following [SemVer](https://semver.org/)
3. Create a Git tag
4. Create a GitHub Release with release notes
5. Update `README.md` if API changed

## Questions?

Open a [Discussion](https://github.com/daecge/zephyr-snmp/discussions) or
reach out to the maintainers.
