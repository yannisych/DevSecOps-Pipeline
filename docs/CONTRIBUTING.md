# Contributing to DevSecOps Pipeline

Thank you for your interest in contributing to the DevSecOps Pipeline project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/DevSecOps-Pipeline.git
   cd DevSecOps-Pipeline
   ```
3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/yannisych/DevSecOps-Pipeline.git
   ```

## Development Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- Pre-commit hooks

### Install Dependencies

```bash
# Install Python dependencies
pip install -r scripts/requirements.txt

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Local Testing Environment

```bash
# Start local security tools
docker-compose up -d sonarqube sonarqube-db

# Wait for SonarQube to be ready
# Access: http://localhost:9000 (admin/admin)
```

## Making Changes

### Branch Naming Convention

- `feature/` - New features
- `bugfix/` - Bug fixes
- `docs/` - Documentation updates
- `security/` - Security improvements

Example:
```bash
git checkout -b feature/add-new-scanner
```

### Commit Message Guidelines

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks
- `security`: Security improvements

**Examples:**
```
feat(sast): add Semgrep integration

Integrated Semgrep for additional SAST coverage.
Configured rulesets for OWASP Top 10.

Closes #123
```

```
fix(dashboard): correct severity color coding

Fixed issue where medium severity was displaying as high.

Fixes #456
```

## Submitting Changes

### Pull Request Process

1. **Update your fork**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests** and ensure they pass:
   ```bash
   pytest tests/
   python -m bandit -r scripts/
   flake8 scripts/
   ```

3. **Run pre-commit hooks**:
   ```bash
   pre-commit run --all-files
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub with:
   - Clear description of changes
   - Link to related issues
   - Screenshots (if applicable)
   - Test results

### PR Review Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] No security vulnerabilities introduced
- [ ] Pre-commit hooks passing
- [ ] Commit messages follow conventions

## Coding Standards

### Python

- Follow [PEP 8](https://pep8.org/)
- Use type hints where applicable
- Maximum line length: 88 characters (Black default)
- Docstrings for all public functions

**Example:**
```python
def aggregate_reports(input_dir: str, output_dir: str) -> Dict[str, Any]:
    """
    Aggregate security reports from multiple tools.
    
    Args:
        input_dir: Directory containing scan results
        output_dir: Directory for consolidated reports
        
    Returns:
        Dictionary containing aggregated findings
        
    Raises:
        FileNotFoundError: If input directory doesn't exist
    """
    # Implementation
    pass
```

### Shell Scripts

- Use `shellcheck` for linting
- Include error handling
- Add comments for complex logic

### YAML

- 2-space indentation
- Use quotes for strings
- Validate with `yamllint`

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_aggregator.py -v

# Run with coverage
pytest --cov=scripts tests/
```

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_*.py`
- Use descriptive test names
- Include both positive and negative test cases

**Example:**
```python
def test_aggregate_reports_success():
    """Test successful report aggregation"""
    # Arrange
    input_dir = "test_data/reports"
    output_dir = "test_data/output"
    
    # Act
    result = aggregate_reports(input_dir, output_dir)
    
    # Assert
    assert result['total'] > 0
    assert os.path.exists(f"{output_dir}/consolidated-report.json")
```

## Adding New Security Tools

To add a new security scanning tool:

1. Create parser in `scripts/aggregate-reports.py`:
   ```python
   def parse_newtool_report(self, filepath: Path) -> Dict:
       """Parse NewTool JSON report"""
       # Implementation
   ```

2. Add tool to workflow in `.github/workflows/security-pipeline.yml`:
   ```yaml
   - name: NewTool Scan
     run: |
       newtool scan . --format json > reports/newtool.json
   ```

3. Update documentation in `README.md`

4. Add example configuration in `security-tools/newtool/`

## Documentation

- Update README.md for user-facing changes
- Add technical details to docs/
- Include code examples
- Update CHANGELOG.md

## Questions or Need Help?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Contact maintainers via email (see README)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to making DevSecOps Pipeline better! 🚀
