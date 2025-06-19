# Claude Development Rules

This file contains development guidelines and rules that Claude should follow when working on this cybersecurity AI agent project.

## Python Code Style & Best Practices

### Idiomatic Python
- Use list/dict comprehensions when they improve readability
- Prefer `pathlib.Path` over `os.path` for file operations
- Use context managers (`with` statements) for resource management
- Follow PEP 8 naming conventions (snake_case for functions/variables, PascalCase for classes)
- Use type hints for all function parameters and return values
- Prefer f-strings over `.format()` or `%` formatting
- Use `is` and `is not` for None comparisons
- Use `in` operator for membership testing

### Clean Code Principles
- **Single Responsibility**: Each function/class should have one clear purpose
- **DRY (Don't Repeat Yourself)**: Extract common functionality into reusable functions
- **Meaningful Names**: Use descriptive variable and function names that explain intent
- **Small Functions**: Keep functions focused and under 20 lines when possible
- **No Magic Numbers**: Use named constants for literal values
- **Error Handling**: Use specific exception types, not bare `except:`
- **Comments**: Write comments that explain "why", not "what"

### SOLID Principles

#### Single Responsibility Principle (SRP)
- Each class should have only one reason to change
- Separate data models from business logic
- Keep node classes focused on their specific agent behavior

#### Open/Closed Principle (OCP)
- Use inheritance and composition to extend functionality
- Prefer protocol/interface definitions for extensibility
- Use dependency injection for configurable components

#### Liskov Substitution Principle (LSP)
- Ensure derived classes can replace base classes without breaking functionality
- Maintain consistent interfaces across implementations

#### Interface Segregation Principle (ISP)
- Create specific, focused interfaces rather than large general ones
- Use Protocol classes for type hints when appropriate

#### Dependency Inversion Principle (DIP)
- Depend on abstractions, not concrete implementations
- Use dependency injection for external dependencies
- Pass dependencies through constructors

## Project-Specific Conventions

### Pydantic Models
- All data models must inherit from `BaseModel`
- Always implement `to_dict()` method that calls `model_dump(mode="json")`
- Use `Field()` with descriptive descriptions for all model fields
- Group related models in the same module

### Agent Architecture
- Follow the existing pattern: Node classes extend base agent types
- Use structured output with Pydantic models for LLM interactions
- Keep tool definitions separate from node implementations
- Use state classes that extend base state types

### Error Handling
- Use specific exception types, not generic `Exception`
- Provide meaningful error messages with context
- Log errors with appropriate levels
- Fail fast - validate inputs early

### Testing
- Write unit tests for all business logic
- Use descriptive test names that explain the scenario
- Mock external dependencies
- Test both happy path and error conditions

## Code Organization

### File Structure
- Keep related functionality in the same package
- Use `__init__.py` for package-level imports
- Separate models, logic, and configuration
- Follow the existing agent structure pattern

### Import Organization
- Standard library imports first
- Third-party imports second
- Local imports last
- Use absolute imports for clarity
- Group imports logically with blank lines

### Documentation
- Write docstrings for all public functions and classes
- Use Google-style docstrings
- Include type information in docstrings when helpful
- Document complex algorithms and business logic

## Performance Considerations

- Use generators for large data processing
- Avoid premature optimization
- Profile before optimizing
- Consider memory usage for large datasets
- Use appropriate data structures (sets for membership, dicts for lookups)

## Security Best Practices

- Never log sensitive information (credentials, tokens, etc.)
- Validate all inputs
- Use parameterized queries for database operations
- Sanitize data before processing
- Follow principle of least privilege

## Git and Version Control

- Write clear, descriptive commit messages
- Keep commits focused and atomic
- Use conventional commit format when possible
- Don't commit secrets or sensitive data

## Code Review Guidelines

- Code should be self-explanatory
- Prefer simple solutions over complex ones
- Ensure all new code has appropriate tests
- Follow the project's existing patterns
- Document any architectural decisions

---

*These rules should be followed consistently across all code changes and new implementations in this project.*