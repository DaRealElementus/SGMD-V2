# SIGMUND CODING STANDARDS
# PEP 8 – Python Style Guide Summary

PEP 8 is the official style guide for Python code, promoting readability and consistency across Python projects.

---

## Code Layout

- **Indentation:** Use 4 spaces per indentation level. No tabs.
- **Maximum Line Length:** Limit lines to 79 characters.
- **Blank Lines:** Use blank lines to separate functions and classes, and inside functions to indicate logical sections.
- **Imports:** Should be on separate lines and grouped in this order:
  1. Standard library imports
  2. Related third-party imports
  3. Local application imports

---

## Naming Conventions

| Type                         | Style              |
|-----------------------------|--------------------|
| Modules                     | `lowercase_with_underscores` |
| Packages                    | `lowercase`        |
| Classes                     | `CapWords`         |
| Functions and variables     | `lowercase_with_underscores` |
| Constants                   | `UPPERCASE_WITH_UNDERSCORES` |
| Instance and method names   | `lowercase_with_underscores` |
| Private variables/methods   | `_single_leading_underscore` |
| Avoid                       | `l`, `O`, `I` as single letters |

---

## Whitespace

- No extra spaces inside parentheses, brackets, or braces.
- Avoid trailing whitespace.
- Use a single space after commas, colons, and semicolons.
- No space before the `(` in function calls or definitions.

---

## Comments

- **Block Comments:** Use complete sentences, update them when code changes.
- **Inline Comments:** Use sparingly, separated by at least two spaces from code.
- **Docstrings:** Use triple quotes `"""` and describe method purpose, arguments, and return values.

---

## Programming Recommendations

- Use `is`/`is not` for comparing to `None`.
- Use `==`/`!=` for comparisons, not `is` for values.
- Use `.startswith()` and `.endswith()` instead of slicing.
- Avoid `from module import *`.

---

## Miscellaneous

- Code should work on multiple Python versions (if intended).
- Follow the "Zen of Python" for guiding principles.
```zen
Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!
```

---

## Tools

Use tools like:
- `flake8`, `pylint` for linting.
- `black` or `autopep8` for automatic formatting.

---

## Final Note

Readability counts. When in doubt, favor clarity and consistency with surrounding code.

For full details, see the original PEP: [https://peps.python.org/pep-0008/](https://peps.python.org/pep-0008/)


# Git Commit and Pull Request Standards

For commit messages,follow a tree structure e.g.:
```commit
File.py
+ change, short description of the change
- remove, short description of the removal and why
= refactor, short description of the refactor
? comment, should refer to line number (? ln223)

File2.py
+ change, short description of the change
- remove, short description of the removal and why
= refactor, short description of the refactor
? comment, should refer to line number (? ln45)

```
This allows for easy tracking of changes and understanding of the codebase evolution.
For pull requests, follow these guidelines:
- Ensure your code adheres to PEP 8 standards.
- Include a clear description of the changes made.
- Reference any related issues or discussions.

**YOU MUST TEST YOUR CODE BEFORE PUSHING**

Keep vibe-coding to a minimum, AI is chill, but it isnt a slave and nor is it a god. <br>
AND FOR THE LOVE OF GOD, PLEASE DO NOT USE AI RECURSIVELY TO TRY AND FIX BUGS, IT MAKES IT WORSE.

Much love and care,
Alex Larkings :heart:

Alex Larkings<br>
2025-26-07


