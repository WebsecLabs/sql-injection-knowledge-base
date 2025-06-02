---
title: How to Contribute
description: Guidelines for contributing to the SQL Injection Knowledge Base
category: Resources
order: 3
lastUpdated: 2025-03-24
---

## Contributing to the SQL Injection Knowledge Base

Thank you for your interest in contributing to the SQL Injection Knowledge Base! This guide outlines how you can help improve this resource for the security community.

## Ways to Contribute

There are several ways you can contribute to the knowledge base:

1. **Adding new techniques** - Document SQL injection techniques not yet covered
2. **Updating existing content** - Enhance or update existing entries with new information
3. **Correcting errors** - Fix technical or grammatical errors
4. **Improving examples** - Add clearer examples or more effective payloads
5. **Adding new database platforms** - Extend coverage to additional database systems
6. **Enhancing user experience** - Improve site navigation, search, or accessibility

## Contribution Process

### GitHub Workflow

1. **Fork the repository** - Create a fork of the main repository
2. **Create a branch** - Make a new branch for your contribution
3. **Make your changes** - Add or modify content following the guidelines below
4. **Submit a pull request** - Create a PR with a clear description of your changes

### Content Guidelines

#### File Structure

New entries should be added to the appropriate database folder:

```plaintext
src/content/
├── mysql/     # MySQL-specific techniques
├── mssql/     # Microsoft SQL Server techniques
├── oracle/    # Oracle techniques
└── extras/    # General resources and information
```

#### Markdown Format

All entries should use Markdown with the following frontmatter:

```markdown
---
title: Entry Title
description: Brief description of the technique
category: Basics | Information Gathering | Injection Techniques | Advanced Techniques
order: [numeric order within category]
tags: ["relevant", "tags", "here"]
lastUpdated: YYYY-MM-DD
---

# Entry Title

## Overview
Brief explanation of the technique

## Examples
```sql
Example SQL code
```

## Notes

Additional information, caveats, or version-specific details

```markdown

### Technical Guidelines

1. **Keep examples concise** - Focus on clarity and effectiveness
2. **Include version information** - Note which database versions the technique works with
3. **Use proper syntax highlighting** - Mark code blocks appropriately
4. **Be accurate** - Verify all techniques and payloads before submission
5. **Respect responsible disclosure** - Don't include zero-day exploits without proper disclosure

## Code of Conduct

When contributing to this project, please:

- Maintain a respectful and inclusive attitude
- Focus on educational aspects rather than malicious use
- Give credit to original sources when applicable
- Be open to feedback and suggestions
- Help review and improve others' contributions

## Getting Help

If you have questions about contributing, you can:

- Open an issue on GitHub with your question
- Contact the maintainers directly
- Join community discussions in the project's discussion forums

## Legal Note

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (typically MIT or similar open-source license). All contributions should be for educational and security research purposes only.

Thank you for helping make the SQL Injection Knowledge Base a valuable resource for the security community!
