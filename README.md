# SQL Injection Knowledge Base

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Built with Astro](https://img.shields.io/badge/Built%20with-Astro-BC52EE.svg?logo=astro)](https://astro.build/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./src/content/extras/contributing.md)
[![GitHub stars](https://img.shields.io/github/stars/WebsecLabs/sql-injection-knowledge-base)](https://github.com/WebsecLabs/sql-injection-knowledge-base/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/WebsecLabs/sql-injection-knowledge-base)](https://github.com/WebsecLabs/sql-injection-knowledge-base/commits/main)

A modern, comprehensive resource for SQL injection techniques, examples, and bypasses across multiple database platforms.

## About

The SQL Injection Knowledge Base is a comprehensive resource designed to help security professionals and developers understand, identify, and test SQL injection vulnerabilities across various database systems. Serving both as an educational tool and practical reference, it supports continuous learning and effective vulnerability assessment.

This project is a modern rebuild of the original SQLi Knowledge Base, featuring improved performance, enhanced accessibility, better user experience, and increased extensibility to encourage community contributions.

## Features

- **Comprehensive Coverage**: Techniques for MySQL, MSSQL, Oracle, and PostgreSQL databases
- **User-Friendly Navigation**: Organized by database type and technique categories
- **Modern Interface**: Fast, responsive design that works across all devices
- **Searchable Content**: Quick access to specific techniques
- **Code Examples**: Practical examples for each technique
- **Open Source**: Community-driven knowledge base

## Technology Stack

Built with:

- [Astro](https://astro.build/) - A modern static site generator focused on performance
- Markdown for content management
- Modern JavaScript for interactive features
- Responsive design for all device sizes

## Requirements

- Node.js 20.0.0 or later (22.x LTS recommended and tested)
- npm

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/WebsecLabs/sql-injection-knowledge-base.git
   cd sql-injection-knowledge-base
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Run the development server:

   ```bash
   npm run dev
   ```

4. Build for production:

   ```bash
   npm run build
   ```

## Contributing

Contributions are welcome! Please see our [Contributing Guide](./src/content/extras/contributing.md) for more details on how to contribute to this project.

## Development

For information about linting configuration and disabled rules, see [docs/linting.md](./docs/linting.md).

## Disclaimer

The techniques documented in this knowledge base are for educational and authorized security testing purposes only. Always obtain proper authorization before testing systems for security vulnerabilities.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
