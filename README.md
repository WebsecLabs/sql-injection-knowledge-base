# SQL Injection Knowledge Base

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Built with Astro](https://img.shields.io/badge/Built%20with-Astro-BC52EE.svg?logo=astro)](https://astro.build/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./src/content/extras/contributing.md)
[![GitHub stars](https://img.shields.io/github/stars/WebsecLabs/sql-injection-knowledge-base)](https://github.com/WebsecLabs/sql-injection-knowledge-base/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/WebsecLabs/sql-injection-knowledge-base)](https://github.com/WebsecLabs/sql-injection-knowledge-base/commits/main)

A modern, comprehensive resource for SQL injection techniques, examples, and bypasses across multiple database platforms.

**Read it at [websec.ca/sql-injection-knowledge-base](https://websec.ca/sql-injection-knowledge-base/)**, its official home.

## About

The SQL Injection Knowledge Base is a comprehensive resource designed to help security professionals and developers understand, identify, and test SQL injection vulnerabilities across various database systems. Serving both as an educational tool and practical reference, it supports continuous learning and effective vulnerability assessment.

This project is a modern rebuild of the original SQLi Knowledge Base, featuring improved performance, enhanced accessibility, better user experience, and increased extensibility to encourage community contributions.

## Features

- **Comprehensive Coverage**: Techniques for MySQL, MariaDB, MSSQL, Oracle, and PostgreSQL databases
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

- Node.js 24.0.0 or later (24.x LTS recommended and tested)
- npm (bundled with Node.js; no separate installation required)

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

## Deployment

The build output in `dist/` is a fully static site. Choose a build mode first:

- `npm run build` serves the site under `/sql-injection-knowledge-base/`, as on websec.ca.
- `STANDALONE=true SITE_URL=https://your.domain npm run build:standalone` serves it at the root of your domain.

### Docker (recommended)

```bash
npm run build
docker build -t sqli-kb .
docker run -d -p 8080:80 sqli-kb
```

The image runs nginx as an unprivileged user. It sends a Content-Security-Policy header together with the other security headers.

### Any static host

Upload `dist/` to any static host, such as GitHub Pages, Netlify or Cloudflare Pages. No server configuration is required. Every page embeds its Content-Security-Policy as a `<meta>` tag generated at build time. That policy allows only the site's own scripts and the hashes of its inline scripts.

### Canonical URLs

Every page declares its canonical URL on websec.ca, the knowledge base's official home, so copies deployed elsewhere don't compete with it in search results. A build also publishes a sitemap only when it is served from the canonical URL. To make your deployment canonical, for example a fork with its own content, set `CANONICAL_URL` when building:

```bash
STANDALONE=true SITE_URL=https://kb.example.com CANONICAL_URL=https://kb.example.com/ npm run build:standalone
```

### Security headers on static hosts

If your host lets you set response headers, also send these. They cannot be set from a `<meta>` tag:

```text
Content-Security-Policy: frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

## Contributing

Contributions are welcome! Please see our [Contributing Guide](./src/content/extras/contributing.md) for more details on how to contribute to this project.

## Development

For information about linting configuration and disabled rules, see [docs/linting.md](./docs/linting.md).

## Disclaimer

The techniques documented in this knowledge base are for educational and authorized security testing purposes only. Always obtain proper authorization before testing systems for security vulnerabilities.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
