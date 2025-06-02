import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://websec.com/sql-injection-knowledge-base',
  outDir: './dist',
  publicDir: './public',
  base: '/sql-injection-knowledge-base/',
  server: {
    port: 3000,
  },
  viewTransitions: true,
});
