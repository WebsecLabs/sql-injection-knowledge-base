import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://websec.com/sql_injection',
  outDir: './dist',
  publicDir: './public',
  server: {
    port: 3000,
  },
  // Enable View Transitions globally
  viewTransitions: true,
});
