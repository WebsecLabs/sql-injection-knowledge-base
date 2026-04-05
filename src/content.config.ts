import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { z } from "zod";

// Define the schema for our content collections
const entrySchema = z.object({
  title: z.string(),
  description: z.string().optional(),
  category: z.string(),
  order: z.number().int().positive(),
  tags: z.array(z.string()).optional(),
  lastUpdated: z.date().optional(),
});

// Define collections for each database type
export const collections = {
  mysql: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "src/content/mysql" }),
    schema: entrySchema,
  }),
  mariadb: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "src/content/mariadb" }),
    schema: entrySchema,
  }),
  mssql: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "src/content/mssql" }),
    schema: entrySchema,
  }),
  oracle: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "src/content/oracle" }),
    schema: entrySchema,
  }),
  postgresql: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "src/content/postgresql" }),
    schema: entrySchema,
  }),
  extras: defineCollection({
    loader: glob({ pattern: "**/*.md", base: "src/content/extras" }),
    schema: entrySchema,
  }),
};
