import { defineCollection, z } from 'astro:content';

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
    schema: entrySchema,
  }),
  mssql: defineCollection({
    schema: entrySchema,
  }),
  oracle: defineCollection({
    schema: entrySchema,
  }),
  extras: defineCollection({
    schema: entrySchema,
  }),
};