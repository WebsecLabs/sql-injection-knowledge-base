// Database-only collection types (excludes extras)
export const DATABASE_COLLECTION_TYPES = [
  "mysql",
  "mariadb",
  "mssql",
  "oracle",
  "postgresql",
] as const;

// All collection types including extras
export const COLLECTION_TYPES = [...DATABASE_COLLECTION_TYPES, "extras"] as const;

export type ValidCollection = (typeof COLLECTION_TYPES)[number];
export type DatabaseCollection = (typeof DATABASE_COLLECTION_TYPES)[number];

export const COLLECTION_LABELS: Record<ValidCollection, string> = {
  mysql: "MySQL",
  mariadb: "MariaDB",
  mssql: "MSSQL",
  oracle: "Oracle",
  postgresql: "PostgreSQL",
  extras: "Extras",
};

/**
 * Alternative labels for search results context.
 * Uses more descriptive names where appropriate.
 */
export const COLLECTION_SEARCH_LABELS: Record<ValidCollection, string> = {
  mysql: "MySQL",
  mariadb: "MariaDB",
  mssql: "MSSQL",
  oracle: "Oracle",
  postgresql: "PostgreSQL",
  extras: "Other Resources",
};
