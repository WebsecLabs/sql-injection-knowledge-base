export const COLLECTION_TYPES = ["mysql", "mssql", "oracle", "postgresql", "extras"] as const;

export type ValidCollection = (typeof COLLECTION_TYPES)[number];

export const COLLECTION_LABELS: Record<ValidCollection, string> = {
  mysql: "MySQL",
  mssql: "MSSQL",
  oracle: "Oracle",
  postgresql: "PostgreSQL",
  extras: "Extras",
};
