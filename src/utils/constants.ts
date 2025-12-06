export const COLLECTION_TYPES = ["mysql", "mssql", "oracle", "extras"] as const;

export const COLLECTION_LABELS: Record<(typeof COLLECTION_TYPES)[number], string> = {
  mysql: "MySQL",
  mssql: "MSSQL",
  oracle: "Oracle",
  extras: "Extras",
};
