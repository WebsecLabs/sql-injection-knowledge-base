export const COLLECTION_TYPES = ["mysql", "mssql", "oracle", "extras"] as const;

export const COLLECTION_LABELS: Record<string, string> = {
  mysql: "MySQL",
  mssql: "MSSQL",
  oracle: "Oracle",
  extras: "Extras",
};
