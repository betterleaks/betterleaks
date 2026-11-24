export interface ScanResult {
  schema_version: 1;
  engine_version: string;
  config_hash: string;
  findings: Finding[];
  summary: { bytes_inspected: number; findings: number };
}

export interface Match {
  full: string;
  value: string;
  entropy?: number;
  fingerprint?: string;
  captures?: Record<string, string>;
  context?: string;
}

/** Lines and byte columns are one-based. */
export interface Location {
  path?: string;
  start_line?: number;
  end_line?: number;
  start_column?: number;
  end_column?: number;
}

interface Detection {
  rule_id: string;
  rule_hash?: string;
  match: Match;
  location: Location;
  encodings?: string[];
  decode_depth?: number;
}

export interface Finding extends Detection {
  description: string;
  confidence: string;
  tags?: string[];
  attributes?: Record<string, string>;
  component_sets?: { components: (Detection & { optional?: boolean })[] }[];
  component_sets_truncated?: boolean;
}

/** Scan up to 8 MiB of UTF-8 text with the built-in rules. */
export function scanText(text: string): Promise<ScanResult>;

/** Scan one local regular file with filesystem rules and path metadata. */
export function scanFile(path: string): Promise<ScanResult>;
