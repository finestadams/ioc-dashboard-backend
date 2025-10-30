import { IOCType, IOCVerdict, IOCCategory } from '../dtos/ioc.dto';

export interface ThreatIntelligenceProvider {
  name: string;
  checkIOC(value: string, type: IOCType): Promise<ThreatIntelligenceResult>;
  isSupported(type: IOCType): boolean;
  getRateLimit(): { requests: number; window: number };
}

export interface ThreatIntelligenceResult {
  provider: string;
  verdict: IOCVerdict;
  category: IOCCategory;
  confidence: number;
  detectionCount?: number;
  totalEngines?: number;
  lastSeen?: Date;
  metadata: Record<string, any>;
}

export interface CachedResult {
  value: string;
  type: IOCType;
  results: ThreatIntelligenceResult[];
  cachedAt: Date;
  expiresAt: Date;
}

export interface FileAnalysisResult {
  filename: string;
  fileSize: number;
  mimeType: string;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  verdict: IOCVerdict;
  category: IOCCategory;
  detectionCount: number;
  totalEngines: number;
  metadata: Record<string, any>;
}

export interface BulkProcessingOptions {
  batchSize?: number;
  delayBetweenRequests?: number;
  skipCache?: boolean;
}