import { IsEnum, IsNotEmpty, IsOptional, IsString, IsArray, ValidateNested } from 'class-validator';
import { Transform, Type } from 'class-transformer';

export enum IOCType {
  HASH = 'hash',
  URL = 'url',
  IP = 'ip',
  DOMAIN = 'domain',
  FILE = 'file'
}

export enum IOCVerdict {
  CLEAN = 'clean',
  SUSPICIOUS = 'suspicious',
  MALICIOUS = 'malicious',
  UNKNOWN = 'unknown'
}

export enum IOCCategory {
  PHISHING = 'phishing',
  MALWARE = 'malware',
  BOTNET = 'botnet',
  SPAM = 'spam',
  C2 = 'c2',
  RANSOMWARE = 'ransomware',
  UNKNOWN = 'unknown'
}

export class SingleIOCDto {
  @IsNotEmpty()
  @IsString()
  value: string;

  @IsEnum(IOCType)
  type: IOCType;

  @IsOptional()
  @IsString()
  description?: string;
}

export class BulkIOCDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SingleIOCDto)
  iocs: SingleIOCDto[];
}

export class IOCResultDto {
  id: string;
  value: string;
  type: IOCType;
  verdict: IOCVerdict;
  category: IOCCategory;
  confidence: number;
  detectionCount: number;
  totalEngines: number;
  lastSeen?: Date;
  sources: string[];
  metadata: Record<string, any>;
  createdAt: Date;
}

export class FileUploadDto {
  @IsOptional()
  @IsString()
  description?: string;
}

export class BulkAnalysisResultDto {
  totalProcessed: number;
  results: IOCResultDto[];
  errors: Array<{
    value: string;
    error: string;
  }>;
  summary: {
    clean: number;
    suspicious: number;
    malicious: number;
    unknown: number;
  };
}