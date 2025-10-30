import { Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { Cache } from 'cache-manager';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { IOCType, IOCVerdict, IOCCategory, IOCResultDto, BulkAnalysisResultDto } from '../dtos/ioc.dto';
import { 
  ThreatIntelligenceProvider, 
  ThreatIntelligenceResult, 
  CachedResult, 
  FileAnalysisResult,
  BulkProcessingOptions 
} from '../interfaces/threat-intelligence.interface';
import { VirusTotalProvider } from '../providers/virustotal.provider';
import { AbuseIPDBProvider } from '../providers/abuseipdb.provider';
import { URLScanProvider } from '../providers/urlscan.provider';
import { IOCAnalysisResult } from '../entities/ioc-analysis.entity';
import { ApiRateLimit } from '../entities/api-rate-limit.entity';

@Injectable()
export class IOCService {
  private readonly providers: ThreatIntelligenceProvider[] = [];
  private readonly cacheTimeout = 3600000; // 1 hour

  constructor(
    private configService: ConfigService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private virusTotalProvider: VirusTotalProvider,
    private abuseIPDBProvider: AbuseIPDBProvider,
    private urlScanProvider: URLScanProvider,
    @Optional() @InjectRepository(IOCAnalysisResult)
    private iocRepository?: Repository<IOCAnalysisResult>,
    @Optional() @InjectRepository(ApiRateLimit)
    private rateLimitRepository?: Repository<ApiRateLimit>,
  ) {
    this.providers = [
      this.virusTotalProvider,
      this.abuseIPDBProvider,
      this.urlScanProvider,
    ];
  }

  async analyzeSingleIOC(value: string, type: IOCType): Promise<IOCResultDto> {
    if (this.iocRepository) {
      try {
        const valueHash = this.generateValueHash(value);
        const dbResult = await this.iocRepository.findOne({
          where: { 
            valueHash: valueHash, 
            type: type,
            expiresAt: MoreThan(new Date()) 
          },
          order: { updatedAt: 'DESC' }
        });
        
        if (dbResult) {
    
          return this.convertDbResultToIOCResult(dbResult);
        }
      } catch (error) {

      }
    }
    
    
    const cacheKey = this.generateCacheKey(value, type);
    const cachedResult = await this.getCachedResult(cacheKey);
    
    if (cachedResult) {

      return this.convertToIOCResult(value, type, cachedResult.results);
    }

    
    const applicableProviders = this.providers.filter(provider => 
      provider.isSupported(type)
    );

    if (applicableProviders.length === 0) {

      return this.createDefaultResult(value, type);
    }

    
    const results: ThreatIntelligenceResult[] = [];
    
    for (const provider of applicableProviders) {
      try {
        
        if (this.rateLimitRepository) {
          await this.checkAndUpdateRateLimit(provider);
        }
        

        const result = await provider.checkIOC(value, type);
        results.push(result);
        
        
        await this.delayForRateLimit(provider);
      } catch (error) {
 
      }
    }

    
    await this.cacheResults(cacheKey, value, type, results);

  
    const iocResult = this.convertToIOCResult(value, type, results);
    if (this.iocRepository) {
      await this.saveToDatabase(iocResult);
    }

    return iocResult;
  }

  async analyzeBulkIOCs(
    iocs: Array<{ value: string; type: IOCType }>,
    options: BulkProcessingOptions = {}
  ): Promise<BulkAnalysisResultDto> {

    
    const {
      batchSize = 10,
      delayBetweenRequests = 1000,
      skipCache = false
    } = options;

    const results: IOCResultDto[] = [];
    const errors: Array<{ value: string; error: string }> = [];
    
 
    for (let i = 0; i < iocs.length; i += batchSize) {
      const batch = iocs.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (ioc) => {
        try {
          return await this.analyzeSingleIOC(ioc.value, ioc.type);
        } catch (error) {
          errors.push({
            value: ioc.value,
            error: error.message
          });
          return null;
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults.filter(result => result !== null));

      // Delay between batches to respect rate limits
      if (i + batchSize < iocs.length) {
        await this.delay(delayBetweenRequests);
      }
    }

    // Generate summary
    const summary = this.generateSummary(results);

    return {
      totalProcessed: iocs.length,
      results,
      errors,
      summary
    };
  }

  async analyzeFile(filePath: string, originalName: string): Promise<FileAnalysisResult> {

    
    try {

      const fileBuffer = fs.readFileSync(filePath);
      const fileSize = fileBuffer.length;
      
      const hashes = {
        md5: crypto.createHash('md5').update(fileBuffer).digest('hex'),
        sha1: crypto.createHash('sha1').update(fileBuffer).digest('hex'),
        sha256: crypto.createHash('sha256').update(fileBuffer).digest('hex'),
      };

 
      // Dynamically import the ESM-only `file-type` package and handle
      // both named and default export shapes so this works after compilation
      // regardless of module interop settings.
      // Try to use the ESM-only `file-type` package; if it fails (older Node or
      // ESM interop issues), fall back to a simple extension-based MIME lookup.
      let mimeType = 'application/octet-stream';
      try {
        const _fileTypeMod: any = await import('file-type');
        const fileTypeFromBuffer: ((buf: Buffer) => Promise<any>) | undefined =
          _fileTypeMod.fileTypeFromBuffer || _fileTypeMod.default?.fileTypeFromBuffer;
        const fileType = fileTypeFromBuffer ? await fileTypeFromBuffer(fileBuffer) : undefined;
        if (fileType?.mime) mimeType = fileType.mime;
      } catch (err) {
        // Fallback: derive mime from file extension for common types
        const ext = (originalName && path.extname(originalName).toLowerCase()) || '';
        const extMap: Record<string, string> = {
          '.exe': 'application/x-msdownload',
          '.dll': 'application/x-msdownload',
          '.pdf': 'application/pdf',
          '.zip': 'application/zip',
          '.tar': 'application/x-tar',
          '.gz': 'application/gzip',
          '.csv': 'text/csv',
          '.xls': 'application/vnd.ms-excel',
          '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          '.json': 'application/json',
          '.js': 'application/javascript',
          '.html': 'text/html',
          '.htm': 'text/html',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.jpeg': 'image/jpeg',
          '.gif': 'image/gif',
          '.txt': 'text/plain',
        };
        if (ext && extMap[ext]) {
          mimeType = extMap[ext];
        }
      }

    
      const iocResult = await this.analyzeSingleIOC(hashes.sha256, IOCType.HASH);

      return {
        filename: originalName,
        fileSize,
        mimeType,
        hashes,
        verdict: iocResult.verdict,
        category: iocResult.category,
        detectionCount: iocResult.detectionCount,
        totalEngines: iocResult.totalEngines,
        metadata: {
          ...iocResult.metadata,
          originalFilename: originalName,
        }
      };
    } catch (error) {

      throw error;
    }
  }

  private async getCachedResult(cacheKey: string): Promise<CachedResult | null> {
    try {
      return await this.cacheManager.get<CachedResult>(cacheKey);
    } catch (error) {
  // cache error
      return null;
    }
  }

  private async cacheResults(
    cacheKey: string,
    value: string,
    type: IOCType,
    results: ThreatIntelligenceResult[]
  ): Promise<void> {
    try {
      const cachedResult: CachedResult = {
        value,
        type,
        results,
        cachedAt: new Date(),
        expiresAt: new Date(Date.now() + this.cacheTimeout)
      };
      
      await this.cacheManager.set(cacheKey, cachedResult, this.cacheTimeout);
    } catch (error) {
  // cache error
    }
  }

  private convertToIOCResult(
    value: string,
    type: IOCType,
    results: ThreatIntelligenceResult[]
  ): IOCResultDto {
    if (results.length === 0) {
      return this.createDefaultResult(value, type);
    }

    // Aggregate results from multiple providers
    const overallVerdict = this.aggregateVerdicts(results);
    const overallCategory = this.aggregateCategories(results);
    const averageConfidence = this.calculateAverageConfidence(results);
    const totalDetections = results.reduce((sum, r) => sum + (r.detectionCount || 0), 0);
    const totalEngines = results.reduce((sum, r) => sum + (r.totalEngines || 0), 0);
    const sources = results.map(r => r.provider);
    const latestSeen = this.getLatestSeenDate(results);
    
    // Merge all metadata
    const metadata = results.reduce((acc, result) => ({
      ...acc,
      [result.provider]: result.metadata
    }), {});

    return {
      id: this.generateResultId(value, type),
      value,
      type,
      verdict: overallVerdict,
      category: overallCategory,
      confidence: averageConfidence,
      detectionCount: totalDetections,
      totalEngines,
      lastSeen: latestSeen,
      sources,
      metadata,
      createdAt: new Date()
    };
  }

  private aggregateVerdicts(results: ThreatIntelligenceResult[]): IOCVerdict {
    const verdicts = results.map(r => r.verdict);
    
    if (verdicts.includes(IOCVerdict.MALICIOUS)) {
      return IOCVerdict.MALICIOUS;
    } else if (verdicts.includes(IOCVerdict.SUSPICIOUS)) {
      return IOCVerdict.SUSPICIOUS;
    } else if (verdicts.includes(IOCVerdict.CLEAN)) {
      return IOCVerdict.CLEAN;
    }
    
    return IOCVerdict.UNKNOWN;
  }

  private aggregateCategories(results: ThreatIntelligenceResult[]): IOCCategory {
    const categories = results
      .map(r => r.category)
      .filter(c => c !== IOCCategory.UNKNOWN);
    
    if (categories.length === 0) return IOCCategory.UNKNOWN;
    
    // Check priority categories
    if (categories.some(c => c === IOCCategory.RANSOMWARE)) return IOCCategory.RANSOMWARE;
    if (categories.some(c => c === IOCCategory.MALWARE)) return IOCCategory.MALWARE;
    if (categories.some(c => c === IOCCategory.PHISHING)) return IOCCategory.PHISHING;
    if (categories.some(c => c === IOCCategory.BOTNET)) return IOCCategory.BOTNET;
    if (categories.some(c => c === IOCCategory.C2)) return IOCCategory.C2;
    if (categories.some(c => c === IOCCategory.SPAM)) return IOCCategory.SPAM;

    return categories[0];
  }

  private calculateAverageConfidence(results: ThreatIntelligenceResult[]): number {
    const confidences = results.map(r => r.confidence);
    return Math.round(confidences.reduce((sum, c) => sum + c, 0) / confidences.length);
  }

  private getLatestSeenDate(results: ThreatIntelligenceResult[]): Date | undefined {
    const dates = results
      .map(r => r.lastSeen)
      .filter(d => d !== undefined)
      .sort((a, b) => b.getTime() - a.getTime());
    
    return dates.length > 0 ? dates[0] : undefined;
  }

  private generateSummary(results: IOCResultDto[]) {
    return {
      clean: results.filter(r => r.verdict === IOCVerdict.CLEAN).length,
      suspicious: results.filter(r => r.verdict === IOCVerdict.SUSPICIOUS).length,
      malicious: results.filter(r => r.verdict === IOCVerdict.MALICIOUS).length,
      unknown: results.filter(r => r.verdict === IOCVerdict.UNKNOWN).length,
    };
  }

  private createDefaultResult(value: string, type: IOCType): IOCResultDto {
    return {
      id: this.generateResultId(value, type),
      value,
      type,
      verdict: IOCVerdict.UNKNOWN,
      category: IOCCategory.UNKNOWN,
      confidence: 0,
      detectionCount: 0,
      totalEngines: 0,
      sources: [],
      metadata: {},
      createdAt: new Date()
    };
  }

  private generateCacheKey(value: string, type: IOCType): string {
    return `ioc:${type}:${crypto.createHash('sha256').update(value).digest('hex')}`;
  }

  private generateResultId(value: string, type: IOCType): string {
    return crypto.createHash('sha256').update(`${type}:${value}:${Date.now()}`).digest('hex').substring(0, 16);
  }

  private async delayForRateLimit(provider: ThreatIntelligenceProvider): Promise<void> {
    const rateLimit = provider.getRateLimit();
    const delayMs = Math.ceil(rateLimit.window / rateLimit.requests);
    await this.delay(delayMs);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private generateValueHash(value: string): string {
    return crypto.createHash('sha256').update(value.toLowerCase().trim()).digest('hex');
  }

  private convertDbResultToIOCResult(dbResult: IOCAnalysisResult): IOCResultDto {
    return {
      id: dbResult.id,
      value: dbResult.value,
      type: dbResult.type,
      verdict: dbResult.verdict,
      category: dbResult.category,
      confidence: dbResult.confidence,
      detectionCount: dbResult.detectionCount,
      totalEngines: dbResult.totalEngines,
      lastSeen: dbResult.lastSeen,
      sources: this.extractSourcesFromProviders(dbResult.providers),
      metadata: dbResult.metadata || {},
      createdAt: dbResult.createdAt
    };
  }

  private extractSourcesFromProviders(providers: any): string[] {
    if (!providers || typeof providers !== 'object') return [];
    return Object.keys(providers);
  }

  private async saveToDatabase(result: IOCResultDto): Promise<void> {
    if (!this.iocRepository) return;
    
    try {
      const entity = new IOCAnalysisResult();
      entity.value = result.value;
      entity.valueHash = this.generateValueHash(result.value);
      entity.type = result.type;
      entity.verdict = result.verdict;
      entity.category = result.category;
      entity.confidence = result.confidence;
      entity.detectionCount = result.detectionCount;
      entity.totalEngines = result.totalEngines;
      entity.providers = this.convertSourcesToProviders(result.sources, result.metadata);
      entity.metadata = result.metadata;
      entity.lastSeen = result.lastSeen;
      entity.description = this.generateDescription(result);
      

      entity.expiresAt = new Date();
      entity.expiresAt.setHours(entity.expiresAt.getHours() + 24);

      await this.iocRepository.save(entity);

    } catch (error) {

    }
  }

  private convertSourcesToProviders(sources: string[], metadata: any): any {
    const providers = {};
    sources.forEach(source => {
      providers[source] = metadata[source] || { queried: true };
    });
    return providers;
  }

  private generateDescription(result: IOCResultDto): string {
    return `${result.type.toUpperCase()} analysis: ${result.verdict} (confidence: ${result.confidence}%)`;
  }


  private async checkAndUpdateRateLimit(provider: ThreatIntelligenceProvider): Promise<void> {
    if (!this.rateLimitRepository) return;

    try {
      const now = new Date();

      
      const declared = provider.getRateLimit && provider.getRateLimit();
      const windowDuration = (declared && declared.window) ? declared.window : 60000; 
      const maxRequests = (declared && declared.requests) ? declared.requests : 10;

  
      let rateLimitRecord = await this.rateLimitRepository.findOne({
        where: { provider: provider.name }
      });

      if (!rateLimitRecord) {
   
        rateLimitRecord = new ApiRateLimit();
        rateLimitRecord.provider = provider.name;
        rateLimitRecord.requestCount = 0;
        rateLimitRecord.windowStart = now;
        rateLimitRecord.windowDuration = windowDuration;
        rateLimitRecord.maxRequests = maxRequests;
      } else {

        if (!rateLimitRecord.windowDuration) rateLimitRecord.windowDuration = windowDuration;
        if (!rateLimitRecord.maxRequests) rateLimitRecord.maxRequests = maxRequests;
      }

   
      const timeSinceWindowStart = now.getTime() - rateLimitRecord.windowStart.getTime();
      if (timeSinceWindowStart >= rateLimitRecord.windowDuration) {
   
        rateLimitRecord.requestCount = 0;
        rateLimitRecord.windowStart = now;
      }

  
      if (rateLimitRecord.requestCount >= rateLimitRecord.maxRequests) {
        const resetTime = new Date(rateLimitRecord.windowStart.getTime() + rateLimitRecord.windowDuration);
        const waitTime = Math.ceil((resetTime.getTime() - now.getTime()) / 1000);
        throw new Error(`Rate limit exceeded for ${provider.name}. Try again in ${waitTime} seconds.`);
      }


      rateLimitRecord.requestCount++;
      await this.rateLimitRepository.save(rateLimitRecord);


    } catch (error) {

      throw error;
    }
  }

  detectIOCType(value: string): IOCType {

    const cleanValue = value.trim().toLowerCase();
    
    // Hash patterns (MD5, SHA1, SHA256)
    if (/^[a-f0-9]{32}$/.test(cleanValue)) return IOCType.HASH; // MD5
    if (/^[a-f0-9]{40}$/.test(cleanValue)) return IOCType.HASH; // SHA1
    if (/^[a-f0-9]{64}$/.test(cleanValue)) return IOCType.HASH; // SHA256
    
    // URL pattern
    if (/^https?:\/\//.test(cleanValue)) return IOCType.URL;
    
    // IP address pattern
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleanValue)) {
      const parts = cleanValue.split('.');
      if (parts.every(part => parseInt(part) <= 255)) {
        return IOCType.IP;
      }
    }
    
    // Domain pattern (basic)
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(cleanValue)) {
      return IOCType.DOMAIN;
    }
    
  
    if (/^[a-f0-9]+$/.test(cleanValue)) return IOCType.HASH;

    return IOCType.DOMAIN;
  }

  async getAnalytics(days: number = 7): Promise<any> {

    if (!this.iocRepository) {
      return this.getAnalyticsFromMemory(days);
    }

    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const results = await this.iocRepository.find({
        where: {
          createdAt: MoreThan(startDate)
        },
        order: { createdAt: 'DESC' }
      });

      // Group results by date
      const dailyStats: Record<string, any> = {};
      const verdictCounts = {
        clean: 0,
        suspicious: 0,
        malicious: 0,
        unknown: 0
      };
      const typeCounts = {
        ip: 0,
        url: 0,
        hash: 0,
        domain: 0,
        file: 0
      };
      const categoryCounts: Record<string, number> = {};

      results.forEach(result => {
        const date = result.createdAt.toISOString().split('T')[0];
        
        if (!dailyStats[date]) {
          dailyStats[date] = {
            total: 0,
            malicious: 0,
            suspicious: 0,
            clean: 0,
            unknown: 0
          };
        }

        dailyStats[date].total++;
        dailyStats[date][result.verdict]++;
        
        verdictCounts[result.verdict]++;
        typeCounts[result.type]++;
        
        const category = result.category || 'unknown';
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
      });

      const totalAnalyzed = results.length;
      const averageConfidence = totalAnalyzed > 0 
        ? results.reduce((sum, r) => sum + r.confidence, 0) / totalAnalyzed 
        : 0;

      return {
        summary: {
          totalAnalyzed,
          verdictBreakdown: verdictCounts,
          typeBreakdown: typeCounts,
          categoryBreakdown: categoryCounts,
          averageConfidence: Math.round(averageConfidence * 100) / 100,
          dateRange: {
            from: startDate.toISOString().split('T')[0],
            to: new Date().toISOString().split('T')[0]
          }
        },
        dailyStats,
        recentAnalyses: results.slice(0, 10).map(result => ({
          id: result.id,
          value: result.value,
          type: result.type,
          verdict: result.verdict,
          category: result.category,
          confidence: result.confidence,
          createdAt: result.createdAt
        }))
      };
    } catch (error) {
      return this.getAnalyticsFromMemory(days);
    }
  }

  async getRecentAnalyses(limit: number = 10): Promise<any[]> {
    if (!this.iocRepository) {
      return [];
    }

    try {
      const results = await this.iocRepository.find({
        order: { createdAt: 'DESC' },
        take: limit
      });

      return results.map(result => ({
        id: result.id,
        value: result.value,
        type: result.type,
        verdict: result.verdict,
        confidence: result.confidence,
        createdAt: result.createdAt
      }));
    } catch (error) {

      return [];
    }
  }

  private getAnalyticsFromMemory(days: number): any {

    return {
      summary: {
        totalAnalyzed: 0,
        verdictBreakdown: {
          clean: 0,
          suspicious: 0,
          malicious: 0,
          unknown: 0
        },
        typeBreakdown: {
          ip: 0,
          url: 0,
          hash: 0,
          domain: 0,
          file: 0
        },
        categoryBreakdown: {},
        averageConfidence: 0,
        dateRange: {
          from: new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          to: new Date().toISOString().split('T')[0]
        }
      },
      dailyStats: {},
      recentAnalyses: [],
      note: 'Analytics from database not available. Data shown is from current session only.'
    };
  }
}