import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';
import { IOCType, IOCVerdict, IOCCategory } from '../dtos/ioc.dto';
import { ThreatIntelligenceProvider, ThreatIntelligenceResult } from '../interfaces/threat-intelligence.interface';


@Injectable()
export class URLScanProvider implements ThreatIntelligenceProvider {
  // logging removed per user request; provider-level HTTP client logs were kept elsewhere
  private readonly httpClient: AxiosInstance;
  private readonly apiKey: string;
  public readonly name = 'URLScan.io';

  constructor(private configService: ConfigService) {
    this.apiKey = this.configService.get<string>('URLSCAN_API_KEY', '');
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    this.httpClient = axios.create({
      baseURL: 'https://urlscan.io/api/v1',
      headers,
      timeout: 15000,
    });
  }

  isSupported(type: IOCType): boolean {
    return [IOCType.URL, IOCType.DOMAIN].includes(type);
  }

  getRateLimit(): { requests: number; window: number } {
    return { requests: 100, window: 3600000 }; 
  }

  async checkIOC(value: string, type: IOCType): Promise<ThreatIntelligenceResult> {
    if (!this.apiKey) {
      return this.createDefaultResult();
    }

    try {
      switch (type) {
        case IOCType.URL:
          return await this.checkUrl(value);
        case IOCType.DOMAIN:
          return await this.checkDomain(value);
        default:
          throw new Error(`URLScan.io only supports URLs and domains, got: ${type}`);
      }
    } catch (error) {
      // Error checking (logging removed)
      return this.createDefaultResult();
    }
  }

  private async checkUrl(url: string): Promise<ThreatIntelligenceResult> {
    try {
      const domain = this.extractDomainFromUrl(url);
      const searchResponse = await this.httpClient.get('/search/', {
        params: {
          q: `domain:${domain}`,
          size: 5,
        },
      });

      const results = searchResponse.data.results;
      
      if (results && results.length > 0) {
        // Look for exact URL match first, then fall back to domain match
        const exactMatch = results.find(r => r.page && r.page.url === url);
        const scan = exactMatch || results[0];
        return await this.getResultFromScan(scan);
      }

      // If no existing scan found, submit new scan (if API key available)
      if (this.apiKey) {
        try {
          const submitResponse = await this.httpClient.post('/scan/', { 
            url: url,
            visibility: 'public'
          });
          const scanId = submitResponse.data.uuid;
          
          // Return pending result since URLScan takes time to complete
          return {
            provider: this.name,
            verdict: IOCVerdict.UNKNOWN,
            category: IOCCategory.UNKNOWN,
            confidence: 0,
            metadata: {
              url: url,
              scanId: scanId,
              status: 'pending',
              message: 'Scan submitted, results will be available shortly'
            },
          };
        } catch (error) {
          // Failed to submit scan (logging removed)
        }
      }
    } catch (error) {
      // URLScan search failed (logging removed)
    }

    return this.createDefaultResult();
  }

  private async checkDomain(domain: string): Promise<ThreatIntelligenceResult> {
    try {
   
      const searchResponse = await this.httpClient.get('/search/', {
        params: {
          q: `domain:${domain}`,
          size: 5,
        },
      });

      const results = searchResponse.data.results;
      console.log('[URLScan] search results for domain:', results);
      if (results && results.length > 0) {
        // Analyze the most recent results
        const recentScan = results[0];
        return await this.getResultFromScan(recentScan);
      }
    } catch (error) {
      // URLScan search failed for domain (logging removed)
    }

    return this.createDefaultResult();
  }

  private async getResultFromScan(scan: any): Promise<ThreatIntelligenceResult> {
    try {
        const resultResponse = await this.httpClient.get(`/result/${scan.task.uuid}/`);
        console.log('[URLScan] result data from scan:', resultResponse.data);
      return this.parseResult(resultResponse.data);
    } catch (error) {
      // Fall back to basic scan data
      return {
        provider: this.name,
        verdict: this.determineVerdictFromScan(scan),
        category: this.determineCategoryFromScan(scan),
        confidence: 50,
        lastSeen: new Date(scan.task.time),
        metadata: {
          url: scan.page.url,
          domain: scan.page.domain,
          country: scan.page.country,
          server: scan.page.server,
        },
      };
    }
  }

  private parseResult(result: any): ThreatIntelligenceResult {
    const verdicts = result.verdicts || {};
    const lists = result.lists || {};
    
    const overallVerdict = verdicts.overall || {};
    const malicious = overallVerdict.malicious || false;
    const suspicious = overallVerdict.suspicious || false;
    
    // Count detections from various lists
    const detectionCount = Object.values(lists).filter((list: any) => 
      list && (list.malicious || list.suspicious)
    ).length;

    return {
      provider: this.name,
      verdict: this.determineVerdictFromResult(malicious, suspicious, detectionCount),
      category: this.determineCategoryFromResult(result),
      confidence: this.calculateConfidence(malicious, suspicious, detectionCount),
      detectionCount,
      lastSeen: new Date(result.task.time),
      metadata: {
        url: result.page.url,
        domain: result.page.domain,
        ip: result.page.ip,
        country: result.page.country,
        title: result.page.title,
        verdicts: verdicts,
        screenshot: result.task.screenshotURL,
      },
    };
  }

  private determineVerdictFromResult(malicious: boolean, suspicious: boolean, detectionCount: number): IOCVerdict {
    if (malicious || detectionCount >= 3) {
      return IOCVerdict.MALICIOUS;
    } else if (suspicious || detectionCount >= 1) {
      return IOCVerdict.SUSPICIOUS;
    } else if (detectionCount === 0) {
      return IOCVerdict.CLEAN;
    }
    
    return IOCVerdict.UNKNOWN;
  }

  private determineVerdictFromScan(scan: any): IOCVerdict {
    // Basic heuristics based on scan metadata
    const url = scan.page.url || '';
    
    if (url.includes('phishing') || url.includes('malware')) {
      return IOCVerdict.SUSPICIOUS;
    }
    
    return IOCVerdict.UNKNOWN;
  }

  private determineCategoryFromResult(result: any): IOCCategory {
    const verdicts = result.verdicts || {};
    const categories = Object.keys(verdicts);
    
    if (categories.includes('phishing')) {
      return IOCCategory.PHISHING;
    } else if (categories.includes('malware')) {
      return IOCCategory.MALWARE;
    }

    return IOCCategory.UNKNOWN;
  }

  private determineCategoryFromScan(scan: any): IOCCategory {
    const url = scan.page.url || '';
    
    if (url.includes('phishing')) {
      return IOCCategory.PHISHING;
    } else if (url.includes('malware')) {
      return IOCCategory.MALWARE;
    }

    return IOCCategory.UNKNOWN;
  }

  private calculateConfidence(malicious: boolean, suspicious: boolean, detectionCount: number): number {
    if (malicious) return 90;
    if (suspicious) return 70;
    if (detectionCount > 0) return 60;
    return 30;
  }

  private extractDomainFromUrl(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      // If URL parsing fails, assume it's already a domain
      return url.replace(/^https?:\/\//, '').split('/')[0];
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private createDefaultResult(): ThreatIntelligenceResult {
    return {
      provider: this.name,
      verdict: IOCVerdict.UNKNOWN,
      category: IOCCategory.UNKNOWN,
      confidence: 0,
      metadata: {},
    };
  }
}