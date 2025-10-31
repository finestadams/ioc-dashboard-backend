import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';
import { IOCType, IOCVerdict, IOCCategory } from '../dtos/ioc.dto';
import { ThreatIntelligenceProvider, ThreatIntelligenceResult } from '../interfaces/threat-intelligence.interface';


@Injectable()
export class VirusTotalProvider implements ThreatIntelligenceProvider {

  private readonly httpClient: AxiosInstance;
  private readonly apiKey: string;
  public readonly name = 'VirusTotal';

  constructor(private configService: ConfigService) {
    this.apiKey = this.configService.get<string>('VIRUSTOTAL_API_KEY', '');
    this.httpClient = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      headers: {
        'x-apikey': this.apiKey,
      },
      timeout: 10000,
    });

  }

  isSupported(type: IOCType): boolean {
    return [IOCType.HASH, IOCType.URL, IOCType.IP, IOCType.DOMAIN].includes(type);
  }

  getRateLimit(): { requests: number; window: number } {
    return { requests: 4, window: 60000 }; // 4 requests per minute for free tier
  }

  async checkIOC(value: string, type: IOCType): Promise<ThreatIntelligenceResult> {
    if (!this.apiKey) {
      return this.createDefaultResult();
    }

    try {
      switch (type) {
        case IOCType.HASH:
          return await this.checkFile(value);
        case IOCType.URL:
          return await this.checkUrl(value);
        case IOCType.IP:
          return await this.checkIp(value);
        case IOCType.DOMAIN:
          return await this.checkDomain(value);
        default:
          throw new Error(`Unsupported IOC type: ${type}`);
      }
    } catch (error) {
      return this.createDefaultResult();
    }
  }

  private async checkFile(hash: string): Promise<ThreatIntelligenceResult> {
    const response = await this.httpClient.get(`/files/${hash}`);
    const data = response.data.data;
    
    const stats = data.attributes.last_analysis_stats || {};
    const malicious = this.safeParseInt(stats.malicious);
    const suspicious = this.safeParseInt(stats.suspicious);
    const total: number = Object.values(stats).reduce<number>((sum: number, count: unknown) => sum + this.safeParseInt(count), 0);

    return {
      provider: this.name,
      verdict: this.determineVerdict(malicious, suspicious, total),
      category: this.determineCategory(data.attributes.last_analysis_results),
      confidence: this.calculateConfidence(malicious, suspicious, total),
      detectionCount: malicious + suspicious,
      totalEngines: total,
      lastSeen: new Date(data.attributes.last_submission_date * 1000),
      metadata: {
        sha256: data.attributes.sha256,
        md5: data.attributes.md5,
        sha1: data.attributes.sha1,
        fileSize: data.attributes.size,
        fileType: data.attributes.type_description,
        names: data.attributes.names,
      },
    };
  }

  private async checkUrl(url: string): Promise<ThreatIntelligenceResult> {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await this.httpClient.get(`/urls/${urlId}`);
    const data = response.data.data;
    console.log('[VirusTotal] URL data from VirusTotal', data);
    const stats = data.attributes.last_analysis_stats || {};
    const malicious = this.safeParseInt(stats.malicious);
    const suspicious = this.safeParseInt(stats.suspicious);
    const total: number = Object.values(stats).reduce<number>((sum: number, count: unknown) => sum + this.safeParseInt(count), 0);

    return {
      provider: this.name,
      verdict: this.determineVerdict(malicious, suspicious, total),
      category: this.determineUrlCategory(data.attributes.categories),
      confidence: this.calculateConfidence(malicious, suspicious, total),
      detectionCount: malicious + suspicious,
      totalEngines: total,
      lastSeen: new Date(data.attributes.last_submission_date * 1000),
      metadata: {
        url: data.attributes.url,
        title: data.attributes.title,
        categories: data.attributes.categories,
      },
    };
  }

  private async checkIp(ip: string): Promise<ThreatIntelligenceResult> {
    const response = await this.httpClient.get(`/ip_addresses/${ip}`);
    const data = response.data.data;
    console.log('[VirusTotal] IP data from VirusTotal', data);
    const stats = data.attributes.last_analysis_stats || {};
    const malicious = this.safeParseInt(stats.malicious);
    const suspicious = this.safeParseInt(stats.suspicious);
    const total: number = Object.values(stats).reduce<number>((sum: number, count: unknown) => sum + this.safeParseInt(count), 0);

    return {
      provider: this.name,
      verdict: this.determineVerdict(malicious, suspicious, total),
      category: this.determineIpCategory(data.attributes),
      confidence: this.calculateConfidence(malicious, suspicious, total),
      detectionCount: malicious + suspicious,
      totalEngines: total,
      metadata: {
        asOwner: data.attributes.as_owner,
        country: data.attributes.country,
        network: data.attributes.network,
      },
    };
  }

  private async checkDomain(domain: string): Promise<ThreatIntelligenceResult> {
    const response = await this.httpClient.get(`/domains/${domain}`);
    const data = response.data.data;
    console.log('[VirusTotal] Domain data from VirusTotal', data);
    const stats = data.attributes.last_analysis_stats || {};
    const malicious = this.safeParseInt(stats.malicious);
    const suspicious = this.safeParseInt(stats.suspicious);
    const total: number = Object.values(stats).reduce<number>((sum: number, count: unknown) => sum + this.safeParseInt(count), 0);

      
    return {
      provider: this.name,
      verdict: this.determineVerdict(malicious, suspicious, total),
      category: this.determineDomainCategory(data.attributes.categories),
      confidence: this.calculateConfidence(malicious, suspicious, total),
      detectionCount: malicious + suspicious,
      totalEngines: total,
      lastSeen: new Date(data.attributes.last_modification_date * 1000),
      metadata: {
        registrar: data.attributes.registrar,
        creationDate: data.attributes.creation_date,
        categories: data.attributes.categories,
      },
    };
  }

  private determineVerdict(malicious: number, suspicious: number, total: number): IOCVerdict {
    const detectionRatio = (malicious + suspicious) / total;
    console.log('Determining verdict with - virus Total:', { malicious, suspicious, total, detectionRatio });
    if (malicious > 0 || detectionRatio > 0.1) {
      return IOCVerdict.MALICIOUS;
    } else if (suspicious > 0 || detectionRatio > 0.05) {
      return IOCVerdict.SUSPICIOUS;
    } else if (total > 0) {
      return IOCVerdict.CLEAN;
    }
    
    return IOCVerdict.UNKNOWN;
    }
    

  private determineCategory(analysisResults: any): IOCCategory {
      const results = Object.values(analysisResults || {}) as any[];
      console.log('Determining category with - virus Total:', results);
    const categories = results
      .map(result => result.category)
      .filter(Boolean);

    if (categories.includes('trojan') || categories.includes('malware')) {
      return IOCCategory.MALWARE;
    } else if (categories.includes('ransomware')) {
      return IOCCategory.RANSOMWARE;
    } else if (categories.includes('phishing')) {
      return IOCCategory.PHISHING;
    }

    return IOCCategory.UNKNOWN;
  }

  private determineUrlCategory(categories: any): IOCCategory {
    const categoryList = Object.keys(categories || {});
    console.log('Determining URL category with - virus Total:', categoryList);
    if (categoryList.includes('phishing')) {
      return IOCCategory.PHISHING;
    } else if (categoryList.includes('malware')) {
      return IOCCategory.MALWARE;
    }

    return IOCCategory.UNKNOWN;
  }

  private determineIpCategory(attributes: any): IOCCategory {
    // Determine category based on IP attributes
    return IOCCategory.UNKNOWN;
  }

  private determineDomainCategory(categories: any): IOCCategory {
    const categoryList = Object.keys(categories || {});
    console.log('Determining domain category with - virus Total:', categoryList);
    if (categoryList.includes('phishing')) {
      return IOCCategory.PHISHING;
    } else if (categoryList.includes('malware')) {
      return IOCCategory.MALWARE;
    }

    return IOCCategory.UNKNOWN;
  }

  private calculateConfidence(malicious: number, suspicious: number, total: number): number {
    if (total === 0) return 0;
    
    const detectionRatio = (malicious + suspicious) / total;
    return Math.min(100, Math.round(detectionRatio * 100 + (total / 50) * 10));
  }

  private safeParseInt(value: unknown): number {
    if (typeof value === 'number') return Math.floor(value);
    if (typeof value === 'string') {
      const parsed = parseInt(value, 10);
      return isNaN(parsed) ? 0 : parsed;
    }
    return 0;
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