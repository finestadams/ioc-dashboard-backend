import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';
import { IOCType, IOCVerdict, IOCCategory } from '../dtos/ioc.dto';
import { ThreatIntelligenceProvider, ThreatIntelligenceResult } from '../interfaces/threat-intelligence.interface';


@Injectable()
export class AbuseIPDBProvider implements ThreatIntelligenceProvider {

  private readonly httpClient: AxiosInstance;
  private readonly apiKey: string;
  public readonly name = 'AbuseIPDB';

  constructor(private configService: ConfigService) {
    this.apiKey = this.configService.get<string>('ABUSEIPDB_API_KEY');
    this.httpClient = axios.create({
      baseURL: 'https://api.abuseipdb.com/api/v2',
      headers: {
        'Key': this.apiKey,
        'Accept': 'application/json',
      },
      timeout: 10000,
    });
  }

  isSupported(type: IOCType): boolean {
    return type === IOCType.IP;
  }

  getRateLimit(): { requests: number; window: number } {
    return { requests: 1000, window: 86400000 }; 
  }

  async checkIOC(value: string, type: IOCType): Promise<ThreatIntelligenceResult> {
    if (!this.apiKey) {
  
      return this.createDefaultResult();
    }

    if (type !== IOCType.IP) {
      throw new Error(`AbuseIPDB only supports IP addresses, got: ${type}`);
    }

    try {
      return await this.checkIp(value);
    } catch (error) { 
      return this.createDefaultResult();
    }
  }

  private async checkIp(ip: string): Promise<ThreatIntelligenceResult> {
    const response = await this.httpClient.get('/check', {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: true,
      },
    });

      const data = response.data.data;
      console.log('[AbuseIPDB] response data from AbuseIPDB', data);
    const abuseConfidence = data.abuseConfidencePercentage || 0;
    const totalReports = data.totalReports || 0;

    return {
      provider: this.name,
      verdict: this.determineVerdict(abuseConfidence, totalReports),
      category: this.determineCategory(data.usageType),
      confidence: abuseConfidence,
      detectionCount: totalReports,
      lastSeen: data.lastReportedAt ? new Date(data.lastReportedAt) : undefined,
      metadata: {
        abuseConfidencePercentage: abuseConfidence,
        countryCode: data.countryCode,
        usageType: data.usageType,
        isp: data.isp,
        domain: data.domain,
        isPublic: data.isPublic,
        isWhitelisted: data.isWhitelisted,
        totalReports: totalReports,
        numDistinctUsers: data.numDistinctUsers,
      },
    };
    }
    

  private determineVerdict(abuseConfidence: number, totalReports: number): IOCVerdict {
    if (abuseConfidence >= 75 || totalReports >= 10) {
      return IOCVerdict.MALICIOUS;
    } else if (abuseConfidence >= 25 || totalReports >= 3) {
      return IOCVerdict.SUSPICIOUS;
    } else if (abuseConfidence === 0 && totalReports === 0) {
      return IOCVerdict.CLEAN;
    }
    
    return IOCVerdict.UNKNOWN;
  }

    
  private determineCategory(usageType: string): IOCCategory {
    if (!usageType) return IOCCategory.UNKNOWN;

    const type = usageType.toLowerCase();
    
    if (type.includes('hosting') || type.includes('datacenter')) {
      return IOCCategory.C2;
    } else if (type.includes('spam')) {
      return IOCCategory.SPAM;
    }

    return IOCCategory.UNKNOWN;
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