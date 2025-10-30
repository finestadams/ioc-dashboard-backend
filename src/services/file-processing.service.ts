import { Injectable, BadRequestException } from '@nestjs/common';
import * as csv from 'csv-parser';
import * as XLSX from 'xlsx';
import * as fs from 'fs';
import { IOCType } from '../dtos/ioc.dto';
import { IOCService } from './ioc.service';

export interface ParsedIOC {
  value: string;
  type: IOCType;
  description?: string;
  rowNumber: number;
}

export interface FileParsingResult {
  iocs: ParsedIOC[];
  errors: Array<{
    rowNumber: number;
    error: string;
    rawData?: any;
  }>;
  totalRows: number;
}

@Injectable()
export class FileProcessingService {
  // logging removed per request
  
  constructor(private iocService: IOCService) {}

  async parseCSVFile(filePath: string): Promise<FileParsingResult> {
  // parsing CSV file
    
    return new Promise((resolve, reject) => {
      const iocs: ParsedIOC[] = [];
      const errors: Array<{ rowNumber: number; error: string; rawData?: any }> = [];
      let rowNumber = 0;

      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => {
          rowNumber++;
          try {
            // Normalize the row headers
            const normalizedRow: { [key: string]: string } = {};
            Object.keys(row).forEach(key => {
              const normalizedKey = this.normalizeHeaders([key])[0];
              normalizedRow[normalizedKey] = row[key];
            });
            
            const parsedIOCs = this.parseRow(normalizedRow, rowNumber);
            iocs.push(...parsedIOCs);
          } catch (error) {
            errors.push({
              rowNumber,
              error: error.message,
              rawData: row,
            });
          }
        })
        .on('end', () => {
          // CSV parsing complete
          resolve({
            iocs,
            errors,
            totalRows: rowNumber
          });
        })
        .on('error', (error) => {
          // CSV parsing error
          reject(error);
        });
    });
  }

  async parseExcelFile(filePath: string): Promise<FileParsingResult> {
  // parsing Excel file
    
    try {
      const workbook = XLSX.readFile(filePath);
      const sheetName = workbook.SheetNames[0]; // Use first sheet
      const worksheet = workbook.Sheets[sheetName];
      
      // Convert to JSON with header normalization
      const rawData = XLSX.utils.sheet_to_json(worksheet, { 
        header: 1,
        defval: '',
        raw: false
      }) as string[][];

      if (rawData.length === 0) {
        throw new BadRequestException('Excel file is empty');
      }

      // Normalize headers
      const normalizedHeaders = this.normalizeHeaders(rawData[0] as string[]);
      const dataRows = rawData.slice(1);

      const iocs: ParsedIOC[] = [];
      const errors: Array<{ rowNumber: number; error: string; rawData?: any }> = [];

      dataRows.forEach((row, index) => {
        const rowNumber = index + 2; // +2 because we start from row 2 (after header)
        
        try {
          // Convert array to object using normalized headers
          const rowObject: { [key: string]: string } = {};
          normalizedHeaders.forEach((header, i) => {
            rowObject[header] = row[i] || '';
          });

          const parsedIOCs = this.parseRow(rowObject, rowNumber);
          iocs.push(...parsedIOCs);
        } catch (error) {
          errors.push({
            rowNumber,
            error: error.message,
            rawData: row,
          });
        }
      });

  // Excel parsing complete
      return {
        iocs,
        errors,
        totalRows: dataRows.length
      };
    } catch (error) {
  // Excel parsing error
      throw new BadRequestException(`Failed to parse Excel file: ${error.message}`);
    }
  }

  generateSampleCSV(): string {
    const headers = ['ioc', 'type', 'description'];
    const sampleData = [
      ['google.com', 'domain', 'Sample domain'],
      ['8.8.8.8', 'ip', 'Google DNS'],
      ['https://example.com/malware', 'url', 'Sample suspicious URL'],
      ['5d41402abc4b2a76b9719d911017c592', 'hash', 'MD5 hash example'],
      ['da39a3ee5e6b4b0d3255bfef95601890afd80709', 'hash', 'SHA1 hash example'],
    ];

    const csvContent = [headers, ...sampleData]
      .map(row => row.map(cell => `"${cell}"`).join(','))
      .join('\n');

    return csvContent;
  }

  private normalizeHeaders(headers: string[]): string[] {
    return headers.map(header => {
      const normalized = header.toLowerCase().trim();
      
      // Map common variations to standard names
      const headerMappings: { [key: string]: string } = {
        'ioc': 'ioc',
        'indicator': 'ioc',
        'value': 'ioc',
        'observable': 'ioc',
        'artifact': 'ioc',
        'type': 'type',
        'ioc_type': 'type',
        'indicator_type': 'type',
        'kind': 'type',
        'category': 'type',
        'description': 'description',
        'desc': 'description',
        'comment': 'description',
        'notes': 'description',
        'note': 'description',
      };

      return headerMappings[normalized] || normalized;
    });
  }

  private parseRow(row: { [key: string]: string }, rowNumber: number): ParsedIOC[] {
    const iocs: ParsedIOC[] = [];
    
    // Get the main IOC value
    const iocValue = this.getIOCValue(row);
    if (!iocValue) {
      throw new Error('No IOC value found in row');
    }

    // Get or detect IOC type
    const typeValue = row.type || row.ioc_type || '';
    let iocType: IOCType;
    
    if (typeValue) {
      iocType = this.parseIOCType(typeValue);
    } else {
      iocType = this.iocService.detectIOCType(iocValue);
    }

    // Get description
    const description = row.description || row.desc || row.comment || '';

    // Handle multiple IOCs in a single cell (comma-separated)
    const values = iocValue.split(',').map(v => v.trim()).filter(v => v);
    
    for (const value of values) {
      if (value) {
        iocs.push({
          value: value.trim(),
          type: iocType,
          description: description.trim() || undefined,
          rowNumber,
        });
      }
    }

    return iocs;
  }

  private getIOCValue(row: { [key: string]: string }): string {
    // Try common column names for IOC values
    const possibleColumns = ['ioc', 'indicator', 'value', 'observable', 'artifact'];
    
    for (const column of possibleColumns) {
      if (row[column] && row[column].trim()) {
        return row[column].trim();
      }
    }

    // If no standard column found, try to find any column with a value that looks like an IOC
    const values = Object.values(row).filter(v => v && v.trim());
    
    for (const value of values) {
      const trimmedValue = value.trim();
      // Basic check if it looks like an IOC
      if (this.looksLikeIOC(trimmedValue)) {
        return trimmedValue;
      }
    }

    return '';
  }

  private looksLikeIOC(value: string): boolean {
    // Basic heuristics to identify if a value looks like an IOC
    const cleanValue = value.toLowerCase().trim();
    
    // Hash patterns
    if (/^[a-f0-9]{32}$/.test(cleanValue)) return true; // MD5
    if (/^[a-f0-9]{40}$/.test(cleanValue)) return true; // SHA1
    if (/^[a-f0-9]{64}$/.test(cleanValue)) return true; // SHA256
    
    // URL pattern
    if (/^https?:\/\//.test(cleanValue)) return true;
    
    // IP address pattern
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleanValue)) return true;
    
    // Domain pattern (basic)
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(cleanValue)) return true;
    
    // Long hex strings (likely hashes)
    if (/^[a-f0-9]{16,}$/.test(cleanValue)) return true;
    
    return false;
  }

  private parseIOCType(typeValue: string): IOCType {
    const normalizedType = typeValue.toLowerCase().trim();
    
    const typeMappings: { [key: string]: IOCType } = {
      'hash': IOCType.HASH,
      'file_hash': IOCType.HASH,
      'filehash': IOCType.HASH,
      'md5': IOCType.HASH,
      'sha1': IOCType.HASH,
      'sha256': IOCType.HASH,
      'url': IOCType.URL,
      'uri': IOCType.URL,
      'link': IOCType.URL,
      'ip': IOCType.IP,
      'ip_address': IOCType.IP,
      'ipaddress': IOCType.IP,
      'ipv4': IOCType.IP,
      'domain': IOCType.DOMAIN,
      'hostname': IOCType.DOMAIN,
      'fqdn': IOCType.DOMAIN,
      'file': IOCType.FILE,
    };

    return typeMappings[normalizedType] || IOCType.HASH; // Default to hash
  }

  async cleanupFile(filePath: string): Promise<void> {
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      // cleaned up file
      }
    } catch (error) {
    // error cleaning up file
    }
  }
}