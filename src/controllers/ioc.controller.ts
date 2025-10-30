import {
  Controller,
  Post,
  Body,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  Get,
  Query,
  Res,
  Logger,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { Response } from 'express';
import { diskStorage } from 'multer';
import * as path from 'path';
import * as fs from 'fs';
import { 
  SingleIOCDto, 
  BulkIOCDto, 
  IOCResultDto, 
  BulkAnalysisResultDto,
  FileUploadDto 
} from '../dtos/ioc.dto';
import { IOCService } from '../services/ioc.service';
import { FileProcessingService } from '../services/file-processing.service';
import { FileAnalysisResult } from '../interfaces/threat-intelligence.interface';

@Controller('api/ioc')
export class IOCController {
  // logging removed per request

  constructor(
    private iocService: IOCService,
    private fileProcessingService: FileProcessingService,
  ) {}

  @Post('analyze')
  async analyzeSingleIOC(@Body() dto: SingleIOCDto): Promise<IOCResultDto> {
  // analyze single IOC
    
    try {
      return await this.iocService.analyzeSingleIOC(dto.value, dto.type);
    } catch (error) {
  // error analyzing IOC
      throw new BadRequestException(`Failed to analyze IOC: ${error.message}`);
    }
  }

  @Post('analyze/bulk')
  async analyzeBulkIOCs(@Body() dto: BulkIOCDto): Promise<BulkAnalysisResultDto> {
  // analyze bulk IOCs
    
    if (dto.iocs.length === 0) {
      throw new BadRequestException('No IOCs provided for analysis');
    }

    if (dto.iocs.length > 1000) {
      throw new BadRequestException('Maximum 1000 IOCs allowed per request');
    }

    try {
      const iocArray = dto.iocs.map(ioc => ({
        value: ioc.value,
        type: ioc.type,
      }));

      return await this.iocService.analyzeBulkIOCs(iocArray, {
        batchSize: 5,
        delayBetweenRequests: 2000,
      });
    } catch (error) {
  // error analyzing bulk IOCs
      throw new BadRequestException(`Failed to analyze bulk IOCs: ${error.message}`);
    }
  }

  @Post('file/analyze')
  @UseInterceptors(FileInterceptor('file', {
    storage: diskStorage({
      destination: (req, file, cb) => {
        const uploadsDir = './uploads';
        try {
          if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
          }
          cb(null, uploadsDir);
        } catch (err) {
          cb(err, uploadsDir);
        }
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
      },
    }),
    limits: {
      fileSize: 100 * 1024 * 1024, // 100MB limit
    },
    fileFilter: (req, file, cb) => {
      // Allow all file types for analysis
      cb(null, true);
    },
  }))
  async analyzeFile(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: FileUploadDto,
  ): Promise<FileAnalysisResult> {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

  // analyzing uploaded file

    try {
      const result = await this.iocService.analyzeFile(file.path, file.originalname);
      
      // Clean up uploaded file
      await this.fileProcessingService.cleanupFile(file.path);
      
      return result;
    } catch (error) {
  // error analyzing file
      
      // Clean up uploaded file on error
      await this.fileProcessingService.cleanupFile(file.path);
      
      throw new BadRequestException(`Failed to analyze file: ${error.message}`);
    }
  }

  @Post('file/bulk-upload')
  @UseInterceptors(FileInterceptor('file', {
    storage: diskStorage({
      destination: (req, file, cb) => {
        const uploadsDir = './uploads';
        try {
          if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
          }
          cb(null, uploadsDir);
        } catch (err) {
          cb(err, uploadsDir);
        }
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
      },
    }),
    limits: {
      fileSize: 10 * 1024 * 1024, // 10MB limit for CSV/Excel
    },
    fileFilter: (req, file, cb) => {
      const allowedMimeTypes = [
        'text/csv',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      ];
      
      if (allowedMimeTypes.includes(file.mimetype) || 
          file.originalname.match(/\.(csv|xlsx|xls)$/i)) {
        cb(null, true);
      } else {
        cb(new BadRequestException('Only CSV and Excel files are allowed'), false);
      }
    },
  }))
  async analyzeBulkFromFile(
    @UploadedFile() file: Express.Multer.File,
  ): Promise<BulkAnalysisResultDto> {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

  // processing bulk IOC file

    try {
      let parsingResult;
      
      if (file.originalname.toLowerCase().endsWith('.csv')) {
        parsingResult = await this.fileProcessingService.parseCSVFile(file.path);
      } else {
        parsingResult = await this.fileProcessingService.parseExcelFile(file.path);
      }

      if (parsingResult.iocs.length === 0) {
        throw new BadRequestException('No valid IOCs found in the uploaded file');
      }

      if (parsingResult.iocs.length > 1000) {
        throw new BadRequestException('File contains too many IOCs. Maximum 1000 allowed.');
      }

      // Convert to the format expected by the IOC service
      const iocArray = parsingResult.iocs.map(ioc => ({
        value: ioc.value,
        type: ioc.type,
      }));

      const analysisResult = await this.iocService.analyzeBulkIOCs(iocArray, {
        batchSize: 3,
        delayBetweenRequests: 3000,
      });

      // Add parsing errors to the analysis result
      analysisResult.errors.push(...parsingResult.errors.map(error => ({
        value: `Row ${error.rowNumber}`,
        error: error.error,
      })));

      // Clean up uploaded file
      await this.fileProcessingService.cleanupFile(file.path);

      return analysisResult;
    } catch (error) {
  // error processing bulk file
      
      // Clean up uploaded file on error
      await this.fileProcessingService.cleanupFile(file.path);
      
      throw new BadRequestException(`Failed to process file: ${error.message}`);
    }
  }

  @Get('detect-type')
  async detectIOCType(@Query('value') value: string): Promise<{ type: string }> {
    if (!value) {
      throw new BadRequestException('Value parameter is required');
    }

    const detectedType = this.iocService.detectIOCType(value);
    return { type: detectedType };
  }

  @Get('sample-csv')
  downloadSampleCSV(@Res() res: Response): void {
  // generating sample CSV template
    
    const csvContent = this.fileProcessingService.generateSampleCSV();
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="ioc_sample_template.csv"');
    res.send(csvContent);
  }

  @Get('health')
  async healthCheck(): Promise<{ 
    status: string; 
    timestamp: string; 
    providers: Array<{ name: string; status: string }> 
  }> {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      providers: [
        { name: 'VirusTotal', status: 'configured' },
        { name: 'AbuseIPDB', status: 'configured' },
        { name: 'URLScan.io', status: 'configured' },
      ]
    };
  }

  @Get('analytics')
  async getAnalytics(@Query('days') days?: string): Promise<any> {
  // getting analytics data
    
    try {
      const numDays = days ? parseInt(days, 10) : 7;
      return await this.iocService.getAnalytics(numDays);
    } catch (error) {
  // error getting analytics
      throw new BadRequestException(`Failed to get analytics: ${error.message}`);
    }
  }

  @Get('recent')
  async getRecentAnalyses(@Query('limit') limit?: string): Promise<any[]> {
  // getting recent analyses
    
    try {
      const numLimit = limit ? parseInt(limit, 10) : 10;
      return await this.iocService.getRecentAnalyses(numLimit);
    } catch (error) {
  // error getting recent analyses
      throw new BadRequestException(`Failed to get recent analyses: ${error.message}`);
    }
  }
}