import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { IOCController } from './controllers/ioc.controller';
import { IOCService } from './services/ioc.service';
import { FileProcessingService } from './services/file-processing.service';
import { VirusTotalProvider } from './providers/virustotal.provider';
import { AbuseIPDBProvider } from './providers/abuseipdb.provider';
import { URLScanProvider } from './providers/urlscan.provider';
import { IOCAnalysisResult } from './entities/ioc-analysis.entity';
import { ApiRateLimit } from './entities/api-rate-limit.entity';
import { LoggingInterceptor } from './interceptors/logging.interceptor';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // TypeORM configuration (temporarily disabled for testing)
    ...(process.env.DB_HOST ? [
      TypeOrmModule.forRootAsync({
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          type: 'mysql',
          host: configService.get('DB_HOST', 'localhost'),
          port: configService.get('DB_PORT', 3306),
          username: configService.get('DB_USERNAME', 'root'),
          password: configService.get('DB_PASSWORD', ''),
          database: configService.get('DB_DATABASE', 'ioc_dashboard'),
          entities: [IOCAnalysisResult, ApiRateLimit],
          synchronize: configService.get('NODE_ENV') === 'development', // Only in dev
          logging: configService.get('NODE_ENV') === 'development',
        }),
        inject: [ConfigService],
      }),
      TypeOrmModule.forFeature([IOCAnalysisResult, ApiRateLimit])
    ] : []),
    CacheModule.register({
      isGlobal: true,
      ttl: 3600, // 1 hour cache
    }),
    ThrottlerModule.forRoot([{
      ttl: 60000, // 1 minute
      limit: 100, // 100 requests per minute
    }]),
  ],
  controllers: [AppController, IOCController],
  providers: [
    AppService,
    IOCService,
    FileProcessingService,
    VirusTotalProvider,
    AbuseIPDBProvider,
    URLScanProvider,
    // Global logging interceptor removed per request
  ],
})
export class AppModule {}
