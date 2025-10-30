import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const startTime = Date.now();
    const timestamp = new Date().toISOString();

    // Log incoming request
    this.logger.log(`🟡 [${timestamp}] Incoming Request`);
    this.logger.log(`  Method: ${request.method}`);
    this.logger.log(`  URL: ${request.url}`);
    this.logger.log(`  User-Agent: ${request.headers['user-agent'] || 'Unknown'}`);
    this.logger.log(`  IP: ${request.ip || request.connection.remoteAddress || 'Unknown'}`);
    
    // Log headers (excluding sensitive ones)
    const sanitizedHeaders = { ...request.headers };
    delete sanitizedHeaders.authorization;
    delete sanitizedHeaders.cookie;
    this.logger.log(`  Headers: ${JSON.stringify(sanitizedHeaders)}`);

    // Log query parameters
    if (Object.keys(request.query).length > 0) {
      this.logger.log(`  Query Params: ${JSON.stringify(request.query)}`);
    }

    // Log request body (exclude file uploads and sensitive data)
    if (request.body && Object.keys(request.body).length > 0) {
      const bodyStr = JSON.stringify(request.body);
      if (bodyStr.length > 2000) {
        this.logger.log(`  Request Body (truncated): ${bodyStr.substring(0, 2000)}... [truncated]`);
      } else {
        this.logger.log(`  Request Body: ${bodyStr}`);
      }
    }

    return next.handle().pipe(
      tap({
        next: (data) => {
          const duration = Date.now() - startTime;
          const responseTimestamp = new Date().toISOString();
          
          this.logger.log(`🟢 [${responseTimestamp}] Outgoing Response`);
          this.logger.log(`  Method: ${request.method}`);
          this.logger.log(`  URL: ${request.url}`);
          this.logger.log(`  Status: ${response.statusCode}`);
          this.logger.log(`  Duration: ${duration}ms`);
          
          // Log response data (truncate if too large)
          if (data) {
            const dataStr = JSON.stringify(data);
            if (dataStr.length > 2000) {
              this.logger.log(`  Response Body (truncated): ${dataStr.substring(0, 2000)}... [truncated]`);
            } else {
              this.logger.log(`  Response Body: ${dataStr}`);
            }
          }
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          const errorTimestamp = new Date().toISOString();
          
          this.logger.error(`🔴 [${errorTimestamp}] Request Error`);
          this.logger.error(`  Method: ${request.method}`);
          this.logger.error(`  URL: ${request.url}`);
          this.logger.error(`  Status: ${response.statusCode || 500}`);
          this.logger.error(`  Duration: ${duration}ms`);
          this.logger.error(`  Error: ${error.message}`);
          
          if (error.stack) {
            this.logger.error(`  Stack: ${error.stack}`);
          }
        },
      }),
    );
  }
}