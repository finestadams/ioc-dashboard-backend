import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm';

@Entity('api_rate_limits')
export class ApiRateLimit {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ length: 50 })
  @Index()
  provider: string;

  @Column({ type: 'int', default: 0 })
  requestCount: number;

  @Column({ type: 'datetime' })
  windowStart: Date;

  @Column({ type: 'int' })
  windowDuration: number; 

  @Column({ type: 'int' })
  maxRequests: number;

  @CreateDateColumn()
  createdAt: Date;
}