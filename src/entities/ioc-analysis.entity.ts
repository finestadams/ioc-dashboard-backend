import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';
import { IOCType, IOCVerdict, IOCCategory } from '../dtos/ioc.dto';

@Entity('ioc_analysis_results')
@Index(['valueHash', 'type']) 
    
export class IOCAnalysisResult {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' }) 
  value: string;

  @Column({ length: 64 })
  @Index() 
  valueHash: string;

  @Column({
    type: 'enum',
    enum: IOCType,
  })
  @Index() 
  type: IOCType;

  @Column({
    type: 'enum',
    enum: IOCVerdict,
    default: IOCVerdict.UNKNOWN,
  })
  verdict: IOCVerdict;

  @Column({
    type: 'enum',
    enum: IOCCategory,
    default: IOCCategory.UNKNOWN,
  })
  category: IOCCategory;

  @Column({ type: 'int', default: 0 })
  confidence: number;

  @Column({ type: 'int', default: 0 })
  detectionCount: number;

  @Column({ type: 'int', default: 0 })
  totalEngines: number;

  @Column({ type: 'json', nullable: true })
  providers: any;

  @Column({ type: 'json', nullable: true })
  metadata: any;

  @Column({ type: 'datetime', nullable: true })
  lastSeen: Date;

  @Column({ type: 'text', nullable: true })
  description: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;


  @Column({ type: 'datetime', nullable: true })
  @Index()
  expiresAt: Date;
}