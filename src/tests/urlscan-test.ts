import { URLScanProvider } from '../providers/urlscan.provider';
import { ConfigService } from '@nestjs/config';
import { IOCType } from '../dtos/ioc.dto';
import * as dotenv from 'dotenv';

async function testURLScanProvider() {
    // Load environment variables
    dotenv.config();
    
    const configService = new ConfigService();
    const provider = new URLScanProvider(configService);
    
    // Verify API key is loaded
    const apiKey = configService.get('URLSCAN_API_KEY');
    console.log(`URLScan API Key configured: ${apiKey ? 'Yes (' + apiKey.substring(0, 8) + '...)' : 'No'}`);

    console.log('Testing URLScan Provider...\n');

    // Test URLs - known malicious examples
    const testUrls = [
        'http://malware.wicar.org/data/java_jre17_exec.html',
        'http://malware-site.com/payload.exe',
        'https://google.com', // Should be clean
        'http://eicar.org/download/eicar.com', // EICAR test file
    ];

    for (const url of testUrls) {
        try {
            console.log(`\n🔍 Testing URL: ${url}`);
            const result = await provider.checkIOC(url, IOCType.URL);
            
            console.log(`  Provider: ${result.provider}`);
            console.log(`  Verdict: ${result.verdict}`);
            console.log(`  Category: ${result.category}`);
            console.log(`  Confidence: ${result.confidence}%`);
            console.log(`  Detection Count: ${result.detectionCount}/${result.totalEngines}`);
            console.log(`  Metadata:`, JSON.stringify(result.metadata, null, 2));
        } catch (error) {
            console.log(`  ❌ Exception: ${error.message}`);
        }
        
        // Add delay to respect rate limits
        await new Promise(resolve => setTimeout(resolve, 3000));
    }
}

// Run the test if this file is executed directly
if (require.main === module) {
    testURLScanProvider().catch(console.error);
}

export { testURLScanProvider };