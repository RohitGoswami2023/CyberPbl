const { execSync } = require('child_process');
const path = require('path');

// Test URL
const testUrl = 'https://www.netflix.com/browse';

console.log(`Testing URL: ${testUrl}\n`);

// Function to run the Python prediction script
function testUrlWithPython(url) {
  try {
    console.log('Running Python prediction script...');
    const pythonScriptPath = path.join(__dirname, '../python/predict.py');
    const result = execSync(`python3 "${pythonScriptPath}" "${url}"`, { encoding: 'utf-8' });
    
    console.log('Raw Python script output:');
    console.log('------------------------');
    console.log(result);
    
    try {
      const jsonResult = JSON.parse(result.trim().split('\n')[0]);
      console.log('\nParsed JSON result:');
      console.log('------------------');
      console.log(JSON.stringify(jsonResult, null, 2));
      
      return jsonResult;
    } catch (parseError) {
      console.error('Error parsing Python script output:', parseError);
      return { error: 'Failed to parse script output', rawOutput: result };
    }
  } catch (error) {
    console.error('Error running Python script:', error);
    return { error: error.message };
  }
}

// Test the URL
const result = testUrlWithPython(testUrl);

// Additional debug information
console.log('\nAdditional Debug Information:');
console.log('----------------------------');
console.log(`- URL normalization test:`);
console.log(`  Original URL: ${testUrl}`);

// Test domain extraction
try {
  const { URL } = require('url');
  const parsedUrl = new URL(testUrl);
  const domain = parsedUrl.hostname.replace('www.', '');
  console.log(`- Domain extraction: ${domain}`);
  console.log(`- Is netflix.com in trusted domains: ${domain === 'netflix.com' ? 'Yes' : 'No'}`);
} catch (e) {
  console.error('Error parsing URL:', e);
}

console.log('\nTest completed.');
