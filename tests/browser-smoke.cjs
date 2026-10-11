// Optional developer checks. Runtime users do not need Node or Playwright.
const {chromium} = require('playwright');
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const root = path.resolve(__dirname,'..');
const python = process.env.LOGDETECTIVE_PYTHON || (process.platform==='win32'?'python':'python3');
let browser, server;
let checks = 0;
function passed(name){checks++;console.log('PASS '+name);}
async function startServer(){
  server=spawn(python,['-u','-m','logdetective','serve','--port','0','--no-browser'],{cwd:root,stdio:['ignore','pipe','pipe']});
  return new Promise((resolve,reject)=>{
    let text='';const timer=setTimeout(()=>reject(new Error('Server startup timed out.')),10000);
    server.on('error',reject);
    server.on('exit',code=>{if(code)reject(new Error('Server exited: '+code));});
    server.stderr.on('data',data=>process.stderr.write(data));
    server.stdout.on('data',data=>{text+=data;const match=text.match(/http:\/\/127\.0\.0\.1:\d+/);if(match){clearTimeout(timer);resolve(match[0]);}});
  });
}
async function analyze(page,text){
  await page.locator('#log').fill(text);await page.locator('#analyze').click();await page.locator('#results').waitFor({state:'visible'});
}
async function main(){
  const url=await startServer();
  browser=await chromium.launch({headless:true, ...(process.env.LOGDETECTIVE_BROWSER ? {executablePath:process.env.LOGDETECTIVE_BROWSER,args:['--no-sandbox']} : {})});
  const page=await browser.newPage({viewport:{width:1440,height:1050}});
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  const external=[];page.on('request',request=>{if(!request.url().startsWith(url))external.push(request.url());});
  await page.goto(url);await page.locator('.sample-button').first().waitFor();
  assert.equal(await page.locator('#analyze').isDisabled(),true);
  assert.equal(await page.locator('.sample-button').count(),5);passed('Startup and sample availability');

  await page.locator('.sample-button').first().click();await page.locator('#analyze').click();
  await page.locator('#results').waitFor({state:'visible'});
  assert.equal(await page.locator('#line-count').textContent(),'7 lines');
  assert.equal(await page.locator('#metric-errors').textContent(),'2');
  assert.match(await page.locator('#findings').textContent(),/Import failed/);passed('Known import failure and error counts');
  await page.locator('.line-link').first().click();
  assert.equal(await page.locator('.event.focused').getAttribute('data-line'),'6');passed('Evidence navigation');
  await page.locator('#tab-timeline').click();await page.locator('#severity').selectOption('error');
  assert.equal(await page.locator('#view-timeline .event').count(),2);passed('Timeline severity filtering');
  await page.locator('#tab-findings').click();await page.locator('.check input').first().check();
  assert.match(await page.locator('#progress').textContent(),/^1 \/ /);
  const markdownPromise=page.waitForEvent('download');await page.locator('#export-md').click();
  const markdown=await fs.readFile(await (await markdownPromise).path(),'utf8');
  assert.match(markdown,/- \[x\]/);assert.match(markdown,/L6:/);passed('Checklist and Markdown export');

  await page.locator('.sample-button').nth(2).click();await page.locator('#analyze').click();
  await page.locator('#results').waitFor({state:'visible'});
  assert.match(await page.locator('#metric-redactions').textContent(),/3 secret/);
  const jsonPromise=page.waitForEvent('download');await page.locator('#export-json').click();
  const jsonText=await fs.readFile(await (await jsonPromise).path(),'utf8');
  assert.ok(!jsonText.includes('demo.fake.token'));assert.ok(!jsonText.includes('demo-not-a-real-secret'));passed('Secret redaction and JSON export');

  await page.locator('#file').setInputFiles({name:'upload.log',mimeType:'text/plain',buffer:Buffer.from('ERROR Permission denied\nINFO done')});
  await page.locator('#analyze').click();await page.locator('#results').waitFor({state:'visible'});
  assert.match(await page.locator('#findings').textContent(),/Access denied/);passed('UTF-8 file upload');
  await page.locator('#file').setInputFiles({name:'windows.log',mimeType:'text/plain',buffer:Buffer.concat([Buffer.from([255,254]),Buffer.from('ERROR Address already in use','utf16le')])});
  await page.locator('#analyze').click();await page.locator('#results').waitFor({state:'visible'});
  assert.match(await page.locator('#findings').textContent(),/Port already in use/);passed('Windows UTF-16 upload');
  await page.locator('#file').setInputFiles({name:'empty.log',mimeType:'text/plain',buffer:Buffer.alloc(0)});
  assert.match(await page.locator('#notice').textContent(),/empty/);passed('Empty file rejected');

  await page.locator('.sample-button').last().click();await page.locator('#analyze').click();
  await page.locator('#results').waitFor({state:'visible'});
  assert.equal(await page.locator('#metric-findings').textContent(),'0');
  assert.match(await page.locator('#findings').textContent(),/does not prove/);passed('Healthy sample preserves uncertainty');

  await analyze(page,'ERROR <img src=x onerror="window.hacked=true"> <script>window.hacked=true</script>');
  assert.equal(await page.evaluate(()=>window.hacked),undefined);
  assert.equal(await page.locator('#findings img, #findings script').count(),0);passed('Untrusted log content stays literal');

  await analyze(page,Array.from({length:205},(_,i)=>'INFO entry '+(i+1)).join('\n'));
  await page.locator('#tab-log').click();assert.equal(await page.locator('#view-log .event').count(),100);
  await page.locator('#next').click();await page.locator('#next').click();assert.equal(await page.locator('#view-log .event').count(),5);
  await page.locator('#search').fill('entry 205');assert.equal(await page.locator('#view-log .event').count(),1);passed('Pagination and search');

  await page.locator('#log').fill('INFO changed');assert.equal(await page.locator('#results').isVisible(),false);passed('Changed input invalidates old results');

  await analyze(page,'ERROR Connection refused');
  await page.route('**/api/models',route=>route.fulfill({json:{models:['test-local:latest']}}));
  await page.route('**/api/ai',route=>route.fulfill({json:{answer:{summary:'Test fixture: service may be stopped.',hypotheses:[{explanation:'Test fixture: check the listener.',lines:[1]}],checks:['Verify service state.']}}}));
  await page.locator('#connect-ai').click();await page.locator('#ask-ai').waitFor({state:'visible'});await page.locator('#ask-ai').click();
  await page.locator('#ai-answer').waitFor({state:'visible'});assert.match(await page.locator('#ai-answer').textContent(),/UNVERIFIED/);passed('AI presentation using a clearly labeled test fixture');
  await page.unroute('**/api/models');await page.unroute('**/api/ai');
  await page.locator('#connect-ai').click();
  await page.waitForFunction(()=>!document.getElementById('connect-ai').disabled);
  assert.match(await page.locator('#ai-status').textContent(),/Ollama|Local model/);passed('Unavailable AI handled without breaking analysis');

  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);passed('Mobile layout has no horizontal overflow');
  await page.setViewportSize({width:1440,height:1050});
  await page.locator('.sample-button').first().click();await page.locator('#analyze').click();await page.locator('#results').waitFor({state:'visible'});
  if(process.env.LOGDETECTIVE_SCREENSHOT){await page.screenshot({path:process.env.LOGDETECTIVE_SCREENSHOT,fullPage:true});}
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);passed('No browser errors or external requests');
  console.log(checks+' browser checks passed.');
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();if(server)server.kill();});
