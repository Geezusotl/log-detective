'use strict';
const $ = id => document.getElementById(id);
const state = {token:'', samples:[], report:null, original:'', source:'Pasted log', completed:new Set(), ai:null, tab:'findings', page:0, focus:null, models:[], busy:false};
const pageSize = 100;

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = String(text);
  if (className) el.className = className;
  return el;
}
function notice(message, success=false) {
  $('notice').textContent = message;
  $('notice').className = 'notice' + (success ? ' success' : '');
  $('notice').hidden = !message;
}
async function api(path, payload) {
  const options = payload === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json','X-LogDetective-Token':state.token},body:JSON.stringify(payload)};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The request failed.');
  return data;
}
function updateCount() {
  const value = $('log').value;
  const lines = value ? value.split(/\r\n|\n|\r/) : [];
  if (lines.length && lines[lines.length-1] === '') lines.pop();
  $('line-count').textContent = lines.length + ' lines';
  $('analyze').disabled = !state.token || !value.trim() || state.busy;
}
function invalidate() {
  state.report = null; state.ai = null; state.completed.clear();
  $('results').hidden = true; $('empty-state').hidden = false;
  $('ai-answer').hidden = true; $('ask-ai').disabled = false;
  updateCount();
}
function sourceLabel(source) {
  state.source = source; $('source').textContent = source;
}
function loadSample(sample) {
  if (state.busy) return;
  $('log').value = sample.text; sourceLabel(sample.filename);
  invalidate(); notice('Sample loaded. Select Analyze log to investigate.',true);
  for (const button of $('samples').children) button.classList.toggle('selected', button.dataset.filename === sample.filename);
}
async function readFile(file) {
  if (state.busy) return;
  if (file.size > 2 * 1024 * 1024) return notice('This file exceeds 2 MiB. Choose a smaller log excerpt.');
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let encoding = 'utf-8';
    if (bytes[0] === 255 && bytes[1] === 254) encoding='utf-16le';
    if (bytes[0] === 254 && bytes[1] === 255) encoding='utf-16be';
    const text = new TextDecoder(encoding,{fatal:true}).decode(bytes);
    if (!text.trim()) throw new Error('This file is empty. Choose a nonempty log.');
    if (text.includes('\u0000')) throw new Error('This looks like a binary file. Choose a UTF-8 or BOM-marked UTF-16 text log.');
    $('log').value = text; sourceLabel(file.name); invalidate();
    notice('File loaded. Select Analyze log to investigate.',true);
    for (const button of $('samples').children) button.classList.remove('selected');
  } catch(error) {notice(error instanceof TypeError ? 'The file is not valid text. Use UTF-8 or BOM-marked UTF-16.' : error.message);}
}
function setBusy(busy) {
  state.busy = busy;
  $('analyze').textContent = busy ? 'Analyzing…' : 'Analyze log →';
  $('file').disabled = busy; $('log').disabled = busy; $('redact').disabled = busy; $('clear').disabled = busy;
  for (const button of $('samples').children) button.disabled = busy;
  updateCount();
}
async function runAnalysis() {
  if (state.busy) return;
  setBusy(true); notice('');
  try {
    const original = $('log').value;
    const report = await api('/api/analyze',{text:original,source:state.source,redact:$('redact').checked});
    state.report = report; state.original = original; state.completed.clear(); state.ai=null;
    state.page=0; state.focus=null; $('search').value=''; $('severity').value='all';
    $('results').hidden=false; $('empty-state').hidden=true; $('ai-answer').hidden=true;
    $('ai-status').textContent='The rule-based investigation needs no AI setup.';
    $('ask-ai').disabled = false;
    renderSummary(); renderFindings(); switchTab('findings');
  } catch(error) {invalidate(); notice(error.message);}
  finally {setBusy(false);}
}
function renderSummary() {
  const report = state.report, summary = report.summary;
  $('metric-lines').textContent=summary.lines;
  $('metric-errors').textContent=summary.counts.error;
  $('metric-warnings').textContent=summary.counts.warning;
  $('metric-findings').textContent=summary.findings;
  $('metric-source').textContent=report.source;
  $('metric-redactions').textContent=report.redacted ? report.redactions + ' secret replacements' : 'Redaction disabled';
  $('findings-count').textContent=summary.findings;
  $('limits').textContent=report.limitations;
  renderProgress();
}
function lineButton(number) {
  const button=node('button','L'+number,'line-link');
  button.title='Show line '+number+' in context';
  button.addEventListener('click',()=>jumpToLine(number));
  return button;
}
function renderFindings() {
  const container=$('findings'); container.replaceChildren();
  if (state.report.notices && state.report.notices.length) {
    const notices=node('details',undefined,'no-findings');
    notices.append(node('summary','Deprecation notices · '+state.report.notices.length+' retained references'));
    for (const item of state.report.notices) {
      const entry=node('p');entry.append(lineButton(item.line),node('span',' '+item.message));notices.append(entry);
    }
    container.append(notices);
  }
  if (!state.report.findings.length) {
    const empty=node('div',undefined,'no-findings');
    empty.append(node('h3','No recognized issues found.'),node('p','No incident symptoms matched. This does not prove the application is healthy. Notices and other content remain available in Log explorer.'));
    container.append(empty);return;
  }
  const lines=state.report.text.split('\n');
  for (const finding of state.report.findings) {
    const card=node('article',undefined,'finding');
    const heading=node('div',undefined,'finding-header');
    heading.append(node('span',finding.severity,'pill '+finding.severity),node('h3',finding.title),node('span',finding.occurrences+' occurrence'+(finding.occurrences===1?'':'s'),'occurrences'));
    const hypothesis=node('div',undefined,'hypothesis');
    hypothesis.append(node('strong',finding.hypothesis ? 'POSSIBLE EXPLANATION' : 'CAUSE NOT ESTABLISHED'),node('span',finding.hypothesis || 'Inspect the cited text and surrounding context.'));
    const evidence=node('pre',finding.lines.slice(0,2).map(n=>'L'+n+'  '+lines[n-1]).join('\n'),'evidence');
    const links=node('div',undefined,'evidence-links');
    finding.lines.slice(0,8).forEach(n=>links.append(lineButton(n)));
    if(finding.occurrences>8) links.append(node('span','+ '+(finding.occurrences-8)+' more matches','occurrences'));
    const checks=node('div',undefined,'check-list');
    finding.steps.forEach((step,index)=>{
      const label=node('label',undefined,'check'),input=node('input');input.type='checkbox';
      const key=finding.id+':'+index;
      input.checked=state.completed.has(key);
      input.addEventListener('change',()=>{input.checked?state.completed.add(key):state.completed.delete(key);renderProgress();});
      label.append(input,node('span',step));checks.append(label);
    });
    card.append(heading,node('p',finding.observation,'observation'),hypothesis,node('div','EVIDENCE · '+finding.basis.toUpperCase(),'evidence-label'),evidence,links,node('div','CHECK NEXT','evidence-label'),checks);
    container.append(card);
  }
}
function renderProgress() {
  const total=state.report ? state.report.findings.reduce((sum,f)=>sum+f.steps.length,0):0;
  $('progress').textContent=state.completed.size+' / '+total;
}
function switchTab(tab) {
  state.tab=tab;
  for (const name of ['findings','timeline','log']) {
    $('tab-'+name).classList.toggle('active',name===tab);
    $('tab-'+name).setAttribute('aria-selected',String(name===tab));
    $('tab-'+name).tabIndex=name===tab?0:-1;
    $('view-'+name).hidden=name!==tab;
  }
  $('event-controls').hidden=tab==='findings';
  $('pagination').hidden=tab==='findings';
  if(tab!=='findings') renderEvents();
}
function filteredEvents() {
  const query=$('search').value.toLowerCase(),severity=$('severity').value;
  return state.report.events.filter(e=>(severity==='all'||e.severity===severity)&&(!query||e.message.toLowerCase().includes(query)));
}
function renderEvents() {
  if(!state.report)return;
  const items=filteredEvents(),pages=Math.max(1,Math.ceil(items.length/pageSize));
  state.page=Math.min(state.page,pages-1);
  const container=$('view-'+state.tab);container.replaceChildren();
  const raw=state.report.text.split('\n');
  for(const event of items.slice(state.page*pageSize,(state.page+1)*pageSize)){
    const row=node('div',undefined,'event'+(event.line===state.focus?' focused':''));
    row.dataset.line=event.line;
    const number=node('button','L'+event.line,'event-number');
    number.title='Show line '+event.line+' in the log explorer';
    number.addEventListener('click',()=>jumpToLine(event.line));
    const body=node('div');
    if(state.tab==='timeline'){
      const meta=node('div',undefined,'event-meta');
      meta.append(node('span',event.severity,'pill '+event.severity),node('span',event.timestamp||'No timestamp','event-time'));
      body.append(meta);
    }
    body.append(node('div',state.tab==='log'?raw[event.line-1]:event.message,'event-message'));
    row.append(number,body);container.append(row);
  }
  if(!items.length)container.append(node('p','No messages match this filter.','no-findings'));
  $('page-info').textContent=items.length+' lines · page '+(state.page+1)+' of '+pages;
  $('previous').disabled=state.page===0;$('next').disabled=state.page>=pages-1;
}
function jumpToLine(number) {
  $('search').value='';$('severity').value='all';
  state.page=Math.floor((number-1)/pageSize);state.focus=number;switchTab('log');
  const target=$('view-log').querySelector('[data-line="'+number+'"]');
  if(target)target.scrollIntoView({behavior:'smooth',block:'center'});
}
function download(content,extension,mime) {
  const blob=new Blob([content],{type:mime}),url=URL.createObjectURL(blob),a=node('a');
  a.href=url;a.download='LogDetectiveReport.'+extension;
  document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function exportMarkdown() {
  const snapshot=state.report;if(!snapshot)return;
  $('export-md').disabled=true;
  try {
    const payload={text:state.original,source:snapshot.source,redact:snapshot.redacted,completed:[...state.completed],ai:state.ai};
    const result=await api('/api/report',payload);
    if(snapshot===state.report)download(result.markdown,'md','text/markdown;charset=utf-8');
  }catch(error){notice(error.message);}
  finally{$('export-md').disabled=false;}
}
async function connectAI() {
  $('connect-ai').disabled=true;$('ai-status').textContent='Looking for installed local models…';
  try{
    const result=await api('/api/models',{});state.models=result.models;
    $('model').replaceChildren();
    for(const model of result.models){const option=node('option',model);option.value=model;$('model').append(option);}
    $('model').hidden=!result.models.length;$('ask-ai').hidden=!result.models.length;
    $('ai-status').textContent=result.models.length?'Local model ready. AI suggestions are unverified.':'Ollama is running, but no local models are installed. See README for setup.';
  }catch(error){$('model').hidden=true;$('ask-ai').hidden=true;$('ai-status').textContent=error.message;}
  finally{$('connect-ai').disabled=false;}
}
async function askAI() {
  const snapshot=state.report;if(!snapshot)return;
  $('ask-ai').disabled=true;$('connect-ai').disabled=true;$('ai-status').textContent='Investigating selected evidence… This can take up to 90 seconds.';
  try{
    const result=await api('/api/ai',{text:state.original,source:snapshot.source,redact:true,model:$('model').value});
    if(snapshot!==state.report)return;
    state.ai=result.answer;renderAI();$('ai-status').textContent='AI suggestions generated. Citations point to supplied lines; they do not prove the explanation.';
  }catch(error){if(snapshot===state.report)$('ai-status').textContent=error.message;}
  finally{$('ask-ai').disabled=false;$('connect-ai').disabled=false;}
}
function renderAI() {
  const answer=state.ai,container=$('ai-answer');container.replaceChildren();container.className='ai-output';container.hidden=false;
  container.append(node('h3','UNVERIFIED AI SUGGESTIONS'),node('p',answer.summary));
  for(const item of answer.hypotheses){container.append(node('p',item.explanation));const refs=node('div',undefined,'evidence-links');item.lines.forEach(n=>refs.append(lineButton(n)));container.append(refs);}
  const list=node('ul');answer.checks.forEach(step=>list.append(node('li',step)));container.append(list);
}
$('analyze').addEventListener('click',runAnalysis);
$('log').addEventListener('input',()=>{sourceLabel('Pasted log');invalidate();notice('');for(const button of $('samples').children)button.classList.remove('selected');});
$('redact').addEventListener('change',()=>{invalidate();notice('Redaction setting changed. Analyze again to refresh findings.');});
$('file').addEventListener('change',async()=>{if($('file').files[0])await readFile($('file').files[0]);$('file').value='';});
$('clear').addEventListener('click',()=>{$('log').value='';sourceLabel('Pasted log');invalidate();notice('');for(const button of $('samples').children)button.classList.remove('selected');$('log').focus();});
for(const type of ['dragenter','dragover'])$('dropzone').addEventListener(type,e=>{e.preventDefault();$('dropzone').classList.add('drag');});
for(const type of ['dragleave','drop'])$('dropzone').addEventListener(type,e=>{e.preventDefault();$('dropzone').classList.remove('drag');});
$('dropzone').addEventListener('drop',e=>{if(e.dataTransfer.files[0])readFile(e.dataTransfer.files[0]);});
for(const name of ['findings','timeline','log']){
  $('tab-'+name).addEventListener('click',()=>{state.page=0;switchTab(name);});
  $('tab-'+name).addEventListener('keydown',e=>{const names=['findings','timeline','log'];let index=names.indexOf(name);if(e.key==='ArrowRight')index=(index+1)%3;else if(e.key==='ArrowLeft')index=(index+2)%3;else return;e.preventDefault();state.page=0;switchTab(names[index]);$('tab-'+names[index]).focus();});
}
$('search').addEventListener('input',()=>{state.page=0;renderEvents();});
$('severity').addEventListener('change',()=>{state.page=0;renderEvents();});
$('previous').addEventListener('click',()=>{state.page--;renderEvents();});
$('next').addEventListener('click',()=>{state.page++;renderEvents();});
$('export-md').addEventListener('click',exportMarkdown);
$('export-json').addEventListener('click',()=>{if(state.report)download(JSON.stringify({...state.report,completed:[...state.completed],ai:state.ai},null,2),'json','application/json');});
$('connect-ai').addEventListener('click',connectAI);$('ask-ai').addEventListener('click',askAI);
async function initialize(){
  try{
    const [config,samples]=await Promise.all([api('/api/config'),api('/api/samples')]);state.token=config.token;state.samples=samples.samples;
    for(const sample of state.samples){const button=node('button',undefined,'sample-button');button.dataset.filename=sample.filename;button.append(node('span',sample.name),node('span','↗'));button.addEventListener('click',()=>loadSample(sample));$('samples').append(button);}
    updateCount();
  }catch(error){notice('The local app could not initialize. Refresh the page or restart Log Detective.');}
}
initialize();
