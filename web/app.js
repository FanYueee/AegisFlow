'use strict';
const $=id=>document.getElementById(id);
const states={pending:'宣告待確認',active:'已宣告',simulated:'模擬中',withdrawing:'撤回待確認',withdrawn:'已撤回',absent:'路由不存在',failed:'失敗'};
const actions={announce:'宣告',withdraw:'撤回',announce_pending:'宣告待確認',settings:'設定',recovered:'狀態恢復',absent:'路由不存在',withdrawn:'撤回確認'};
let settingsLoaded=false, controlState=null;
const time=s=>!s||s.startsWith('0001-')?'尚無資料':new Date(s).toLocaleString('zh-TW',{hour12:false});
function message(s){$('message').textContent=s;$('message').hidden=!s}
async function api(path,method='GET',data){const res=await fetch(path,{method,headers:data===undefined?{}:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data),signal:AbortSignal.timeout(35000)});let body;try{body=await res.json()}catch{throw new Error(`HTTP ${res.status}`)}if(!res.ok)throw new Error(body.error||`HTTP ${res.status}`);return body}
function table(id,rows,empty='目前沒有資料'){const root=$(id);root.replaceChildren();if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=10;td.textContent=empty;tr.append(td);root.append(tr);return}for(const cols of rows){const tr=document.createElement('tr');for(const value of cols){const td=document.createElement('td');if(value instanceof Node)td.append(value);else td.textContent=String(value??'—');tr.append(td)}root.append(tr)}}
function renderControl(s){controlState=s;const live=s.config.mode==='live';$('bgpStatus').textContent=live?(s.bgp.connected?`已連線 · AS${s.bgp.asn} · Router ID ${s.bgp.router_id}`:`未連線 · ${s.bgp.error||'檢查中'}`):'尚未設定 GoBGP 連線';$('announce').textContent='宣告路由';$('announce').disabled=!live||!s.bgp.connected;table('peers',(s.bgp.peers||[]).map(p=>[p.address,p.asn,p.state]),live?'尚無鄰居':'尚未連線');
 if(!settingsLoaded){const f=$('settingsForm');f.elements.endpoint.value=s.config.endpoint;f.elements.allowed_prefixes.value=s.config.allowed_prefixes.join('\n');settingsLoaded=true}
 table('routes',[...s.routes].reverse().map(r=>{let action='—';if(!['withdrawn','absent','failed'].includes(r.state)){action=document.createElement('button');action.textContent=r.rule_id?'停用規則並撤回':'撤回';action.addEventListener('click',()=>perform(action,()=>r.rule_id?api(`/api/rules/${r.rule_id}/enabled`,'POST',{enabled:false}):api(`/api/routes/${r.id}/withdraw`,'POST',{}),'撤回操作已送出'))}return [r.prefix,r.next_hop,r.communities.join(', '),r.mode==='live'?'實際':'模擬',states[r.state]||r.state,time(r.expires),[r.note,r.error].filter(Boolean).join('／'),action]}),'尚無路由操作');
 table('events',[...s.events].reverse().map(e=>[time(e.time),actions[e.action]||e.action,e.prefix||'—',e.mode==='live'?'實際':'尚未設定',e.detail]),'尚無操作紀錄');if(s.persistence_error)message('狀態儲存失敗：'+s.persistence_error)
}
async function perform(button,fn,success){button.disabled=true;try{await fn();message(success);renderControl(await api('/api/state'))}catch(e){message(e.message)}finally{button.disabled=false}}
$('routeForm').addEventListener('submit',e=>{e.preventDefault();const f=e.currentTarget;perform($('announce'),()=>api('/api/routes','POST',{prefix:f.elements.prefix.value.trim(),next_hop:f.elements.next_hop.value.trim(),communities:f.elements.communities.value.split(/[\s,]+/).filter(Boolean),ttl:Number(f.elements.ttl.value),note:f.elements.note.value.trim()}),'路由操作已完成')});
$('settingsForm').addEventListener('submit',e=>{e.preventDefault();const f=e.currentTarget;perform(f.querySelector('button'),()=>api('/api/settings','PUT',{mode:'live',endpoint:f.elements.endpoint.value.trim(),allowed_prefixes:f.elements.allowed_prefixes.value.split(/[\s,]+/).filter(Boolean)}),'設定已儲存')});
const grafana=new URL(location.href);grafana.port='3000';grafana.pathname='/d/aegisflow-overview';grafana.search='';grafana.hash='';$('grafana').href=grafana.href;
async function pollControl(){try{renderControl(await api('/api/state'))}catch(e){$('bgpStatus').textContent='控制狀態更新失敗：'+e.message}finally{setTimeout(pollControl,3000)}}
const panels=[[14,'頻寬'],[15,'封包'],[1,'總頻寬'],[2,'每秒封包'],[3,'累計流量'],[4,'每秒樣本'],[5,'protocol 頻寬'],[6,'protocol 封包'],[8,'目的網段頻寬'],[9,'目的網段封包'],[12,'tcp flag 頻寬'],[13,'tcp flag']];
for(const [id,title] of panels){const frame=document.createElement('iframe');frame.title=title;frame.dataset.panelId=id;frame.referrerPolicy='same-origin';frame.loading=id>=14?'eager':'lazy';$(id>=14?'grafanaOverview':id<=4?'grafanaStats':'grafanaCharts').append(frame)}
function updatePanels(){
 $('interfaceHeading').textContent=$('directionSelect').value+' 詳細資料';
 const params=new URLSearchParams({orgId:'1',from:$('chartRange').value,to:'now',refresh:'5s','var-direction':$('directionSelect').value,theme:'light'});
 const dashboard=new URL(grafana);dashboard.search=params.toString();$('grafana').href=dashboard.href;
 for(const frame of document.querySelectorAll('[data-panel-id]')){const id=Number(frame.dataset.panelId);const url=new URL(dashboard);url.pathname='/d-solo/aegisflow-overview';url.searchParams.set('panelId',id);if(id>=14)url.searchParams.set('var-direction','IN');if(frame.getAttribute('src')!==url.href)frame.src=url.href}
}
const initialDirection=new URLSearchParams(location.search).get('direction');if(['IN','OUT'].includes(initialDirection))$('directionSelect').value=initialDirection;
$('chartRange').addEventListener('change',()=>updatePanels());
$('directionSelect').addEventListener('change',()=>updatePanels());
updatePanels();pollControl();
