"""Analyst-first HTML report: one offline file, data embedded as JSON, rendered by inline JS.

Sections (in order): summary, activity (filters + charts + day-grouped timeline), apps, features
(services), permissions, programs, recovered, findings, technical.
"""
from __future__ import annotations

import html
import json

from .views import SERVICES

# Fixed service -> categorical slot (colour follows the entity, never its rank). Others -> slot 0 (grey).
SERVICE_SLOT = {"Camera": 1, "Microphone": 2, "Location": 3, "Contacts": 4, "Screen capture (no border)": 5,
                "Passkey use": 6, "Passkey list": 7, "Screen capture (programmatic)": 8}

ICONS = {
    "camera": '<path d="M3 7h3l2-2h8l2 2h3v12H3z"/><circle cx="12" cy="13" r="3.5"/>',
    "mic": '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/>',
    "pin": '<path d="M12 21s-6-6.2-6-11a6 6 0 0 1 12 0c0 4.8-6 11-6 11z"/><circle cx="12" cy="10" r="2.2"/>',
    "people": '<circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.5 2.7-6 6-6s6 2.5 6 6"/><circle cx="17" cy="9" r="2.4"/><path d="M16 14c2.8.2 5 2.5 5 5.5"/>',
    "screen": '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/><path d="M7 8h4M7 8v3" />',
    "key": '<circle cx="8" cy="14" r="4"/><path d="M11 11l8-8M16 6l2 2M14 8l2 2"/>',
    "calendar": '<rect x="3" y="5" width="18" height="16" rx="1.5"/><path d="M3 10h18M8 3v4M16 3v4"/>',
    "mail": '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="M3 7l9 6 9-6"/>',
    "chat": '<path d="M4 5h16v11H9l-5 4z"/>', "phone": '<path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
    "check": '<path d="M4 12l5 5L20 6"/>', "bell": '<path d="M6 16V11a6 6 0 0 1 12 0v5l2 2H4z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
    "radio": '<circle cx="12" cy="12" r="2"/><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4M5 5a10 10 0 0 0 0 14M19 5a10 10 0 0 1 0 14"/>',
    "wifi": '<path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>',
    "file": '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>', "image": '<rect x="3" y="5" width="18" height="14" rx="1.5"/><circle cx="9" cy="10" r="2"/><path d="M21 17l-5-5-9 7"/>',
    "film": '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="M7 5v14M17 5v14M3 9h4M3 15h4M17 9h4M17 15h4"/>',
    "music": '<path d="M9 18V5l11-2v13"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="17.5" cy="16" r="2.5"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>', "chip": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "dot": '<circle cx="12" cy="12" r="4"/>', "shield": '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
    "app": '<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l5 5"/>', "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    "moon": '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 7 7 0 1 0 20 14.5z"/>', "alert": '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.5"/>',
    "restore": '<path d="M4 12a8 8 0 1 0 2.3-5.7"/><path d="M4 4v4h4"/>',
}

CSS = r"""
:root{color-scheme:light;--bg:#f6f6f3;--surface:#fcfcfb;--surface-2:#f0efea;--line:#e3e2dc;--text:#141413;--text-2:#52514e;
--muted:#7a7974;--accent:#2a78d6;--accent-soft:#e3eefb;--ok:#1e7d32;--ok-soft:#e5f3e7;--bad:#c62828;--bad-soft:#fbe7e6;
--warn:#a35d00;--warn-soft:#fbf0dc;--info-soft:#ecebf9;--shadow:0 1px 2px rgba(0,0,0,.05),0 4px 14px rgba(0,0,0,.04);
--s0:#8a8983;--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--s4:#eda100;--s5:#e87ba4;--s6:#008300;--s7:#6250d6;--s8:#e34948}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#121211;--surface:#1a1a19;
--surface-2:#232321;--line:#33332f;--text:#f0efec;--text-2:#c3c2b7;--muted:#8f8e86;--accent:#3987e5;--accent-soft:#1d2b3d;
--ok:#6cc678;--ok-soft:#1d2e20;--bad:#ef7a73;--bad-soft:#3a1f1d;--warn:#e5a84a;--warn-soft:#3a2d17;--info-soft:#25233d;
--shadow:none;--s0:#77766f;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#008300;--s7:#9085e9;--s8:#e66767}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#121211;--surface:#1a1a19;--surface-2:#232321;--line:#33332f;--text:#f0efec;
--text-2:#c3c2b7;--muted:#8f8e86;--accent:#3987e5;--accent-soft:#1d2b3d;--ok:#6cc678;--ok-soft:#1d2e20;--bad:#ef7a73;
--bad-soft:#3a1f1d;--warn:#e5a84a;--warn-soft:#3a2d17;--info-soft:#25233d;--shadow:none;--s0:#77766f;--s1:#3987e5;--s2:#d95926;
--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#008300;--s7:#9085e9;--s8:#e66767}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI Variable","Segoe UI",system-ui,-apple-system,sans-serif}
svg.i{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round;flex:none}
.top{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(8px);
border-bottom:1px solid var(--line)}
.top .in{max-width:1320px;margin:auto;padding:10px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:15px}
.brand .logo{width:30px;height:30px;border-radius:8px;background:var(--accent);color:#fff;display:grid;place-items:center}
.nav{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto}
.nav a{color:var(--text-2);text-decoration:none;font-size:13px;padding:5px 9px;border-radius:7px}
.nav a:hover{background:var(--surface-2);color:var(--text)}
.iconbtn{border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:8px;padding:6px;cursor:pointer;display:grid;place-items:center}
main{max-width:1320px;margin:auto;padding:22px 20px 80px}
section{margin:0 0 38px;scroll-margin-top:70px}
h2{font-size:19px;margin:0 0 4px;display:flex;align-items:center;gap:8px}h2 .count{font-size:12px;font-weight:600;color:var(--muted);
background:var(--surface-2);border-radius:20px;padding:1px 9px}
.lead{color:var(--text-2);margin:0 0 14px;max-width:880px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
.hero{padding:22px 24px;display:grid;gap:16px;background:linear-gradient(135deg,var(--accent-soft),var(--surface) 55%)}
.hero h1{margin:0;font-size:24px;letter-spacing:-.2px}
.hero p{margin:0;color:var(--text-2);font-size:15px;max-width:980px}
.meta{display:flex;flex-wrap:wrap;gap:6px 16px;color:var(--muted);font-size:12.5px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px}
.tile{padding:12px 14px;border-radius:12px;background:var(--surface);border:1px solid var(--line)}
.tile b{display:block;font-size:24px;font-weight:650;letter-spacing:-.3px;font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:12px}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px;margin-top:14px}
.svc{display:flex;gap:12px;align-items:center;padding:12px 14px;cursor:pointer;text-align:left;font:inherit;color:inherit}
.svc:hover,.appcard:hover{border-color:var(--accent)}
.svc .ic{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;color:#fff;flex:none}
.svc .n{font-weight:650}.svc small{display:block;color:var(--muted);font-size:12px}
.filters{padding:10px 12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.filters .search{display:flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:9px;padding:0 8px;background:var(--surface-2);flex:1 1 220px}
.filters input,.filters select{font:inherit;color:var(--text);background:var(--surface-2);border:1px solid var(--line);border-radius:9px;padding:6px 8px;min-width:0}
.filters .search input{border:0;background:transparent;width:100%;outline:none}
.filters label{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:5px}
.btn{font:inherit;font-size:13px;border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:9px;padding:6px 11px;cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.shown{margin-left:auto;font-size:12.5px;color:var(--muted)}
.charts{display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:14px}
@media (max-width:900px){.charts{grid-template-columns:1fr}}
.chart{padding:14px 16px}.chart h3{margin:0 0 2px;font-size:14px}.chart .sub{color:var(--muted);font-size:12px;margin-bottom:8px}
.chart svg{display:block;width:100%;overflow:visible}.legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:12px;color:var(--text-2);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.tip{position:fixed;pointer-events:none;background:var(--text);color:var(--bg);font-size:12px;padding:6px 9px;border-radius:7px;z-index:50;display:none;max-width:280px}
.day{margin:16px 0 6px;display:flex;align-items:baseline;gap:10px;position:sticky;top:53px;z-index:5;background:var(--bg);padding:4px 0}
.day b{font-size:14px}.day span{color:var(--muted);font-size:12px}
.ev{display:grid;grid-template-columns:150px 1.4fr 1.1fr 110px 1fr 140px;gap:10px;align-items:center;padding:9px 14px;
border:1px solid var(--line);background:var(--surface);border-radius:11px;margin-bottom:5px;cursor:pointer}
.ev:hover{border-color:var(--accent)}.ev>*{min-width:0}.ev .badge{white-space:normal}
@media (max-width:980px){.ev{grid-template-columns:1fr 1fr}}
.ev .t{font-variant-numeric:tabular-nums;font-weight:600}.ev .t small{display:block;font-weight:400;color:var(--muted)}
.app{display:flex;gap:9px;align-items:center;min-width:0}.app .av{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;
font-weight:700;font-size:13px;color:var(--text);background:var(--surface-2);flex:none}
.app .nm{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.app small{display:block;color:var(--muted);font-size:11.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.svcb{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;font-weight:600;padding:3px 9px 3px 4px;border-radius:20px;background:var(--surface-2)}
.svcb .ic{width:20px;height:20px;border-radius:50%;display:grid;place-items:center;color:#fff}.svcb svg.i{width:12px;height:12px}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:600;padding:2px 9px;border-radius:20px;white-space:nowrap}
.b-ok{background:var(--ok-soft);color:var(--ok)}.b-bad{background:var(--bad-soft);color:var(--bad)}.b-warn{background:var(--warn-soft);color:var(--warn)}
.b-info{background:var(--info-soft);color:var(--text-2)}.b-acc{background:var(--accent-soft);color:var(--accent)}
.who{font-size:12.5px;color:var(--text-2);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.detail{grid-column:1/-1;border-top:1px dashed var(--line);margin-top:6px;padding-top:9px;display:none;cursor:auto}
.ev.open .detail{display:block}.detail p{margin:0 0 8px;font-size:14px}
.kv{display:grid;grid-template-columns:170px 1fr;gap:4px 14px;font-size:12.5px}.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-all}
.more{display:block;margin:12px auto 0}
.appgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:10px}
.appcard{padding:14px 16px;cursor:pointer;display:grid;gap:8px}.appcard .top2{display:flex;gap:10px;align-items:center}
.appcard h4{margin:0;font-size:15px}.appcard .path{font-size:11.5px;color:var(--muted);word-break:break-all}
.stats{display:grid;grid-template-columns:repeat(4,auto);justify-content:start;gap:16px;font-size:12px;color:var(--muted)}.stats b{display:block;color:var(--text);font-size:15px;white-space:nowrap}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.tw{overflow:auto;max-height:620px;border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{position:sticky;top:0;background:var(--surface-2);text-align:left;
padding:8px 10px;font-weight:600;color:var(--text-2);cursor:pointer;white-space:nowrap;border-bottom:1px solid var(--line)}
td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}tr:hover td{background:var(--surface-2)}
td.mono,.mono{font-family:"Cascadia Mono",Consolas,ui-monospace,monospace;font-size:11.5px;word-break:break-all}
.toolbar{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.toolbar input{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:6px 9px;min-width:220px}
.finding{padding:12px 16px;margin-bottom:8px;border-left:4px solid var(--line);overflow-wrap:anywhere}.finding.HIGH{border-left-color:var(--bad)}
.finding.MEDIUM{border-left-color:var(--warn)}.finding h4{margin:0 0 3px;font-size:14px}.finding p{margin:0;color:var(--text-2);font-size:13px}
details.tech{padding:12px 16px}details.tech summary{cursor:pointer;font-weight:600}
.empty{padding:18px;color:var(--muted);text-align:center}
a{color:var(--accent)}
@media print{.top,.filters,.more{display:none}.ev .detail{display:block}}
"""

JS = r"""
const D=JSON.parse(document.getElementById('cam-data').textContent);
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ICON=k=>`<svg class="i" viewBox="0 0 24 24"><use href="#ic-${D.icons[k]?k:'dot'}"/></svg>`;
const svcSlot=f=>D.serviceSlot[f]||0, svcIcon=f=>D.serviceIcon[f]||'dot';
const svcBadge=f=>`<span class="svcb"><span class="ic" style="background:var(--s${svcSlot(f)})">${ICON(svcIcon(f))}</span>${esc(f)}</span>`;
const accBadge=a=>a==='Allowed'?`<span class="badge b-ok">● Allowed</span>`:a==='Blocked'?`<span class="badge b-bad">✕ Blocked</span>`:`<span class="badge b-warn">? ${esc(a)}</span>`;
const srcBadge=s=>{const c=s.startsWith('Recovered')?'b-warn':s.includes('WAL')?'b-acc':s.startsWith('Registry')||s.includes('+')?'b-acc':'b-info';return `<span class="badge ${c}">${esc(s)}</span>`};
const T=r=>(r.when_local||r.when_utc||'');
const who=u=>{u=String(u||'');const m=u.match(/^(.*?)\(?(S-1-5-21-[\d-]+?-(\d+))\)?$/);return m?`<span title="${esc(u)}">${esc((m[1].trim()?m[1].trim()+' ':'')+'…-'+m[3])}</span>`:esc(u||'—')};
const hm=s=>s?s.slice(11,19):'';
/* ---------- theme ---------- */
try{const t=localStorage.getItem('cam-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}
$('#theme').onclick=()=>{const cur=document.documentElement.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
const n=cur==='dark'?'light':'dark';document.documentElement.dataset.theme=n;try{localStorage.setItem('cam-theme',n)}catch(e){};drawCharts()};
/* ---------- filters ---------- */
const F={q:'',app:'',svc:'',user:'',src:'',from:'',to:'',prompts:true,order:'asc'};
function opts(sel,vals,label){sel.innerHTML=`<option value="">${label}</option>`+vals.map(v=>`<option>${esc(v)}</option>`).join('')}
const uniq=(k,rows)=>[...new Set(rows.map(r=>r[k]).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
opts($('#f-app'),uniq('app',D.activity),'All applications');opts($('#f-svc'),uniq('feature',D.activity),'All services');
opts($('#f-user'),uniq('user',D.activity),'All accounts');opts($('#f-src'),uniq('source',D.activity),'All sources');
const days=uniq('date',D.activity);if(days.length){$('#f-from').min=$('#f-to').min=days[0];$('#f-from').max=$('#f-to').max=days[days.length-1]}
function filtered(){const q=F.q.toLowerCase();return D.activity.filter(r=>(F.prompts||r.event==='use')&&(!F.app||r.app===F.app)&&
(!F.svc||r.feature===F.svc)&&(!F.user||r.user===F.user)&&(!F.src||r.source===F.src)&&(!F.from||r.date>=F.from)&&(!F.to||r.date<=F.to)&&
(!q||[r.app,r.app_id,r.feature,r.user,r.source,r.app_location,r.sha1,r.when_local,r.when_utc,r.note].join(' ').toLowerCase().includes(q)))}
function bind(id,key,ev='change'){$(id).addEventListener(ev,e=>{F[key]=e.target.type==='checkbox'?e.target.checked:e.target.value;render()})}
bind('#f-q','q','input');bind('#f-app','app');bind('#f-svc','svc');bind('#f-user','user');bind('#f-src','src');bind('#f-from','from');bind('#f-to','to');bind('#f-pr','prompts');bind('#f-order','order');
$('#f-reset').onclick=()=>{Object.assign(F,{q:'',app:'',svc:'',user:'',src:'',from:'',to:'',prompts:true,order:'asc'});$('#f-order').value='asc';
['#f-q','#f-app','#f-svc','#f-user','#f-src','#f-from','#f-to'].forEach(s=>$(s).value='');$('#f-pr').checked=true;render()};
function setFilter(k,v){F[k]=v;const m={app:'#f-app',svc:'#f-svc'}[k];if(m)$(m).value=v;render();$('#activity').scrollIntoView()}
/* ---------- timeline ---------- */
let PAGE=300,shownN=PAGE,cur=[];
function dayLabel(d){if(!d)return 'Date not recorded';const x=new Date(d+'T00:00:00');return isNaN(x)?d:x.toLocaleDateString(undefined,{weekday:'long',year:'numeric',month:'long',day:'numeric'})}
function sentence(r){if(r.event==='prompt')return `Windows asked for <b>${esc(r.feature)}</b> permission for <b>${esc(r.app)}</b>.`;
return `<b>${esc(r.app)}</b> used <b>${esc(r.feature)}</b> ${r.duration_text&&r.duration_text!=='instant'?'for <b>'+esc(r.duration_text)+'</b>':'(instant access)'} — <b>${esc(r.access.toLowerCase())}</b>${r.user?' under account '+esc(r.user):''}.`}
function row(r,i){const loc=r.app_location||r.app_id;return `<div class="ev" data-i="${i}">
<div class="t">${esc(hm(T(r)))}${r.end_local||r.end_utc?' → '+esc(hm(r.end_local||r.end_utc)):''}<small>${r.event==='use'?esc(r.duration_text||''):'prompt'}${r.use_no?' · '+esc(r.use_no):''}</small></div>
<div class="app"><span class="av" style="box-shadow:inset 0 0 0 2px var(--s${svcSlot(r.feature)})">${esc((r.app||'?').replace(/^unknown /,'?').slice(0,1).toUpperCase())}</span>
<div style="min-width:0"><div class="nm" title="${esc(r.app)}">${esc(r.app)}</div><small title="${esc(loc)}">${esc(r.app_kind)}${loc?' · '+esc(loc):''}</small></div></div>
<div>${svcBadge(r.feature)}</div><div>${accBadge(r.access)}</div><div class="who">${who(r.user)}</div><div>${srcBadge(r.source)}</div>
<div class="detail"><p>${sentence(r)}</p><dl class="kv">
<dt>Service</dt><dd>${esc(r.feature)}${r.service_desc?' — '+esc(r.service_desc):''}</dd>
<dt>Start / end (local)</dt><dd>${esc(r.when_local)}${r.end_local?' → '+esc(r.end_local):''}</dd>
<dt>Start / end (UTC)</dt><dd>${esc(r.when_utc)}${r.end_utc?' → '+esc(r.end_utc):''}</dd>
<dt>Duration</dt><dd>${esc(r.duration_text||'—')}</dd><dt>Account</dt><dd>${esc(r.user||'—')}</dd>
<dt>Allowed by</dt><dd>${esc(r.allowed_by||'—')}</dd><dt>Use number</dt><dd>${esc(r.use_no||'—')}</dd>
<dt>Application id</dt><dd class="mono">${esc(r.app_id)}</dd><dt>Application location</dt><dd class="mono">${esc(r.app_location||'—')}</dd>
<dt>Installer</dt><dd>${esc(r.installer||'—')}</dd>${r.sha1?`<dt>SHA-1</dt><dd class="mono">${esc(r.sha1)}</dd>`:''}
<dt>Evidence record</dt><dd>${esc(r.ref)} · ${esc(r.source)}</dd>${r.note?`<dt>Note</dt><dd>${esc(r.note)}</dd>`:''}</dl></div></div>`}
function renderTimeline(){const box=$('#timeline');if(!cur.length){box.innerHTML='<div class="card empty">No activity matches these filters.</div>';$('#more').style.display='none';return}
const part=cur.slice(0,shownN);let h='',last=null,perDay={};cur.forEach(r=>perDay[r.date]=(perDay[r.date]||0)+1);
part.forEach((r,i)=>{if(r.date!==last){last=r.date;h+=`<div class="day"><b>${esc(dayLabel(r.date))}</b><span>${perDay[r.date]} event${perDay[r.date]>1?'s':''}</span></div>`}h+=row(r,i)});
box.innerHTML=h;$('#more').style.display=cur.length>shownN?'block':'none';$('#more').textContent=`Show ${Math.min(PAGE,cur.length-shownN)} more (${cur.length-shownN} hidden)`}
$('#timeline').addEventListener('click',e=>{const ev=e.target.closest('.ev');if(ev&&!e.target.closest('.detail'))ev.classList.toggle('open')});
$('#more').onclick=()=>{shownN+=PAGE;renderTimeline()};
/* ---------- charts ---------- */
const tip=$('#tip');function showTip(e,h){tip.innerHTML=h;tip.style.display='block';tip.style.left=Math.min(e.clientX+12,innerWidth-290)+'px';tip.style.top=(e.clientY+12)+'px'}
function hideTip(){tip.style.display='none'}
function drawCharts(){const uses=cur.filter(r=>r.event==='use');const byDay={},svcs=new Set();uses.forEach(r=>{(byDay[r.date]??={})[r.feature]=(byDay[r.date][r.feature]||0)+1;svcs.add(r.feature)});
const dk=Object.keys(byDay).sort(),sv=[...svcs].sort((a,b)=>svcSlot(a)-svcSlot(b)||a.localeCompare(b));
const W=$('#c-day').clientWidth||700,H=190,pl=34,pb=24,pt=8;const max=Math.max(1,...dk.map(d=>Object.values(byDay[d]).reduce((a,b)=>a+b,0)));
const bw=Math.max(2,Math.min(38,(W-pl)/Math.max(dk.length,1)-2));let s=`<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="Uses per day by service">`;
for(let g=0;g<=4;g++){const y=pt+(H-pb-pt)*(1-g/4);s+=`<line x1="${pl}" x2="${W}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${pl-6}" y="${y+4}" text-anchor="end" font-size="10" fill="var(--muted)">${Math.round(max*g/4)}</text>`}
dk.forEach((d,i)=>{const x=pl+i*((W-pl)/dk.length)+((W-pl)/dk.length-bw)/2;let y=H-pb;sv.forEach(f=>{const n=byDay[d][f]||0;if(!n)return;const h=(H-pb-pt)*n/max;
s+=`<rect x="${x}" y="${y-h}" width="${bw}" height="${Math.max(h-2,1)}" rx="${Math.min(4,bw/3)}" fill="var(--s${svcSlot(f)})" data-t="${esc(d)}|${esc(f)}|${n}"/>`;y-=h});
if(dk.length<=31||i%Math.ceil(dk.length/12)===0)s+=`<text x="${x+bw/2}" y="${H-8}" text-anchor="middle" font-size="10" fill="var(--muted)">${d.slice(5)}</text>`});
s+='</svg>';$('#c-day').innerHTML=dk.length?s:'<div class="empty">No uses in range</div>';
$('#l-day').innerHTML=sv.map(f=>`<span><i style="background:var(--s${svcSlot(f)})"></i>${esc(f)}</span>`).join('');
const hours=Array(24).fill(0);uses.forEach(r=>{const h=parseInt((T(r)).slice(11,13));if(!isNaN(h))hours[h]++});const W2=$('#c-hour').clientWidth||320,m2=Math.max(1,...hours);
let s2=`<svg viewBox="0 0 ${W2} ${H}" height="${H}" role="img" aria-label="Uses by hour of day">`;const b2=(W2-10)/24;
hours.forEach((n,h)=>{const hh=(H-pb-pt)*n/m2;s2+=`<rect x="${5+h*b2+1}" y="${H-pb-hh}" width="${b2-2}" height="${Math.max(hh,n?1:0)}" rx="3" fill="var(--s1)" data-t="${h}:00|uses|${n}"/>`;
if(h%3===0)s2+=`<text x="${5+h*b2+b2/2}" y="${H-8}" text-anchor="middle" font-size="10" fill="var(--muted)">${String(h).padStart(2,'0')}</text>`});
$('#c-hour').innerHTML=s2+'</svg>';
$$('#c-day rect,#c-hour rect').forEach(r=>{r.addEventListener('mousemove',e=>{const[a,b,c]=r.dataset.t.split('|');showTip(e,`<b>${a}</b><br>${b}: ${c}`)});r.addEventListener('mouseleave',hideTip)})}
/* ---------- generic tables ---------- */
function table(el,rows,cols,opts={}){const st={k:null,asc:true,q:''};function draw(){let rs=rows.filter(r=>!st.q||cols.map(c=>r[c[0]]).join(' ').toLowerCase().includes(st.q));
if(opts.filter)rs=rs.filter(opts.filter);if(st.k)rs=[...rs].sort((a,b)=>{const x=a[st.k],y=b[st.k];const c=(typeof x==='number'&&typeof y==='number')?x-y:String(x??'').localeCompare(String(y??''));return st.asc?c:-c});
el.querySelector('.n').textContent=rs.length;el.querySelector('tbody').innerHTML=rs.length?rs.map(r=>'<tr>'+cols.map(c=>`<td${c[2]?' class="'+c[2]+'"':''}>${c[3]?c[3](r):esc(r[c[0]])}</td>`).join('')+'</tr>').join(''):`<tr><td colspan="${cols.length}" class="empty">Nothing to show</td></tr>`}
el.innerHTML=`<div class="toolbar"><input placeholder="Search…"><span class="shown"><span class="n"></span> rows</span>${opts.extra||''}</div><div class="tw card"><table><thead><tr>${cols.map(c=>`<th data-k="${c[0]}">${esc(c[1])}</th>`).join('')}</tr></thead><tbody></tbody></table></div>`;
el.querySelector('input').oninput=e=>{st.q=e.target.value.toLowerCase();draw()};el.querySelectorAll('th').forEach(th=>th.onclick=()=>{st.asc=st.k===th.dataset.k?!st.asc:true;st.k=th.dataset.k;draw()});
if(opts.onExtra)opts.onExtra(el,draw);draw()}
/* ---------- apps & services ---------- */
function renderApps(){const g=$('#appgrid');const apps=D.apps.filter(a=>a.uses>0||a.prompts>0);
g.innerHTML=apps.length?apps.map(a=>`<div class="card appcard" data-app="${esc(a.app)}"><div class="top2"><span class="av" style="width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:var(--surface-2);font-weight:700">${esc(a.app.slice(0,1).toUpperCase())}</span>
<div style="min-width:0"><h4>${esc(a.app)}</h4><div class="path">${esc(a.app_kind)} · ${esc(a.app_location||a.app_id)}</div></div></div>
<div class="chips">${(a.services?a.services.split(', '):[]).map(svcBadge).join('')}${a.prompts?`<span class="badge b-warn">${a.prompts} location prompt${a.prompts>1?'s':''}</span>`:''}${a.blocked?`<span class="badge b-bad">${a.blocked} blocked</span>`:''}</div>
<div class="stats"><div><b>${a.uses}</b>uses</div><div><b>${esc(a.total_duration||'—')}</b>total time</div><div><b>${esc((a.first_local||a.first_seen_local||'').slice(0,10)||'—')}</b>first</div><div><b>${esc((a.last_local||'').slice(0,10)||'—')}</b>last</div></div></div>`).join(''):'<div class="card empty">No applications</div>';
g.querySelectorAll('.appcard').forEach(c=>c.onclick=()=>setFilter('app',c.dataset.app))}
function renderServices(){const by={};D.features.forEach(f=>{(by[f.feature]??=[]).push(f)});const keys=Object.keys(by).sort((a,b)=>by[b].reduce((s,x)=>s+x.uses,0)-by[a].reduce((s,x)=>s+x.uses,0));
$('#svcgrid').innerHTML=keys.map(k=>{const n=by[k].reduce((s,x)=>s+x.uses,0),last=by[k].map(x=>x.last_local||x.last_utc).sort().pop()||'';
return `<button class="card svc" data-svc="${esc(k)}"><span class="ic" style="background:var(--s${svcSlot(k)})">${ICON(svcIcon(k))}</span><span><span class="n">${esc(k)}</span><small>${n} use${n>1?'s':''} · ${by[k].length} app${by[k].length>1?'s':''}</small><small>last ${esc(last.slice(0,16))}</small></span></button>`}).join('')||'<div class="card empty">No service use recorded</div>';
$$('#svcgrid .svc').forEach(b=>b.onclick=()=>setFilter('svc',b.dataset.svc))}
/* ---------- render ---------- */
function render(){cur=filtered();if(F.order==='desc'){const d=cur.filter(r=>r.date),u=cur.filter(r=>!r.date);cur=d.reverse().concat(u)}shownN=PAGE;$('#shown').textContent=`${cur.length.toLocaleString()} of ${D.activity.length.toLocaleString()} events`;renderTimeline();drawCharts()}
renderApps();renderServices();render();
table($('#t-features'),D.features,[['feature','Service',null,r=>svcBadge(r.feature)],['app','Application'],['uses','Uses'],['blocked','Blocked'],['first_local','First use'],['last_local','Last use'],['total_duration','Total time'],['service_desc','What it means']]);
table($('#t-perm'),D.permissions,[['flag','Flag',null,r=>r.flag?`<span class="badge ${r.flag.includes('Deny')?'b-bad':'b-info'}">${esc(r.flag)}</span>`:''],['app','Application'],['feature','Service'],['setting','Setting',null,r=>r.setting?`<span class="badge ${r.setting==='Allow'?'b-ok':r.setting==='Deny'?'b-bad':'b-warn'}">${esc(r.setting)}</span>`:''],['scope','Decided by'],['user','Account',null,r=>who(r.user)],['used_count','Times used'],['last_used_local','Last used'],['note','Note']]);
table($('#t-prog'),D.programs,[['program','Program'],['location_flag','Flag',null,r=>r.location_flag?`<span class="badge b-warn">${esc(r.location_flag)}</span>`:''],['exe_path','Path','mono'],['sha1','SHA-1','mono'],['first_seen_local','First seen'],['uses','Uses'],['prompts','Location prompts'],['installer','Installer']]);
const rec=D.activity.filter(r=>r.source.startsWith('Recovered'));$('#rec-n').textContent=rec.length;
table($('#t-rec'),rec,[['when_local','Start (local)'],['end_local','End (local)'],['duration_text','Duration'],['app','Application'],['feature','Service'],['access','Allowed/Blocked'],['user','Account'],['source','Recovered from'],['ref','Record'],['note','Note']]);
$('#findings').insertAdjacentHTML('beforeend',D.findings.length?D.findings.map(f=>`<div class="card finding ${esc(f.severity)}"><h4>${esc(f.title)}</h4><p>${esc(f.detail)}</p></div>`).join(''):'<div class="card empty">No findings</div>');
let rt;addEventListener('resize',()=>{clearTimeout(rt);rt=setTimeout(drawCharts,150)});
"""


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def write_html_v2(path: str, ctx: dict) -> None:
    s = ctx["summary"]
    act = ctx["activity"]
    uses = [r for r in act if r.get("event") == "use"]
    data = dict(activity=act, apps=ctx["apps"], features=ctx["features"], permissions=ctx["permissions"],
                programs=ctx["programs"], findings=ctx["findings"], serviceSlot=dict(SERVICE_SLOT),
                serviceIcon={v[0]: v[2] for v in SERVICES.values()}, icons={k: 1 for k in ICONS})
    data_json = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")
    symbols = "".join(f'<symbol id="ic-{k}" viewBox="0 0 24 24">{v}</symbol>' for k, v in ICONS.items())
    icon = lambda k: f'<svg class="i" viewBox="0 0 24 24"><use href="#ic-{k}"/></svg>'  # noqa: E731
    tiles = [("Recorded uses", f"{len(uses):,}"), ("Applications", f"{len({r['app_id'].lower() for r in uses}):,}"),
             ("Services", f"{len({r['feature'] for r in uses}):,}"),
             ("Location prompts", f"{sum(1 for r in act if r.get('event') == 'prompt'):,}"),
             ("Recovered / WAL rows", f"{sum(1 for r in act if r['source'].startswith('Recovered') or 'WAL' in r['source']):,}"),
             ("Accounts", f"{len({r['user'] for r in uses if r.get('user')}):,}")]
    integrity = ('<span class="badge b-ok">✓ evidence unchanged (hash verified)</span>' if ctx["integrity_ok"]
                 else '<span class="badge b-bad">✕ an input changed during the run</span>')
    ev_rows = "".join(f"<tr><td>{_esc(e.get('role'))}</td><td>{_esc(e.get('size'))}</td><td class='mono'>{_esc(e.get('sha256'))}</td>"
                      f"<td>{_esc(e.get('mtime_utc'))}</td><td>{'yes' if e.get('unchanged_after_run') else 'NO'}</td></tr>"
                      for e in ctx["evidence"])
    out = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CAM Activity Report</title><style>{CSS}</style></head><body>
<svg width="0" height="0" style="position:absolute">{symbols}</svg>
<div class="top"><div class="in"><div class="brand"><span class="logo">{icon('shield')}</span>Capability Access Manager · Activity report</div>
<nav class="nav"><a href="#summary">Summary</a><a href="#activity">Timeline</a><a href="#apps">Apps</a><a href="#features">Services</a>
<a href="#permissions">Permissions</a><a href="#programs">Programs</a><a href="#recovered">Recovered</a><a href="#findings">Findings</a>
<a href="#technical">Technical</a></nav><button class="iconbtn" id="theme" title="Light / dark">{icon('moon')}</button></div></div>
<main>
<section id="summary"><div class="card hero"><div><h1>{_esc(s.get('headline', 'Who used what, and when'))}</h1></div>
<p>{_esc(s.get('text', ''))}</p><div class="meta"><span>{_esc(s.get('system', ''))}</span><span>Evidence: {_esc(ctx['evidence_dir'])}</span>
<span>Times shown in local time UTC{_esc(ctx['tz_label'])} (UTC in details)</span><span>Generated {_esc(ctx['generated_utc'])} UTC by {_esc(ctx['tool'])}</span>{integrity}</div>
<div class="tiles">{''.join(f'<div class="tile"><b>{v}</b><span>{_esc(k)}</span></div>' for k, v in tiles)}</div></div>
<div class="svc-grid" id="svcgrid"></div></section>
<section id="activity"><h2>{icon('clock')}Activity timeline</h2><p class="lead">Every recorded use, oldest first, grouped by day. Click a row for the full
record: service meaning, start/end in local and UTC, account, the setting that allowed it, application path, installer and the evidence record.</p>
<div class="card filters"><div class="search">{icon('search')}<input id="f-q" placeholder="Search app, path, hash, account…"></div>
<select id="f-app"></select><select id="f-svc"></select><select id="f-user"></select><select id="f-src"></select>
<label>From <input type="date" id="f-from"></label><label>To <input type="date" id="f-to"></label>
<select id="f-order"><option value="asc">Oldest first</option><option value="desc">Newest first</option></select>
<label><input type="checkbox" id="f-pr" checked> include location prompts</label><button class="btn" id="f-reset">Reset</button><span class="shown" id="shown"></span></div>
<div class="charts"><div class="card chart"><h3>Uses per day</h3><div class="sub">stacked by service · follows the filters</div><div id="c-day"></div><div class="legend" id="l-day"></div></div>
<div class="card chart"><h3>Time of day</h3><div class="sub">uses by local hour</div><div id="c-hour"></div></div></div>
<div id="timeline"></div><button class="btn primary more" id="more">Show more</button></section>
<section id="apps"><h2>{icon('app')}Applications <span class="count">{len([a for a in ctx['apps'] if a.get('uses') or a.get('prompts')])}</span></h2>
<p class="lead">One card per application: services it used, how often, total time, first and last use. Click a card to filter the timeline.</p><div class="appgrid" id="appgrid"></div></section>
<section id="features"><h2>{icon('shield')}Services</h2><p class="lead">Which application used each service, how many times and when.</p><div id="t-features"></div></section>
<section id="permissions"><h2>{icon('check')}Permissions</h2><p class="lead">Current Allow / Deny / Prompt settings from CapabilityConsentStorage.db
(and the registry when a hive is supplied), set against actual use. <b>Used while now Deny</b> means the setting was changed after the app used the service.</p><div id="t-perm"></div></section>
<section id="programs"><h2>{icon('file')}Desktop programs</h2><p class="lead">Every desktop program Windows recorded, with its path, SHA-1 (as in Amcache), first-seen time, and
whether it ran from an unusual place.</p><div id="t-prog"></div></section>
<section id="recovered"><h2>{icon('restore')}Recovered records <span class="count" id="rec-n"></span></h2><p class="lead">Rows no longer in the live database:
deleted rows carved from free space and pages past the end of the file, and committed transactions found in WAL slack. They are also in the timeline, marked by source.</p><div id="t-rec"></div></section>
<section id="findings"><h2>{icon('alert')}Findings</h2><p class="lead">Checks on consistency, retention and integrity, highest severity first.</p></section>
<section id="technical"><h2>{icon('chip')}Technical details</h2>
<details class="card tech"><summary>Evidence files, hashes and method</summary><div class="tw" style="margin-top:10px"><table><thead><tr><th>File</th><th>Bytes</th><th>SHA-256</th><th>Modified (UTC)</th><th>Unchanged</th></tr></thead>
<tbody>{ev_rows}</tbody></table></div><div style="margin-top:10px">{ctx['method_html']}</div></details>
<p class="lead" style="margin-top:10px">Database internals (page map, WAL frames, raw tables, carving locations) are in <a href="{_esc(ctx['technical_report'])}">{_esc(ctx['technical_report'])}</a>.</p></section>
</main><div class="tip" id="tip"></div>
<script type="application/json" id="cam-data">{data_json}</script><script>{JS}</script></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
