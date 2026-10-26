/* Core: DOM helpers (no innerHTML - SSIDs are attacker-controlled), state, API, shared components */
window.WA=window.WA||{};
(function(W){
"use strict";
const $=(s,r)=>(r||document).querySelector(s);
const NS="http://www.w3.org/2000/svg";
function add(e,kids){for(const k of kids.flat(9)){if(k==null||k===false)continue;e.append(k.nodeType?k:document.createTextNode(String(k)))}}
function h(tag,p){const e=document.createElement(tag);for(const k in p||{}){const v=p[k];if(v==null||v===false)continue;
 if(k==="class")e.className=v;else if(k==="style")e.style.cssText=v;else if(k.startsWith("on"))e.addEventListener(k.slice(2),v);else e.setAttribute(k,v===true?"":v)}
 add(e,[].slice.call(arguments,2));return e}
function sv(tag,a){const e=document.createElementNS(NS,tag);for(const k in a||{})e.setAttribute(k,a[k]);add(e,[].slice.call(arguments,2));return e}
const P={wifi:"M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01",
grid:"M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",list:"M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
shield:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",alert:"M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01",
lock:"M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4",
unlock:"M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 9.9-1",
clock:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2",download:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3",
x:"M18 6 6 18M6 6l12 12",search:"M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35",
copy:"M20 9h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1",
trash:"M3 6h18M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2",
check:"M20 6 9 17l-5-5",play:"M5 3l14 9-14 9V3z",zap:"M13 2 3 14h9l-1 8 10-12h-9l1-8z",
cpu:"M4 4h16v16H4zM9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3",chev:"M6 9l6 6 6-6",
radar:"M19.07 4.93A10 10 0 0 0 6.99 3.34M4 6h.01M2.29 9.62A10 10 0 1 0 21.31 8.35M16.24 7.76A6 6 0 1 0 8.23 16.67M12 18h.01M17.99 11.66A6 6 0 0 1 15.77 16.67M12 12h.01M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z",
plus:"M12 5v14M5 12h14",refresh:"M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15",
sliders:"M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6",activity:"M22 12h-4l-3 9L9 3l-3 9H2",
users:"M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75",
server:"M2 2h20v8H2zM2 14h20v8H2zM6 6h.01M6 18h.01",
globe:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z",
key:"M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
book:"M4 19.5A2.5 2.5 0 0 1 6.5 17H20V2H6.5A2.5 2.5 0 0 0 4 4.5v15zM4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5",
help:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01",
tool:"M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z",
arrow:"M5 12h14M12 5l7 7-7 7",back:"M19 12H5M12 19l-7-7 7-7",
map:"M1 6v16l7-4 8 4 7-4V2l-7 4-8-4-7 4zM8 2v16M16 6v16"};
const ic=(n,s)=>{const e=sv("svg",{class:"i",viewBox:"0 0 24 24"},sv("path",{d:P[n]||P.wifi}));if(s){e.style.width=e.style.height=s+"px"}return e};

W.$=$;W.h=h;W.sv=sv;W.ic=ic;
W.sleep=ms=>new Promise(r=>setTimeout(r,ms));
W.S={caps:null,scans:[],cur:null,view:"overview",arg:"",filter:"all",q:"",sortK:"risk",sortD:1,lastBackend:null,pending:{}};
W.nets=()=>(W.S.cur&&W.S.cur.networks)||[];
W.LV={"SECURE":["secure","var(--ok)"],"VULNERABLE":["vuln","var(--warn)"],"HIGH RISK":["high","var(--bad)"],"ROGUE AP":["rogue","var(--rog)"]};
W.SEV={critical:"#ff4d7d",high:"#e2574c",medium:"#e3b04b",low:"#7fa6d9",info:"#a7a293",ok:"#6fbf9a"};

/* ---------- api ---------- */
W.api=async function(u,o){o=o||{};o.headers=Object.assign({"X-Requested-With":"wifiaudit","Content-Type":"application/json"},o.headers||{});
 const r=await fetch(u,o);let j={};try{j=await r.json()}catch(e){}
 if(!r.ok){const e=new Error(j.error||r.statusText);e.hint=j.hint;throw e}return j};
W.post=(u,b)=>W.api(u,{method:"POST",body:JSON.stringify(b||{})});
/* run a toolbox tool: inline tools return directly; slow ones return a job that we poll */
W.tool=async function(name,params,onTick){const r=await W.post("/api/tool/"+name,params);if(r.result!==undefined)return r.result;
 for(;;){await W.sleep(700);const j=await W.api("/api/jobs/"+r.job);if(onTick)onTick(j);
  if(j.state==="done")return j.result;if(j.state!=="running"){const e=new Error(j.error||"Failed");e.hint=j.hint;throw e}}};
W.store={get:k=>{try{return localStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}}};
W.fmt=ts=>{try{return new Date(ts).toLocaleString(undefined,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}catch(e){return ts}};
W.ago=ts=>{const m=Math.max(0,Math.round((Date.now()-new Date(ts).getTime())/60000));return m<1?"just now":m<60?m+" min ago":m<1440?Math.round(m/60)+" h ago":Math.round(m/1440)+" d ago"};

/* ---------- leave hooks (stop timers when leaving a page) ---------- */
W._leave=[];W.onLeave=f=>W._leave.push(f);W.runLeave=()=>{W._leave.splice(0).forEach(f=>{try{f()}catch(e){}})};

/* ---------- small components ---------- */
W.toast=function(msg,type){const c={ok:"var(--ok)",err:"var(--rog)",warn:"var(--warn)"}[type]||"var(--gold)";
 const t=h("div",{class:"toast",style:"--c:"+c},ic(type==="err"?"alert":"check",16),h("span",null,msg));$("#toasts").append(t);setTimeout(()=>t.remove(),4600)};
/* jargon with a dotted underline + hover explanation; click to open the Learn page entry */
W.T=function(key,label,down){const g=W.GLOSS[key];if(!g)return label||key;
 return h("span",{class:"term"+(down?" dn":""),"data-tip":g.s,tabindex:0,onclick:e=>{e.stopPropagation();location.hash="learn/"+key}},label||g.t.split(" (")[0])};
W.info=txt=>h("span",{class:"info","data-tip":txt},"i");
W.explain=function(title){return h("div",{class:"explain"},h("b",null,title),[].slice.call(arguments,1))};
W.orn=()=>h("div",{class:"orn"},"◆");
W.pill=l=>h("span",{class:"pill "+(W.LV[l]||W.LV["VULNERABLE"])[0]},h("i"),l);
W.sig=function(d){const n=d==null?0:d>-50?4:d>-60?3:d>-70?2:1;return h("span",{class:"sig",title:d==null?"n/a":d+" dBm"},[1,2,3,4].map(i=>h("i",{class:i<=n?"on":"",style:"height:"+(5+i*3)+"px"})))};
W.countUp=function(el,to,dec){dec=dec||0;const raf=window.requestAnimationFrame||(f=>setTimeout(f,16));const t0=Date.now(),D=900;
 (function step(){const p=Math.min(1,(Date.now()-t0)/D),e=1-Math.pow(1-p,3);el.textContent=(to*e).toFixed(dec);if(p<1)raf(step);else el.textContent=Number(to).toFixed(dec)})()};
W.empty=(icon,title,text,btns)=>h("div",{class:"empty"},h("div",{class:"big"},ic(icon,38)),h("h4",null,title),h("div",null,text),btns?h("div",{class:"btns"},btns):null);

/* classical dial: 60 tick marks, gold progress arc, grade medallion */
W.dial=function(score,grade,col){const R=78,C=2*Math.PI*R;col=col||(score>=80?"var(--ok)":score>=55?"var(--warn)":"var(--bad)");
 const svg=sv("svg",{viewBox:"0 0 220 220"});
 for(let i=0;i<60;i++){const a=(i/60)*2*Math.PI,l=i%5===0?9:4,r1=102,r2=r1-l;
  svg.append(sv("line",{x1:110+Math.sin(a)*r1,y1:110-Math.cos(a)*r1,x2:110+Math.sin(a)*r2,y2:110-Math.cos(a)*r2,stroke:i%5===0?"var(--gold)":"rgba(201,164,92,.35)","stroke-width":i%5===0?1.6:1}))}
 svg.append(sv("circle",{cx:110,cy:110,r:R,fill:"none",stroke:"rgba(255,255,255,.07)","stroke-width":10}));
 const prog=sv("circle",{cx:110,cy:110,r:R,fill:"none","stroke-width":10,"stroke-linecap":"butt",stroke:col,"stroke-dasharray":C,"stroke-dashoffset":C,transform:"rotate(-90 110 110)",class:"dprog",style:"color:"+col});
 svg.append(prog);setTimeout(()=>prog.setAttribute("stroke-dashoffset",C*(1-score/100)),90);
 const num=h("b",null,"0");W.countUp(num,score);
 return h("div",{class:"dial"},svg,h("div",{class:"dmid"},num,h("span",null,"Posture score")),h("div",{class:"grade",style:"background:"+col},grade))};
W.donut=function(parts,total){const R=56,C=2*Math.PI*R;let acc=0;const svg=sv("svg",{viewBox:"0 0 150 150"},sv("circle",{cx:75,cy:75,r:R,fill:"none",stroke:"rgba(255,255,255,.06)","stroke-width":16}));
 parts.forEach(p=>{if(!p.v)return;const len=C*p.v/Math.max(total,1);svg.append(sv("circle",{cx:75,cy:75,r:R,fill:"none",stroke:p.c,"stroke-width":16,"stroke-dasharray":Math.max(0,len-2)+" "+(C-len+2),"stroke-dashoffset":-acc,transform:"rotate(-90 75 75)"}));acc+=len});
 svg.append(sv("text",{x:75,y:80,"text-anchor":"middle","font-size":32,"font-weight":600,fill:"var(--ivory)","font-family":"Georgia,serif"},String(total)),
  sv("text",{x:75,y:97,"text-anchor":"middle","font-size":8,fill:"var(--mut)","letter-spacing":"2"},"NETWORKS"));return svg};
W.kpi=(label,val,sub,color)=>h("div",{class:"kpi",style:color?"--c:"+color:""},h("small",null,label),h("b",null,val),sub?h("span",null,sub):null);
W.card=(title,iconName,cls,n)=>h("div",{class:"card "+(cls||""),style:"--n:"+(n||0)},title?h("h3",null,iconName?ic(iconName):null,title):null);
W.sevpill=s=>h("span",{class:"sev",style:"--c:"+(W.SEV[s]||W.SEV.info)},s);

/* ---------- layer: modal + drawer ---------- */
W.closeLayer=()=>{$("#layer").replaceChildren()};
W.modal=function(content,locked){$("#layer").replaceChildren(h("div",{class:"ov",onclick:()=>{if(!(locked&&locked()))W.closeLayer()}}),content);return content};
})(WA);
