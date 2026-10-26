/* Main: chrome (sidebar/header), router, scan flow, live monitor, first-run tour */
(function(W){
"use strict";
const h=W.h,ic=W.ic,S=W.S,$=W.$;
const RAW=b=>b==="scapy"||b==="airodump";
const BACK={auto:{n:"Auto (recommended)",d:"Picks the best method available on this machine",i:"radar"},
 deep:{n:"Deep scan",d:"Full detail incl. WPS and forged-disconnect protection. No monitor mode needed",i:"zap"},
 system:{n:"Basic OS scan",d:"Uses the operating system's own list: encryption and signal only",i:"wifi"},
 scapy:{n:"Monitor mode (Scapy)",d:"Raw beacon capture on a monitor-mode adapter (Linux, root)",i:"cpu"},
 airodump:{n:"airodump-ng",d:"aircrack-ng tooling, plus wash for WPS (Linux, root)",i:"cpu"}};

/* ------------------------------------------------------------------ setup checklist */
W.setupList=function(caps){const rows=["auto","deep","system","scapy","airodump"].map(k=>{const c=caps[k];return h("div",null,h("span",{class:"dot"+(c.available?"":" off")}),h("div",null,h("b",null,BACK[k].n+(c.available?"":" - not ready")),h("small",null,c.reason+(!c.available&&c.hint?"  →  "+c.hint:""))))});
 if(caps.adapters)rows.push(h("div",null,h("span",{class:"dot"+(caps.adapters.length?"":" off")}),h("div",null,h("b",null,"Wi-Fi adapters"),h("small",null,caps.adapters.length?caps.adapters.map(a=>a.name+(a.mode?" ("+a.mode+")":"")).join(", "):"None detected"))));
 return h("div",{class:"setup"},rows)};

/* ------------------------------------------------------------------ chrome */
const NAV=[["overview","I","Overview","grid"],["networks","II","Networks","wifi"],["threats","III","Threats","shield"],["tools","IV","Toolbox","tool"],["history","V","History","clock"],["learn","VI","Learn","book"]];
let live=null;
function drawChrome(){const cur=S.view==="tool"?"tools":S.view,thr=W.nets().filter(n=>n.rogue||n.display_level==="HIGH RISK").length;
 $("#side").replaceChildren(
  h("div",{class:"brand"},h("div",{class:"emblem"},ic("radar",30)),h("b",null,"WI-FI AUDITOR"),h("small",null,"Wireless & network sentinel")),
  ...NAV.map(([k,rn,l])=>{const cnt=k==="networks"?W.nets().length:k==="threats"?thr:k==="history"?S.scans.length:0;
   return h("a",{class:"nav"+(cur===k?" on":""),href:"#"+k},h("span",{class:"rn"},rn),l,cnt?h("span",{class:"cnt"+(k==="threats"&&S.cur&&S.cur.summary.rogue?" hot":"")},cnt):null)}),
  h("div",{class:"sfoot"},h("b",null,h("span",{class:"dot"+(S.caps&&S.caps.root?"":" off")}),S.caps&&S.caps.root?"Privileged mode":"Standard mode"),
   S.caps&&S.caps.root?"Fresh kernel scans and monitor mode available.":"Passive scanning. On Linux, sudo adds monitor mode.",h("i",null,"“Know thy airwaves.”")));
 let t=W.TITLES[S.view]||W.TITLES.tools,title=t[1],sub=t[2],rn=t[0];
 if(S.view==="tool"){const d=W.toolDef(S.arg);if(d){title=d.n;sub=d.d}}
 const d=S.cur&&S.cur.meta,subEls=[sub];
 if(d&&(S.view==="overview"||S.view==="networks")){subEls.push(h("span",{class:"mono"},"· scan "+d.id+" · "+W.ago(d.ts)),d.backend==="demo"?h("span",{class:"badge warn"},"SAMPLE DATA"):h("span",{class:"badge ac"},"via "+d.backend))}
 const exp=h("div",{style:"position:relative"});
 const expBtn=h("button",{class:"btn",onclick:e=>{e.stopPropagation();const m=$(".menu",exp);if(m){m.remove();return}
   exp.append(h("div",{class:"menu"},...["html","pdf","json","csv"].map(f=>h("a",{href:"/api/report/"+d.id+"/"+f},ic("download",16),"Report ."+f))))}},ic("download"),"Export",ic("chev",14));
 if(!d)expBtn.disabled=true;exp.append(expBtn);
 $("#top").replaceChildren(h("div",{class:"ttl"},h("div",{class:"kicker"},"Chapter "+rn),h("h2",null,title),h("div",{class:"sub"},subEls)),
  h("div",{class:"actions"},h("button",{class:"btn icon",title:"Quick tour",onclick:()=>W.tour(0)},ic("help")),exp,
   h("button",{class:"btn"+(live?" on":""),title:"Rescan every 60 s and alert on new impostors / open networks",onclick:toggleLive},live?h("span",{class:"live-dot"}):ic("activity"),live?"Live":"Monitor"),
   h("button",{class:"btn icon",title:"Scan options",onclick:openScan},ic("sliders")),
   h("button",{class:"btn pri",onclick:()=>W.quickScan(S.lastBackend||"auto")},ic("radar"),"Scan now")))}
document.addEventListener("click",()=>{const m=$(".menu");if(m)m.remove()});

function render(){drawChrome();const v=$("#view");const f=W.views[S.view]||W.views.overview;v.replaceChildren(W.orn(),f());window.scrollTo(0,0)}
W.render=render;
function route(){W.runLeave();const hs=(location.hash||"#overview").slice(1),i=hs.indexOf("/"),v=i<0?hs:hs.slice(0,i);S.view=W.views[v]?v:"overview";S.arg=i<0?"":hs.slice(i+1);render()}

/* ------------------------------------------------------------------ scan flow */
function radar(){return h("div",{class:"radar"},h("div",{class:"sweep"}),h("i",{class:"ring r1"}),h("i",{class:"ring r2"}),h("i",{class:"ring r3"}),...[0,1,2,3,4,5].map(i=>h("b",{class:"blip",style:"left:"+(18+Math.random()*64)+"%;top:"+(18+Math.random()*64)+"%;animation-delay:"+(i*.4)+"s"})))}
async function runScan(box,opts,done,back){
 const bar=h("i"),pr=h("div",{class:"prog"+(RAW(opts.backend)?"":" ind")},bar),st=h("div",{style:"color:var(--mut);font-size:13px"},"Starting…");
 box.replaceChildren(h("div",{class:"scanning"},radar(),h("h3",{style:"text-align:center"},"Listening to the airwaves…"),pr,st));
 const msgs=["Listening for beacon signals…","Reading encryption settings…","Checking WPS exposure…","Hunting for impostor networks…","Grading each network…"];let mi=0;
 const tick=setInterval(()=>{st.textContent=msgs[mi++%msgs.length]},1400),t0=Date.now();
 try{const {job}=await W.post("/api/scan",opts);
  for(;;){await W.sleep(900);if(RAW(opts.backend))bar.style.width=Math.min(97,100*(Date.now()-t0)/1000/opts.duration)+"%";
   const j=await W.api("/api/jobs/"+job);
   if(j.state==="done"){clearInterval(tick);done();W.closeLayer();await W.loadScan(j.scan_id,"overview");const s=S.cur.summary;W.toast("Scan complete - "+s.total+" networks"+(s.rogue?" · "+s.rogue+" IMPOSTOR":""),s.rogue?"err":"ok");maybeTour();return}
   if(j.state!=="running"){const er=new Error(j.error||"Scan failed");er.hint=j.hint;throw er}}}
 catch(e){clearInterval(tick);done();let caps=S.caps;try{caps=await W.api("/api/capabilities");S.caps=caps}catch(_){}
  box.replaceChildren(h("h3",null,"The scan did not run"),h("p",{class:"lead"},e.message),e.hint?h("div",{class:"hintbox"},"How to fix: ",e.hint):null,
   caps?h("div",null,h("div",{class:"lbl"},"This machine"),W.setupList(caps)):null,
   h("div",{class:"mf"},h("button",{class:"btn ghost",onclick:W.closeLayer},"Close"),h("button",{class:"btn",onclick:()=>W.quickScan(opts.backend)},"Try again"),h("button",{class:"btn pri",onclick:back},"Scan options")))}}
W.quickScan=async function(b){S.lastBackend=b;const box=h("div",{class:"modal"});W.modal(box,()=>true);
 await runScan(box,{backend:b,duration:RAW(b)?30:20,iface:RAW(b)?(S.caps&&S.caps.monitor_iface)||"":"",label:""},()=>{},openScan)};
async function openScan(){
 const caps=S.caps||await W.api("/api/capabilities");S.caps=caps;let ifs=[];try{ifs=await W.api("/api/interfaces")}catch(e){}
 let sel=S.lastBackend&&caps[S.lastBackend]&&caps[S.lastBackend].available?S.lastBackend:(caps.auto.available?"auto":["deep","system","scapy","airodump"].find(k=>caps[k].available)||"auto"),
  busy=false,iface=caps.monitor_iface||(ifs.find(i=>i.mode==="monitor")||{}).name||"",dur=30,label="";
 const box=h("div",{class:"modal"});W.modal(box,()=>busy);
 function paint(){const c=caps[sel];
  const opts=["auto","deep","system","scapy","airodump"].map(b=>{const cb=caps[b],ok=cb.available;return h("button",{class:"opt"+(sel===b?" on":""),disabled:!ok,onclick:()=>{sel=b;paint()},title:cb.hint||""},
   h("b",null,ic(BACK[b].i,18),BACK[b].n),h("span",null,BACK[b].d),h("em",{style:"color:"+(ok?"var(--ok)":"var(--warn)")},ok?"● Ready":"○ "+cb.reason))});
  const li=h("input",{class:"in",placeholder:"e.g. wlan0mon",list:"ifl",value:iface});li.addEventListener("input",()=>iface=li.value.trim());
  const rg=h("input",{type:"range",min:10,max:120,step:5,value:dur}),rl=h("b",null,dur+"s");rg.addEventListener("input",()=>{dur=+rg.value;rl.textContent=dur+"s"});
  const lb=h("input",{class:"in",placeholder:"e.g. Office floor 2",value:label});lb.addEventListener("input",()=>label=lb.value);
  const hints=["scapy","airodump","deep"].filter(b=>!caps[b].available&&caps[b].hint).map(b=>caps[b].hint).filter((v,i,a)=>a.indexOf(v)===i);
  box.replaceChildren(h("h3",null,"Choose how to scan"),h("p",{class:"lead"},"Passive only: the scanner listens to broadcasts and never attacks or injects anything. If unsure, keep Auto."),h("div",{class:"opts"},opts),
   RAW(sel)?h("div",null,h("div",{class:"field"},h("label",null,"Monitor-mode interface"),li,h("datalist",{id:"ifl"},ifs.map(i=>h("option",{value:i.name},i.mode)))),h("div",{class:"field"},h("label",null,"Capture time  ",rl),rg)):null,
   h("div",{class:"field"},h("label",null,"Label (optional)"),lb),
   hints.length?h("div",{class:"hintbox"},"To unlock more methods: ",...hints.map((x,i)=>[i?" · ":"",h("code",null,x)])):null,
   h("div",{class:"mf"},h("button",{class:"btn ghost sm",style:"margin-right:auto",title:"Fake networks, for trying the interface only",onclick:()=>{busy=true;S.lastBackend=null;runScan(box,{backend:"demo",duration:5,label:"Sample data"},()=>{busy=false},paint)}},"Use sample data"),
    h("button",{class:"btn ghost",onclick:W.closeLayer},"Cancel"),h("button",{class:"btn pri",disabled:!c.available||(RAW(sel)&&!iface),onclick:go},ic("radar",18),"Start scan")))}
 async function go(){busy=true;S.lastBackend=sel;await runScan(box,{backend:sel,iface,duration:dur,label},()=>{busy=false},paint)}
 paint()}

/* ------------------------------------------------------------------ live monitor */
function toggleLive(){if(live){clearInterval(live.t);live=null;W.toast("Live monitor stopped");drawChrome();return}
 try{if("Notification" in window&&Notification.permission==="default")Notification.requestPermission()}catch(e){}
 live={t:setInterval(liveTick,60000),busy:false};W.toast("Live monitor on: rescanning every 60 s","ok");drawChrome();liveTick()}
function notify(msg){W.toast(msg,"err");try{if("Notification" in window&&Notification.permission==="granted")new Notification("Wi-Fi Auditor",{body:msg})}catch(e){}}
async function liveTick(){if(!live||live.busy||$(".modal"))return;live.busy=true;
 try{const b=S.lastBackend||"auto",{job}=await W.post("/api/scan",{backend:b,duration:15,iface:RAW(b)?(S.caps&&S.caps.monitor_iface)||"":"",label:"live"});
  for(;;){await W.sleep(1200);const j=await W.api("/api/jobs/"+job);
   if(j.state==="done"){const before=new Set(W.nets().filter(n=>n.rogue).map(n=>n.bssid+"|"+n.ssid));
    const d=await W.api("/api/scans/"+j.scan_id);S.cur=d;S.scans=await W.api("/api/scans");render();
    const lines=[];
    d.networks.filter(n=>n.rogue&&!before.has(n.bssid+"|"+n.ssid)).forEach(n=>{notify("IMPOSTOR: "+n.name+" ("+n.bssid+")");lines.push("Impostor network: "+n.name+" ("+n.bssid+")")});
    if(d.diff){d.diff.new.filter(n=>!n.rogue&&n.encryption==="OPEN").forEach(n=>{notify("New OPEN network: "+n.name);lines.push("New open network: "+n.name)});
     d.diff.changed.filter(c=>c.field==="encryption").forEach(c=>{notify(c.ssid+": encryption "+c.old+" → "+c.new);lines.push(c.ssid+": encryption "+c.old+" → "+c.new)})}
    if(lines.length)W.post("/api/alerts/notify",{title:"Wi-Fi Auditor: "+lines.length+" alert(s)",lines}).catch(()=>{});
    break}
   if(j.state!=="running")throw new Error(j.error||"scan failed")}}
 catch(e){W.toast("Live scan: "+e.message,"warn")}finally{if(live)live.busy=false}}

/* ------------------------------------------------------------------ first-run tour */
const STEPS=[["I","Welcome","Wi-Fi Auditor listens to the wireless networks around you and to your own network, then explains in plain English how safe everything is. It never attacks anything."],
 ["II","Scan","Press the gold Scan now button. Your computer listens to nearby routers for a few seconds. Nothing is sent to anyone."],
 ["III","Read the dial","The dial grades your surroundings from A to F. Green is healthy, amber needs hardening, red or pink needs action. 'What to do first' tells you the next steps."],
 ["IV","Dig deeper","Click any network for a plain report. Underlined words explain themselves when you hover over them. Threats shows suspected impostor networks."],
 ["V","Check your own network","The Toolbox finds who is on your network, which ports are open, whether DNS or HTTPS is being tampered with and more. Learn explains every term."]];
W.tour=function(i){const s=STEPS[i];const box=h("div",{class:"modal tour"},h("div",{class:"big"},s[0]),h("h3",null,s[1]),h("p",{class:"lead"},s[2]),
  h("div",{class:"dots"},STEPS.map((_,k)=>h("i",{class:k===i?"on":""}))),
  h("div",{class:"mf",style:"justify-content:center"},h("button",{class:"btn ghost",onclick:()=>{W.store.set("wa-tour","1");W.closeLayer()}},"Skip"),
   i>0?h("button",{class:"btn",onclick:()=>W.tour(i-1)},"Back"):null,
   h("button",{class:"btn pri",onclick:()=>{if(i<STEPS.length-1)W.tour(i+1);else{W.store.set("wa-tour","1");W.closeLayer()}}},i<STEPS.length-1?"Next":"Begin")));W.modal(box)};
function maybeTour(){if(!W.store.get("wa-tour")){W.store.set("wa-tour","1");setTimeout(()=>W.tour(0),600)}}

/* ------------------------------------------------------------------ data flow */
W.loadScan=async function(id,view){const d=await W.api("/api/scans/"+(id||"latest"));S.cur=d.meta?d:null;await W.refresh(false);if(view&&location.hash!=="#"+view){location.hash=view}else render()};
W.refresh=async function(reload){S.scans=await W.api("/api/scans");if(reload){const d=await W.api("/api/scans/latest");S.cur=d.meta?d:null}render()};
window.addEventListener("hashchange",route);
document.addEventListener("keydown",e=>{if(e.key==="Escape")W.closeLayer();
 if(/INPUT|TEXTAREA|SELECT/.test((e.target.tagName||"")))return;
 if(e.key==="/"){e.preventDefault();location.hash="networks";setTimeout(()=>{const q=$("#q");if(q)q.focus()},40)}
 if(e.key==="n")openScan();if(e.key==="?")W.tour(0)});

(async function init(){
 $("#view").replaceChildren(h("div",{class:"grid"},h("div",{class:"skel c7"}),h("div",{class:"skel c5"}),h("div",{class:"skel c7"}),h("div",{class:"skel c5"})));
 try{[S.caps,S.scans]=await Promise.all([W.api("/api/capabilities"),W.api("/api/scans")]);const d=await W.api("/api/scans/latest");S.cur=d.meta?d:null}
 catch(e){W.toast("Cannot reach the auditor backend: "+e.message,"err")}
 route();
 if(!S.cur&&S.caps&&S.caps.auto.available)W.quickScan("auto");else if(S.cur)maybeTour()})();
})(WA);
