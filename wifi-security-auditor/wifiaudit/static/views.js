/* Views: Overview, Networks, Threats, History, Learn + the network drawer */
(function(W){
"use strict";
const h=W.h,sv=W.sv,ic=W.ic,T=W.T,S=W.S,$=W.$;

/* ------------------------------------------------------------------ plain-English helpers */
function plainSummary(n){
 if(n.connected&&n.rogue)return "You are connected to what looks like a fake copy of a real network. Disconnect now and avoid logging in to anything.";
 if(n.rogue)return "This looks like an impostor: "+(n.rogue_reasons[0]||"it behaves like a rogue access point")+".";
 if(n.encryption==="OPEN")return "Anyone nearby can read what you send over this network. Treat it as public.";
 if(n.encryption==="WEP")return "This network's protection was broken years ago and can be cracked in minutes.";
 if(n.encryption==="WPA")return "This network uses outdated protection (WPA version 1). It works, but it is weak.";
 if(n.wps&&!n.wps_locked)return "The password may be strong, but WPS offers a shortcut around it. Turning WPS off fixes this.";
 if(n.level==="SECURE")return "Configured well - no known weaknesses found.";
 return "Usable, but a few settings could be stronger.";
}
function verdict(s,list){
 const o={head:"",lines:[],todo:[]};
 o.head=s.rogue?"Something nearby may be impersonating a network":s.high_risk?"Some networks around you are unsafe":s.vulnerable?"Mostly fine - a few networks can be hardened":"Your wireless surroundings look healthy";
 const L=(t,c)=>o.lines.push({t,c});
 L(s.secure+" of "+s.total+" networks use modern, well-configured security.","var(--ok)");
 if(s.rogue)L(s.rogue+" access point"+(s.rogue>1?"s look":" looks")+" like impostors of real networks.","var(--rog)");
 if(s.open)L(s.open+" network"+(s.open>1?"s have":" has")+" no encryption at all.","var(--bad)");
 if(s.wps_enabled)L(s.wps_enabled+" "+(s.wps_enabled>1?"routers have":"router has")+" WPS switched on (a known weak spot).","var(--warn)");
 const T_=(sev,t,d,go)=>o.todo.push({sev,t,d,go});
 const rogues=list.filter(n=>n.rogue);
 if(rogues.length)T_("critical","Find the suspected rogue access point"+(rogues.length>1?"s":""),"Check: "+rogues.slice(0,3).map(n=>n.name+" ("+n.bssid+")").join(", ")+". If one is yours, mark it as trusted; if not, locate and remove it.","#threats");
 const mine=list.find(n=>n.connected);
 if(mine&&!mine.rogue&&mine.level!=="SECURE"){const f=mine.findings.find(x=>x.sev!=="info");T_("high","Your own connection ("+mine.name+") has weaknesses",f?f.title+" - "+f.fix:"Review its report.","drawer:"+mine.bssid)}
 s.top_fixes.slice(0,4).forEach(f=>{if(o.todo.length<4)T_(/WPS|Open|WEP/.test(f.title)?"high":"medium",f.title+(f.count>1?" ("+f.count+" networks)":""),f.fix,"#networks")});
 return o;
}
W.plainSummary=plainSummary;

async function openRemediation(){const findings=W.nets().flatMap(n=>n.findings.filter(f=>f.sev!=="info"));
 const box=h("div",{class:"modal"});W.modal(box);box.replaceChildren(h("h3",null,"Preparing your fix plan…"),h("div",{style:"text-align:center;padding:20px"},h("span",{class:"spin"})));
 try{const r=await W.post("/api/remediate",{findings});
  const txt=r.plan.map((it,i)=>(i+1)+". ["+it.sev.toUpperCase()+"] "+it.heading+"\n"+it.steps.map(s=>"   - "+s).join("\n")).join("\n\n");
  box.replaceChildren(h("h3",null,"Your fix plan"),h("p",{class:"lead"},r.plan.length+" item"+(r.plan.length===1?"":"s")+", most important first."),
   r.plan.length?h("div",null,r.plan.map((it,i)=>h("div",{class:"find",style:"--c:"+W.SEV[it.sev]},h("h5",null,h("span",{style:"color:var(--gold);font-family:Georgia,serif;margin-right:8px"},i+1+"."),W.sevpill(it.sev),it.heading),h("dl",null,h("dt",null,"Steps"),h("dd",null,it.steps.map(s=>h("div",{style:"margin-bottom:3px"},"◆ "+s))))))):h("div",{class:"find",style:"--c:"+W.SEV.ok},h("h5",null,"Nothing to fix right now")),
   h("div",{class:"mf"},h("button",{class:"btn",onclick:()=>{navigator.clipboard&&navigator.clipboard.writeText(txt).then(()=>W.toast("Plan copied","ok"))}},ic("copy",16),"Copy as text"),h("button",{class:"btn pri",onclick:W.closeLayer},"Done")))}
 catch(e){box.replaceChildren(h("h3",null,"Could not build the plan"),h("p",{class:"lead"},e.message),h("div",{class:"mf"},h("button",{class:"btn pri",onclick:W.closeLayer},"Close")))}}

/* ------------------------------------------------------------------ drawer */
W.openDrawer=function(n){const lv=W.LV[n.display_level],layer=$("#layer");layer.replaceChildren();
 const kv=(k,v)=>h("div",null,h("small",null,k),h("b",null,v||"-"));
 const hist=h("b",null,"…");
 const mini=(()=>{const R=34,C=2*Math.PI*R,p=sv("circle",{cx:42,cy:42,r:R,fill:"none",stroke:lv[1],"stroke-width":6,"stroke-dasharray":C,"stroke-dashoffset":C,transform:"rotate(-90 42 42)",class:"dprog",style:"color:"+lv[1]});
  setTimeout(()=>p.setAttribute("stroke-dashoffset",C*(1-n.score/100)),60);
  return h("div",{style:"position:relative;width:84px;height:84px;flex:none"},sv("svg",{viewBox:"0 0 84 84"},sv("circle",{cx:42,cy:42,r:R,fill:"none",stroke:"rgba(255,255,255,.08)","stroke-width":6}),p),h("div",{style:"position:absolute;inset:0;display:grid;place-items:center;font:600 26px Georgia,serif"},n.score))})();
 const dr=h("div",{class:"drawer"},
  h("div",{class:"dh"},mini,h("div",{style:"flex:1;min-width:0"},h("h3",null,n.name),W.pill(n.display_level),n.connected?h("span",{class:"badge ac",style:"margin-left:8px"},"YOU ARE CONNECTED"):null),h("button",{class:"btn icon",onclick:W.closeLayer},ic("x"))),
  h("div",{class:"plain"},W.plainSummary(n)),
  h("div",{class:"kv"},kv("Hardware address",n.bssid),kv("Made by",n.vendor||"Unknown"),kv("Channel / band",(n.channel||"-")+(n.band?" · "+n.band:"")),kv("Signal",n.signal==null?"n/a":n.signal+" dBm"),
   kv("Encryption",n.encryption),kv("Cipher / login",[n.cipher,n.auth].filter(Boolean).join(" · ")),kv("WPS",n.wps==null?"Unknown":n.wps?(n.wps_locked?"On (locked)":"On"):"Off"),kv("Forged-disconnect protection",n.pmf||"Unknown"),
   h("div",null,h("small",null,"Seen in scans"),hist),kv("Visibility",(n.hidden?"Hidden name":"Name broadcast")))
 );
 if(n.rogue_reasons.length)dr.append(h("div",{class:"find",style:"--c:"+W.SEV.critical},h("h5",null,W.sevpill("critical"),"Why this looks like an impostor"),h("dl",null,h("dt",null,"Evidence"),h("dd",null,...n.rogue_reasons.map(r=>h("div",null,"◆ "+r))),h("dt",null,"Score"),h("dd",null,n.rogue_score+" / 100 (60 or more = rogue)"))));
 n.findings.forEach(f=>dr.append(h("div",{class:"find",style:"--c:"+(W.SEV[f.sev]||W.SEV.info)},h("h5",null,W.sevpill(f.sev),f.title),h("dl",null,h("dt",null,"Why it matters"),h("dd",null,f.detail),f.fix?[h("dt",null,"How to fix"),h("dd",null,f.fix)]:null))));
 if(!n.findings.length)dr.append(h("div",{class:"find",style:"--c:"+W.SEV.ok},h("h5",null,W.sevpill("ok"),"Nothing to fix")));
 dr.append(h("div",{class:"mf",style:"justify-content:flex-start"},
  h("button",{class:"btn",onclick:()=>{(navigator.clipboard?navigator.clipboard.writeText(n.bssid):Promise.reject()).then(()=>W.toast("Address copied","ok"),()=>W.toast("Copy not available","warn"))}},ic("copy",16),"Copy address"),
  n.ssid?h("button",{class:"btn",title:"Tell the auditor this access point is yours",onclick:async()=>{try{await W.post("/api/trust",{ssid:n.ssid,bssid:n.bssid});W.toast("Marked as yours - re-analysed","ok");W.closeLayer();await W.loadScan(S.cur.meta.id)}catch(e){W.toast(e.message,"err")}}},ic("check",16),"This one is mine"):null));
 layer.append(h("div",{class:"ov",onclick:W.closeLayer}),dr);
 W.api("/api/bssid/"+n.bssid).then(r=>{hist.textContent=r.length+(r.length===1?" scan":" scans")}).catch(()=>{hist.textContent="-"})};

/* ------------------------------------------------------------------ overview */
function vOverview(){const d=S.cur;
 if(!d||!d.meta){const e=W.empty("radar","Ready when you are","Press Scan now to see the Wi-Fi networks around you, how safe each one is, and whether anything looks fake.",[h("button",{class:"btn pri",onclick:()=>W.quickScan("auto")},ic("radar"),"Scan my Wi-Fi")]);
  if(S.caps&&!S.caps.auto.available)e.append(h("div",{class:"hintbox"},"This machine is not ready to scan yet:"),W.setupList(S.caps));return e}
 const s=d.summary,list=W.nets(),prev=S.scans.find(x=>x.id<d.meta.id),root=h("div");let n=0;const N=()=>"--n:"+(n++);
 const v=verdict(s,list);
 root.append(W.explain("In plain English","Your computer listened to every Wi-Fi network in range, graded each one, and looked for fakes. The dial gives the overall result; the list below tells you what to do first."));
 if(s.rogue)root.append(h("div",{class:"alert"},h("div",{class:"ic"},ic("alert",20)),h("div",null,h("b",null,s.rogue+" suspected "+(s.rogue>1?"impostors":"impostor")),h("span",null,"These look like fake copies of real networks. Review them now.")),h("button",{class:"btn sm danger",onclick:()=>{location.hash="threats"}},"Investigate")));
 root.append(h("div",{class:"card",style:"--n:"+(n++)+";margin-bottom:0;display:flex;align-items:center;gap:16px;flex-wrap:wrap"},
  h("div",{style:"flex:1;min-width:220px"},h("h4",null,"Need a step-by-step fix plan?"),h("p",{class:"cap",style:"margin:4px 0 0"},"Turns every finding across all your networks into plain, numbered router-settings instructions.")),
  h("button",{class:"btn pri",onclick:openRemediation},ic("list"),"Get a fix plan")));
 if(s.connected){const cn=list.find(x=>x.connected);root.append(h("div",{class:"conn",onclick:()=>cn&&W.openDrawer(cn)},h("div",{class:"ic"},ic("wifi",20)),h("div",null,h("b",null,"You are connected to "+s.connected.name),h("span",null,s.connected.encryption+" · score "+s.connected.score+" · "+s.connected.bssid)),W.pill(s.connected.level)))}
 const g=h("div",{class:"grid"});
 const vc=W.card("The verdict","shield","c7",N());
 vc.append(h("div",{class:"verdict"},W.dial(s.posture,s.grade),h("div",{style:"flex:1;min-width:240px"},h("h4",null,v.head),h("ul",null,v.lines.map(l=>h("li",{style:"--c:"+l.c},l.t))),
  h("div",{class:"cap"},"Grade "+s.grade+" = "+({A:"excellent",B:"good",C:"fair",D:"poor",F:"needs attention"}[s.grade]) ))));
 g.append(vc);
 const tiles=h("div",{class:"c5",style:"display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px"});
 const tile=(k,label,val,icon,col,good,tip)=>{const num=h("b",null,"0");W.countUp(num,val);let dl="First scan";
  if(prev){const df=val-prev[k];dl=df===0?"No change since scan #"+prev.id:h("span",{class:(df>0)===good?"up":"dn"},(df>0?"▲ +":"▼ ")+df+" since #"+prev.id)}
  return h("div",{class:"card stat",style:N()+";--c:"+col},h("div",{class:"ic"},ic(icon,22)),h("small",null,label,W.info(tip)),num,h("div",{class:"dl"},dl))};
 tiles.append(tile("total","Networks heard",s.total,"wifi","var(--ivory)",true,"Every Wi-Fi network your device could hear in this scan."),
  tile("secure","Secure",s.secure,"lock","var(--ok)",true,"Modern encryption and no known weaknesses."),
  tile("vulnerable","Vulnerable",s.vulnerable,"unlock","var(--warn)",false,"Weak or outdated settings (includes high-risk). Rogue networks are counted separately."),
  tile("rogue","Impostors",s.rogue,"alert","var(--rog)",false,"Access points that look like fake copies of real networks."));
 g.append(tiles);
 const td=W.card("What to do first","list","c7",N());
 td.append(v.todo.length?h("div",{class:"todo"},v.todo.map((t,i)=>h("div",{class:"todo-i",style:"--c:"+W.SEV[t.sev],onclick:()=>{if(t.go.startsWith("drawer:")){const x=list.find(q=>q.bssid===t.go.slice(7));x&&W.openDrawer(x)}else location.hash=t.go.slice(1)}},h("div",{class:"n"},i+1),h("div",null,h("b",null,t.t),h("span",null,t.d))))):h("div",{class:"cap"},"Nothing urgent. Keep an eye on things with Live Monitor."));
 g.append(td);
 const parts=[{l:"Secure",v:s.secure,c:"#6fbf9a"},{l:"Vulnerable",v:s.vulnerable-s.high_risk,c:"#e3b04b"},{l:"High risk",v:s.high_risk,c:"#e2574c"},{l:"Impostor",v:s.rogue,c:"#ff4d7d"}];
 const dc=W.card("Risk distribution","grid","c5",N());
 dc.append(h("div",{class:"donut"},W.donut(parts,s.total),h("div",{class:"legend"},parts.map(p=>h("div",null,h("i",{style:"background:"+p.c}),p.l,h("b",null,p.v))))),h("div",{class:"cap"},"How the networks around you split by safety."));
 g.append(dc);
 const enc=Object.entries(s.by_encryption).sort((a,b)=>b[1]-a[1]),mx=Math.max(1,...enc.map(e=>e[1]));
 const ec=e=>/OPEN|WEP/.test(e)?"#e2574c":e==="WPA"||e==="WPA/WPA2"?"#e3b04b":/WPA3|Enterprise/.test(e)?"#6fbf9a":"#c9a45c";
 const bars=h("div");enc.forEach(([e,c])=>{const i=h("i",{style:"background:"+ec(e)});bars.append(h("div",{class:"hb"},h("span",null,e),h("div",{class:"tr"},i),h("b",null,c)));setTimeout(()=>{i.style.width=(100*c/mx)+"%"},120)});
 const ecard=W.card("Encryption mix","lock","c4",N());ecard.append(bars,h("div",{class:"cap"},"Green = modern, gold = fine, amber = old, red = unsafe. Learn more about ",T("wpa","encryption"),"."));g.append(ecard);
 const sp=h("div",{class:"spec"}),chs=s.channels,mc=Math.max(1,...Object.values(chs));
 for(let c=1;c<=13;c++){const val=chs[c]||0,i=h("i");sp.append(h("div",{class:(c===s.recommended_channel?"rec ":"")+(val?"":"empty")},val||"",i,c));setTimeout(()=>{i.style.height=(val?Math.max(12,100*val/mc):4)+"%"},120)}
 const hi=Object.keys(chs).filter(c=>c>14);
 const sc=W.card("Radio spectrum (2.4 GHz)","activity","c8",N());
 sc.append(sp,h("div",{class:"cap"},"Taller bar = more networks on that ",T("channel","channel"),". Best lane for your router: ",h("b",{style:"color:var(--ok);font-style:normal"},"channel "+s.recommended_channel),hi.length?" · 5 GHz channels in use: "+hi.join(", "):"."));g.append(sc);
 const df=d.diff,dcard=W.card("Changes since last scan","refresh","c12",N()),dc2=h("div");
 if(df&&(df.new.length||df.gone.length||df.changed.length)){df.new.forEach(x=>dc2.append(h("div",{style:"margin-bottom:8px"},h("span",{class:"badge ok"},"NEW")," ",x.name," ",W.pill(x.display_level))));df.gone.forEach(x=>dc2.append(h("div",{style:"margin-bottom:8px"},h("span",{class:"badge"},"GONE")," ",x.name)));
  df.changed.forEach(c=>dc2.append(h("div",{style:"margin-bottom:8px"},h("span",{class:"badge warn"},"CHANGED")," ",c.ssid+": "+c.field+" "+c.old+" → "+c.new)))}else dc2.append(h("span",{class:"cap",style:"margin:0"},prev?"Nothing changed since scan #"+prev.id+".":"This is your first scan - run another later to see what changes."));
 dcard.append(dc2);g.append(dcard);root.append(g);return root}

/* ------------------------------------------------------------------ networks */
function filtered(){const q=S.q.trim().toLowerCase();let l=W.nets().filter(n=>{const f=S.filter;
 if(f==="secure"&&!(n.level==="SECURE"&&!n.rogue))return false;if(f==="vulnerable"&&(n.rogue||n.level==="SECURE"))return false;if(f==="high"&&n.display_level!=="HIGH RISK")return false;
 if(f==="rogue"&&!n.rogue)return false;if(f==="wps"&&!n.wps)return false;if(f==="open"&&n.encryption!=="OPEN")return false;
 return !q||[n.name,n.bssid,n.vendor,n.encryption].join(" ").toLowerCase().includes(q)});
 const K={risk:n=>[n.rogue?0:1,n.score],name:n=>n.name.toLowerCase(),channel:n=>n.channel,signal:n=>n.signal==null?-999:n.signal,encryption:n=>n.encryption,wps:n=>n.wps==null?-1:+n.wps,score:n=>n.score,level:n=>n.display_level}[S.sortK];
 return l.sort((a,b)=>{const x=K(a),y=K(b);const c=Array.isArray(x)?(x[0]-y[0]||x[1]-y[1]):(x>y?1:x<y?-1:0);return c*S.sortD})}
function vNetworks(){const all=W.nets();if(!all.length)return W.empty("wifi","No networks yet","Run a scan to see what is on the air.",[h("button",{class:"btn pri",onclick:()=>W.quickScan("auto")},"Scan now")]);
 const cnt={all:all.length,secure:all.filter(n=>n.level==="SECURE"&&!n.rogue).length,vulnerable:all.filter(n=>!n.rogue&&n.level!=="SECURE").length,high:all.filter(n=>n.display_level==="HIGH RISK").length,rogue:all.filter(n=>n.rogue).length,wps:all.filter(n=>n.wps).length,open:all.filter(n=>n.encryption==="OPEN").length};
 const root=h("div"),body=h("div"),inp=h("input",{placeholder:"Search name, address, maker…",id:"q",autocomplete:"off"});inp.value=S.q;const chips=h("div",{class:"chips"});
 root.append(W.explain("What you are looking at","Every access point (router or hotspot) your device can hear. Click any row for a plain-English report and fixes. Underlined words explain themselves when you hover over them."));
 const paintChips=()=>chips.replaceChildren(...[["all","All"],["secure","Secure"],["vulnerable","Vulnerable"],["high","High risk"],["rogue","Impostors"],["wps","WPS on"],["open","Open"]].map(([k,l])=>h("button",{class:"chip"+(S.filter===k?" on":""),onclick:()=>{S.filter=k;paintChips();paintTable()}},l,h("em",null,cnt[k]))));
 inp.addEventListener("input",()=>{S.q=inp.value;paintTable()});
 root.append(h("div",{class:"toolbar"},h("label",{class:"search"},ic("search",16),inp,h("kbd",null,"/")),chips));paintChips();
 const cols=[["name",T("ssid","Name",1)],["bssid",T("bssid","Address",1)],["channel",T("channel","Channel",1)],["signal",T("dbm","Signal",1)],["encryption",T("wpa","Encryption",1)],["wps",T("wps","WPS",1)],["score",T("score","Score",1)],["level","Verdict"]];
 function paintTable(){const rows=filtered();body.replaceChildren(h("div",{class:"card",style:"padding:12px 16px"},h("div",{class:"tw"},rows.length?h("table",{class:"tbl"},
  h("thead",null,h("tr",null,...cols.map(([k,l])=>{const key=k==="bssid"?null:k;return h("th",{class:S.sortK===key?"s":"","data-d":S.sortD===1?"↑":"↓",onclick:()=>{if(!key)return;if(S.sortK===k)S.sortD*=-1;else{S.sortK=k;S.sortD=1}paintTable()}},l)}))),
  h("tbody",null,rows.map((n,i)=>h("tr",{class:"cl"+(n.rogue?" rg":""),style:"--n:"+Math.min(i,14),onclick:()=>W.openDrawer(n)},
   h("td",null,h("div",{class:"nm"+(n.hidden?" hid":"")},ic(n.encryption==="OPEN"?"unlock":"lock",15),h("span",null,n.name),n.connected?h("span",{class:"badge ac"},"YOU"):null)),
   h("td",null,h("div",{class:"mono"},n.bssid),h("div",{class:"vend"},n.vendor||"Unknown maker")),
   h("td",null,n.channel||"-",h("span",{class:"vend"},n.band?"  "+n.band.replace(" GHz","G"):"")),
   h("td",null,W.sig(n.signal),n.signal==null?"-":n.signal+" dBm"),
   h("td",null,h("span",{class:"badge "+(/OPEN|WEP/.test(n.encryption)?"bad":/^WPA(\/WPA2)?$/.test(n.encryption)?"warn":/WPA3|Enterprise/.test(n.encryption)?"ok":"ac")},n.encryption)),
   h("td",null,n.wps==null?h("span",{class:"mono"},"-"):h("span",{class:"badge "+(n.wps?"bad":"")},n.wps?(n.wps_locked?"Locked":"On"):"Off")),
   h("td",null,h("span",{class:"sc"},h("i",null,h("b",{style:"width:"+n.score+"%;background:"+W.LV[n.display_level][1]})),n.score)),
   h("td",null,W.pill(n.display_level)))))):W.empty("search","No matches","Try a different search or filter."))))}
 paintTable();root.append(body);return root}

/* ------------------------------------------------------------------ threats */
function vThreats(){const t=W.nets().filter(n=>n.rogue||n.display_level==="HIGH RISK");const root=h("div");
 root.append(W.explain("What counts as a threat?","An ",T("rogue","impostor")," is an access point that copies the name of a real network (an ",T("eviltwin","evil twin"),") or behaves like an attack device. ",T("highrisk","High-risk")," networks are real but unprotected. Click a card for evidence and fixes."));
 if(!W.nets().length)return W.empty("shield","No scan data","Run a scan first.",[h("button",{class:"btn pri",onclick:()=>W.quickScan("auto")},"Scan now")]);
 if(!t.length){root.append(W.empty("shield","All quiet","No impostors or high-risk networks in the latest scan."));return root}
 t.sort((a,b)=>(b.rogue-a.rogue)||a.score-b.score).forEach((n,i)=>{const c=W.LV[n.display_level][1],f=n.findings.find(x=>x.sev!=="info");
  root.append(h("div",{class:"tcard",style:"--c:"+c+";animation:up .4s both;animation-delay:"+i*60+"ms",onclick:()=>W.openDrawer(n)},h("div",{style:"flex:1;min-width:0"},
   h("h4",null,n.name,W.pill(n.display_level),n.connected?h("span",{class:"badge rog"},"YOU ARE CONNECTED"):null,h("span",{class:"mono"},n.bssid)),
   h("p",null,W.plainSummary(n)),
   h("div",{style:"margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"},h("span",{class:"badge"},n.encryption),h("span",{class:"badge"},"channel "+(n.channel||"-")),h("span",{class:"badge"},"score "+n.score),n.rogue?h("span",{class:"badge rog"},"impostor likelihood "+n.rogue_score+"%"):null,f&&!n.rogue?h("span",{class:"badge warn"},f.title):null)),ic("arrow",20)))});
 return root}

/* ------------------------------------------------------------------ compare any two scans */
function compareCard(list){const card=W.card("Compare two scans","list","c12",2);
 const a=h("select",{class:"in",style:"max-width:260px"}),b=h("select",{class:"in",style:"max-width:260px"}),go=h("button",{class:"btn pri"},"Compare"),out=h("div",{style:"margin-top:18px"});
 const opt=s=>h("option",{value:s.id},"#"+s.id+" - "+W.fmt(s.ts)+(s.label?" ("+s.label+")":""));
 a.replaceChildren(...list.map(opt));b.replaceChildren(...list.map(opt));if(list.length>1)a.value=list[1].id;if(list.length)b.value=list[0].id;
 go.onclick=async()=>{go.disabled=true;out.replaceChildren(h("div",{style:"padding:20px;text-align:center"},h("span",{class:"spin"})));
  try{const r=await W.api("/api/compare?a="+a.value+"&b="+b.value);const A=r.a.summary,B=r.b.summary,d=r.diff;
   const row=(label,ka,kb,fmt)=>h("tr",null,h("td",null,label),h("td",null,fmt?fmt(ka):ka),h("td",null,fmt?fmt(kb):kb),h("td",null,(kb-ka)>0?h("span",{class:"up"},"+"+(kb-ka)):(kb-ka)<0?h("span",{class:"dn"},kb-ka):"—"));
   out.replaceChildren(h("div",{class:"tw"},h("table",{class:"tbl",style:"min-width:500px"},h("thead",null,h("tr",null,h("th",null,"Metric"),h("th",null,"#"+r.a.meta.id),h("th",null,"#"+r.b.meta.id),h("th",null,"Change"))),
    h("tbody",null,row("Networks found",A.total,B.total),row("Secure",A.secure,B.secure),row("Vulnerable",A.vulnerable,B.vulnerable),row("Impostors",A.rogue,B.rogue),row("Posture score",A.posture,B.posture)))),
    h("div",{class:"lbl"},"What changed"),
    d.new.length||d.gone.length||d.changed.length?h("div",null,d.new.map(x=>h("div",{style:"margin-bottom:6px"},h("span",{class:"badge ok"},"NEW")," ",x.name)),d.gone.map(x=>h("div",{style:"margin-bottom:6px"},h("span",{class:"badge"},"GONE")," ",x.name)),d.changed.map(c=>h("div",{style:"margin-bottom:6px"},h("span",{class:"badge warn"},"CHANGED")," ",c.ssid+": "+c.field+" "+c.old+" → "+c.new))):h("div",{class:"cap"},"No differences between these two scans."))}
  catch(e){out.replaceChildren(h("div",{class:"hintbox"},e.message))}finally{go.disabled=false}};
 card.append(h("div",{class:"toolbar",style:"align-items:flex-end"},h("div",{class:"field",style:"margin:0"},h("label",null,"Earlier scan"),a),h("div",{class:"field",style:"margin:0"},h("label",null,"Later scan"),b),go),out);
 if(list.length>1)go.onclick();return card}

/* ------------------------------------------------------------------ scheduled reports */
function scheduleCard(){const card=W.card("Scheduled reports","clock","c12",3),area=h("div");card.append(h("div",{class:"cap"},"Runs automatically while this app stays open (",h("code",null,"python run.py"),"); for a schedule that survives the app being closed, use your OS's own scheduler instead - see the Terminal tip below."),area);
 (async()=>{const s=await W.api("/api/schedule");
  const en=h("input",{type:"checkbox"});en.checked=!!s.enabled;
  const wdField=h("div",{class:"field",style:"margin:0;display:"+(s.frequency==="weekly"?"":"none")});
  const freq=h("select",{class:"in",style:"max-width:140px",onchange:()=>{wdField.style.display=freq.value==="weekly"?"":"none"}},...["hourly","daily","weekly"].map(f=>h("option",{value:f,selected:f===s.frequency},f)));
  const time=h("input",{class:"in",type:"time",value:s.time||"09:00",style:"max-width:120px"});
  const wd=h("select",{class:"in",style:"max-width:140px"},...["Mon","Tue","Wed","Thu","Fri","Sat","Sun"].map((d,i)=>h("option",{value:i,selected:i===(s.weekday||0)},d)));
  wdField.append(h("label",null,"Day"),wd);
  const fmt=h("select",{class:"in",style:"max-width:100px"},...["pdf","html","json","csv"].map(f=>h("option",{value:f,selected:(s.format||["pdf"]).includes(f)},f.toUpperCase())));
  const save=h("button",{class:"btn pri sm"},"Save"),run=h("button",{class:"btn sm"},"Run now"),status=h("div",{class:"cap"},s.enabled?("Next run: "+(s.next_run?new Date(s.next_run).toLocaleString():"-")+"  ·  last ran: "+(s.last_run||"never")):"Not enabled.");
  save.onclick=async()=>{try{const r=await W.post("/api/schedule",{enabled:en.checked,frequency:freq.value,time:time.value,weekday:+wd.value,format:[fmt.value]});W.toast("Saved","ok");status.textContent=r.sched.enabled?("Next run: "+(r.next_run?new Date(r.next_run).toLocaleString():"-")):"Not enabled."}catch(e){W.toast(e.message,"err")}};
  run.onclick=async()=>{run.disabled=true;try{const r=await W.post("/api/schedule/run-now",{});W.toast(r.result?"Ran scan #"+r.result.scan_id:"Nothing to do","ok");W.refresh(true)}catch(e){W.toast(e.message,"err")}finally{run.disabled=false}};
  area.replaceChildren(h("div",{class:"toolbar",style:"align-items:flex-end"},h("div",{class:"field",style:"margin:0"},h("label",null,"Enabled"),en),h("div",{class:"field",style:"margin:0"},h("label",null,"Frequency"),freq),
   h("div",{class:"field",style:"margin:0"},h("label",null,"Time"),time),wdField,h("div",{class:"field",style:"margin:0"},h("label",null,"Format"),fmt),save,run),status,
   h("div",{class:"cap",style:"margin-top:10px"},"Terminal alternative (works even when the app is closed): ",h("code",null,"crontab -e")," on Linux or Task Scheduler on Windows, running ",h("code",null,"python auditor.py scan -f pdf"),". See the README."))})();
 return card}

/* ------------------------------------------------------------------ history */
function vHistory(){const list=S.scans;const root=h("div");
 root.append(W.explain("Why keep history?","Every scan is stored on this computer only. Comparing scans reveals what changed: new networks, networks that vanished, or one that quietly downgraded its encryption."));
 if(!list.length)return W.empty("clock","No history yet","Scans you run are stored locally so you can compare them.");
 const g=h("div",{class:"grid"}),c=W.card("Stored scans","clock","c7",0);
 list.forEach(s=>c.append(h("div",{class:"hrow"+(S.cur&&S.cur.meta&&S.cur.meta.id===s.id?" on":"")},h("span",{class:"id"},s.id),h("div",null,h("div",{class:"when"},W.fmt(s.ts)+(s.label?" · "+s.label:"")),h("div",{class:"meta"},"via "+s.backend+(s.iface?" · "+s.iface:""))),
  h("div",{class:"sp"},h("span",{class:"badge"},s.total+" networks"),h("span",{class:"badge ok"},s.secure+" secure"),h("span",{class:"badge warn"},s.vulnerable+" vulnerable"),s.rogue?h("span",{class:"badge rog"},s.rogue+" impostor"):null,
   h("button",{class:"btn sm",onclick:()=>W.loadScan(s.id,"overview")},"Open"),h("button",{class:"btn sm icon danger",title:"Delete",onclick:async()=>{if(!confirm("Delete scan #"+s.id+"?"))return;await W.api("/api/scans/"+s.id,{method:"DELETE"});await W.refresh(true);W.toast("Scan deleted")}},ic("trash",14))))));
 g.append(c);
 const pts=[...list].reverse(),Wd=420,H=170,P_=26,trend=W.card("Trend","activity","c5",1);
 if(pts.length<2)trend.append(h("div",{class:"cap"},"Run at least two scans to see how your airspace changes over time."));
 else{const mx=Math.max(1,...pts.map(p=>Math.max(p.vulnerable,p.rogue,p.secure))),X=i=>P_+i*(Wd-2*P_)/(pts.length-1),Y=v=>H-P_-v*(H-2*P_)/mx;
  const line=(k,col)=>sv("polyline",{points:pts.map((p,i)=>X(i)+","+Y(p[k])).join(" "),fill:"none",stroke:col,"stroke-width":2,"stroke-linejoin":"round"});
  const col={secure:"#6fbf9a",vulnerable:"#e3b04b",rogue:"#ff4d7d"},svg=sv("svg",{viewBox:"0 0 "+Wd+" "+H,style:"width:100%"},sv("line",{x1:P_,x2:Wd-P_,y1:H-P_,y2:H-P_,stroke:"rgba(201,164,92,.3)"}),line("secure",col.secure),line("vulnerable",col.vulnerable),line("rogue",col.rogue));
  pts.forEach((p,i)=>["secure","vulnerable","rogue"].forEach(k=>svg.append(sv("circle",{cx:X(i),cy:Y(p[k]),r:3.5,fill:col[k]}))));
  trend.append(svg,h("div",{class:"legend",style:"flex-direction:row;gap:18px;margin-top:8px"},h("div",null,h("i",{style:"background:"+col.secure}),"Secure"),h("div",null,h("i",{style:"background:"+col.vulnerable}),"Vulnerable"),h("div",null,h("i",{style:"background:"+col.rogue}),"Impostor")))}
 g.append(trend);if(list.length>1)g.append(compareCard(list));g.append(scheduleCard());root.append(g);return root}

/* ------------------------------------------------------------------ learn */
const WALKTHROUGH=[
 {t:"The evil twin",steps:[
  "An attacker sets up their own access point near a real one (a cafe, an office, your home) and gives it the exact same name.",
  "Many devices auto-join any network whose name they remember - no warning is shown, because the name matches.",
  "Once joined, every request you make passes through the attacker's device first.",
  "They can read unencrypted traffic, redirect you to fake login pages, or simply log what sites you visit."],
  catch:"Two networks broadcasting the same name is the giveaway. Our rogue-AP check looks for exactly this, plus a weaker encryption mode or a stronger-than-expected signal on the impostor."},
 {t:"ARP spoofing (man-in-the-middle)",steps:[
  "Every device on a local network asks 'who has this address?' and trusts whoever answers - there is no built-in authentication.",
  "An attacker already on the network answers 'I do' for the router's address.",
  "Devices start sending their internet-bound traffic to the attacker instead of the real router.",
  "The attacker forwards it onward (so nothing looks broken) while reading or altering it along the way."],
  catch:"The router's hardware address changing, or one address claiming to be several devices, is the signature. The ARP spoof check compares against a saved baseline."},
 {t:"WPS PIN attack",steps:[
  "WPS lets a device join using an 8-digit PIN instead of typing the Wi-Fi password.",
  "The PIN is actually checked as two separate halves, which shrinks the real number of guesses from 100 million to about 11,000.",
  "Software can try all of them against an unlocked router, usually within hours.",
  "Once the PIN is found, the router hands over the real Wi-Fi password - no need to crack it at all."],
  catch:"This only works when WPS is on and unlocked. Turning WPS off removes the entire attack path, which is why it is always one of our top recommendations."},
 {t:"DNS hijacking",steps:[
  "Every website name you type gets turned into a number by a DNS server, usually your router or ISP's.",
  "If that server is compromised or configured maliciously, it can answer with the wrong number for any name it chooses.",
  "Your browser has no way to tell the difference - it just connects to whatever address it was given.",
  "You land on a convincing fake site, often one built to steal passwords."],
  catch:"HTTPS normally catches this, because the fake site can't present a valid certificate for the real name - that's what the Internet & DNS tool's certificate check looks for."}
];
const FAQ=[
 ["Will this tool get me in trouble?","No, as long as you stay within what it's built to do: listening to Wi-Fi broadcasts and checking devices on your own network. It never attacks, cracks, or accesses anything without permission. Don't point the device-discovery or port-scanner tools at a network you don't own or have permission to test."],
 ["Why does the same network sometimes score differently?","Routers sometimes broadcast a slightly weaker 'transition mode' alongside their main signal for older devices, or signal strength changes as you move - both can shift the score a little between scans."],
 ["It says a device is 'unknown' but it's my phone.","Many modern phones use a randomised hardware address for privacy and generate a new one periodically. Label it once with 'I know this' and it should remain recognised, though an OS update can occasionally reset it."],
 ["Can it crack a Wi-Fi password?","No - deliberately. See the Passphrase tester if you want to check your own password's strength instead."],
 ["Why is my own network marked as a possible impostor?","If you run two routers, mesh nodes, or a repeater with the same network name, that can look identical to an evil twin. Click the network and press 'This one is mine' to mark it trusted."],
 ["Does it use the internet?","Only three tools do: Connection quality, Internet & DNS health, and the optional CVE refresh - and only to run ordinary connectivity tests, never to send your data anywhere. Everything else works offline."],
];
const DEDUCT=[["Open network (no encryption)","−60","always High risk"],["WEP encryption","−70","always High risk"],["WPA (version 1) only","−40",""],["Mixed WPA/WPA2 mode","−25",""],["WPA2 with TKIP cipher","−20",""],["WPS on and unlocked","−25","never better than Vulnerable"],["WPS on but locked","−10",""],["No forged-disconnect protection (PMF)","−5",""],["Factory-style name (e.g. NETGEAR47)","−5",""]];
function vLearn(){const root=h("div");const hl=S.arg;
 root.append(W.explain("Start here","This tool listens to the Wi-Fi networks around you and to your own network, then explains what it finds in plain language. Nothing here attacks anything: it only reads broadcasts and makes ordinary connections to your own devices."));
 root.append(h("div",{class:"lbl"},"How it works"),h("div",{class:"steps"},
  h("div",null,h("b",null,"Listen"),h("span",null,"Access points shout their name, encryption and settings ten times a second. We just listen. (",T("beacon","beacons"),")")),
  h("div",null,h("b",null,"Grade"),h("span",null,"Each network starts at 100 points; weaknesses subtract points. The average becomes your posture score.")),
  h("div",null,h("b",null,"Hunt for fakes"),h("span",null,"We compare names, makers, encryption and signal to spot copies of real networks.")),
  h("div",null,h("b",null,"Check your own network"),h("span",null,"The Toolbox finds devices, open ports, DNS tampering, ARP spoofing and more on the network you are on."))));
 const sc=W.card("How scores work","list","",0);sc.style.marginTop="22px";
 sc.append(h("div",{class:"tw"},h("table",{class:"tbl",style:"min-width:520px"},h("thead",null,h("tr",null,h("th",null,"Weakness"),h("th",null,"Points lost"),h("th",null,"Extra rule"))),h("tbody",null,DEDUCT.map(r=>h("tr",null,h("td",null,r[0]),h("td",{style:"font:600 18px Georgia,serif;color:var(--bad)"},r[1]),h("td",{class:"mono"},r[2])))))),
  h("div",{class:"cap"},"Score 80+ = Secure · 30-79 = Vulnerable · under 30 = High risk. Posture = average score − 10 per impostor. Grades: A 90+, B 80+, C 70+, D 55+, F below."));
 root.append(sc,h("div",{class:"lbl"},"Glossary"));
 const q=h("input",{class:"in",placeholder:"Search the glossary…",style:"max-width:380px;margin-bottom:14px"}),box=h("div");
 function paint(){const t=q.value.trim().toLowerCase();box.replaceChildren(...W.GROUPS.map(([gname,keys])=>{const ks=keys.filter(k=>{const g=W.GLOSS[k];return !t||(g.t+g.s+g.l).toLowerCase().includes(t)});
  return ks.length?h("div",null,h("div",{class:"lbl"},gname),h("div",{class:"gl"},ks.map(k=>{const g=W.GLOSS[k];return h("div",{class:"card"+(k===hl?" hl":""),id:"g-"+k},h("h5",null,g.t),h("p",null,g.l),h("small",null,"Why it matters: "+g.why))}))):null}))}
 q.addEventListener("input",paint);root.append(q,box);paint();
 root.append(h("div",{class:"lbl"},"How common attacks actually work"),h("div",{class:"gl"},WALKTHROUGH.map(w=>h("div",{class:"card"},h("h5",null,w.t),h("dl",{style:"grid-template-columns:22px 1fr;margin:10px 0"},...w.steps.flatMap((st,i)=>[h("dt",{style:"color:var(--gold);font:600 16px Georgia,serif"},(i+1)+"."),h("dd",{style:"margin:0 0 6px"},st)])),h("p",{style:"margin:10px 0 0;color:var(--ok);font-style:italic"},"How this tool catches it: "+w.catch)))));
 root.append(h("div",{class:"lbl"},"Frequently asked"),h("div",{class:"gl"},FAQ.map(([q,a])=>h("div",{class:"card"},h("h5",null,q),h("p",null,a)))));
 root.append(h("div",{class:"lbl"},"Responsible use"),h("div",{class:"card"},h("p",{style:"margin:0;color:#d4cdb8"},"Listening to broadcasts is legal almost everywhere, but only test networks and devices you own or have written permission to assess. The discovery and port-scan tools refuse anything outside your private network by design.")));
 if(hl)setTimeout(()=>{const e=document.getElementById("g-"+hl);if(e)e.scrollIntoView({behavior:"smooth",block:"center"})},150);
 return root}

W.views={overview:vOverview,networks:vNetworks,threats:vThreats,history:vHistory,learn:vLearn};
W.TITLES={overview:["I","Security overview","How safe is the wireless world around you?"],networks:["II","Networks","Every access point in range"],threats:["III","Threat center","Impostors and unsafe networks"],
 tools:["IV","Toolbox","Check the network you are on"],history:["V","Scan history","Compare scans and spot changes"],learn:["VI","Learn","Plain-English guide and glossary"]};
})(WA);
