/* Toolbox: network tools for the network you are on */
(function(W){
"use strict";
const h=W.h,sv=W.sv,ic=W.ic,T=W.T,S=W.S;

const TOOLS=[
 {id:"link",n:"My connection",i:"wifi",tag:["Live","ok"],d:"A live meter of the Wi-Fi signal you are using right now, with a moving graph.",use:"Find the best spot for your router or laptop.",
  does:"Reads your adapter every 2 seconds: signal strength, channel, link speed and security.",why:"Weak signal is the #1 cause of slow Wi-Fi. Watch the graph while you move around.",expect:"A needle on a red-to-green meter, a history graph and a verdict from Excellent to Very poor."},
 {id:"devices",n:"Who is on my network?",i:"users",tag:["Active · your LAN only","ac"],d:"Finds every device connected to your network and flags ones you do not recognise.",use:"Spot an uninvited guest or a forgotten gadget.",
  does:"Knocks politely on every address in your subnet and reads the router's address book (ARP) to list devices with their maker and name.",why:"Neighbours borrowing your Wi-Fi or a compromised gadget show up here as unknown devices.",expect:"A table of devices. Mark the ones you know once; anything new is highlighted next time."},
 {id:"ports",n:"Port scanner",i:"server",tag:["Active · your LAN only","ac"],d:"Shows which doors (ports) a device on your network leaves open, and which are risky.",use:"Check your router, camera or NAS for needless exposure.",
  does:"Tries ordinary TCP connections to a list of ports on one device you choose, reads each service's banner, and checks it against a bundled list of known CVEs.",why:"Open Telnet, remote desktop or file-sharing ports are how most home-network breaches start, and an outdated service version can be a known, named vulnerability.",expect:"A list of open ports with a plain-English risk note, and a verdict. Refuses non-private addresses."},
 {id:"internet",n:"Internet & DNS health",i:"globe",tag:["Read-only","ok"],d:"Detects captive portals, DNS tampering and HTTPS interception on the network you are on.",use:"Run it on hotel, cafe or airport Wi-Fi before logging in to anything.",
  does:"Tests whether DNS tells the truth, whether secure sites present genuine certificates, and whether a login page is intercepting you.",why:"These are the signatures of man-in-the-middle attacks and hijacked routers.",expect:"A verdict and a list of findings. If HTTPS certificates fail, do not enter passwords."},
 {id:"quality",n:"Connection quality",i:"activity",tag:["Read-only","ok"],d:"Measures delay, jitter and packet loss to your router and the internet, then grades the connection.",use:"Find out whether lag is your Wi-Fi or your internet provider.",
  does:"Sends small test messages to your router, Cloudflare and Google and times the replies.",why:"Separating 'bad Wi-Fi' from 'bad ISP' tells you whether to move the router or phone the provider.",expect:"A grade A to F, the numbers behind it, and specific tips."},
 {id:"arp",n:"ARP spoof check",i:"shield",tag:["Read-only","ok"],d:"Watches for the tell-tale signs of someone impersonating your router on the local network.",use:"Run it when the network behaves strangely or after joining untrusted Wi-Fi.",
  does:"Reads the table linking addresses to hardware, flags duplicates, and compares your router's hardware address with a saved baseline.",why:"If the router's hardware address changes, someone may be sitting in the middle of your traffic.",expect:"'No sign of ARP spoofing' or specific warnings. Save a baseline on a network you trust."},
 {id:"router",n:"Router fingerprint",i:"server",tag:["Read-only","ok"],d:"Identifies your router's make and admin software from its web page, with any known weak points.",use:"Know what you are dealing with before changing settings.",
  does:"Makes an ordinary GET request to your router's admin page and reads its headers and title - the same thing a browser does.",why:"Some embedded web servers (like old RomPager builds) have well-known vulnerabilities.",expect:"Vendor, software and any notes, plus a direct link to the admin page. Never attempts to log in."},
 {id:"saved",n:"Saved networks audit",i:"lock",tag:["Private","ok"],d:"Lists the Wi-Fi networks this computer remembers and flags risky ones that auto-connect.",use:"Clean out old cafe and hotel networks.",
  does:"Reads the saved profile list (never the passwords) and checks each one's security and auto-connect setting.",why:"Your laptop will silently join any open network with a remembered name, which attackers exploit with fake twins.",expect:"A table sorted by risk with a one-line fix for each."},
 {id:"info",n:"Network info",i:"list",tag:["Read-only","ok"],d:"Your address, router, subnet and DNS servers, each explained.",use:"Quick reference when configuring or troubleshooting.",
  does:"Reads your current network configuration from the operating system.",why:"You need these values for almost every other network task.",expect:"Six labelled values with one-line explanations."},
 {id:"pass",n:"Passphrase tester",i:"key",tag:["Private · never leaves your browser","ok"],d:"Estimates how long your Wi-Fi password would take to crack.",use:"Before you set or change your Wi-Fi password.",
  does:"Analyses length, variety and common patterns locally in your browser and estimates offline guessing time.",why:"Weak Wi-Fi passwords can be cracked offline from a captured handshake, with no way to stop the attacker.",expect:"A strength meter, estimated crack time and concrete suggestions. Nothing is sent or stored."},
 {id:"mac",n:"Address & vendor lookup",i:"search",tag:["Read-only","ok"],d:"Turns a hardware (MAC) address into a manufacturer and tells you if it is randomised.",use:"Identify a mystery device or check a router's maker.",
  does:"Looks up the first half of the address in the built-in vendor list and decodes its flags.",why:"A 'Netgear' router suddenly appearing as an unknown maker under the same name is suspicious.",expect:"Maker name and whether the address is randomised (phones) or factory-assigned."},
 {id:"locations",n:"My locations",i:"map",tag:["Private","ok"],d:"Remembers Home, Office, Cafe and other networks so your own router isn't re-flagged every time you move.",use:"Stop re-labelling your own router as new each visit.",
  does:"Saves the current router's address and network name under a name you choose.",why:"Moving between trusted places used to make every scan look unfamiliar again.",expect:"A list of saved locations you can add to or remove."},
  {id:"alertcfg",n:"Alert delivery",i:"activity",tag:["Private","ok"],d:"Send Live Monitor alerts to your email or a Slack/Discord channel, not just this browser tab.",use:"Get notified even when the dashboard is closed.",
  does:"Stores SMTP or webhook settings and lets you send a test message.",why:"A rogue AP alert only helps if you see it - email/webhook delivery works even when you are away from the screen.",expect:"A settings form and a 'Send test' button."},
 {id:"speedtest",n:"Speed test",i:"zap",tag:["Uses the internet","warn"],d:"Measures real download throughput, not just delay.",use:"Check if you are getting the speed you pay for.",
  does:"Downloads a chunk of data from a well-known public test server for a few seconds and times it.",why:"Connection quality measures delay (ping); this measures actual Mbps.",expect:"A speed in Mbps with a plain rating. Download only - no reliable public upload-test exists without an account."},
 {id:"coverage",n:"Coverage map",i:"map",tag:["Active · your LAN only","ac"],d:"Walk around and click where you are standing; builds a simple map of Wi-Fi dead zones.",use:"Find out where in your home or office the signal is weak.",
  does:"Each click reads your current signal and places a coloured dot where you clicked on a simple grid - no floor plan needed.",why:"A visual map of weak spots is far clearer than a single number.",expect:"A clickable grid that fills in with green-to-red dots as you walk around and click."},
 {id:"guestcheck",n:"Guest network check",i:"shield",tag:["Active · your LAN only","ac"],d:"A heuristic check for whether your guest Wi-Fi is actually isolated from your main devices.",use:"Verify a guest network before giving visitors the password.",
  does:"Looks at the current network's name and checks how many other devices answer besides the router.",why:"Many 'guest' networks are not actually isolated - visitors can quietly reach your other devices.",expect:"A verdict, not a guarantee - see the note on why this can't be 100% certain from outside the router."},
 {id:"activity",n:"My network activity",i:"activity",tag:["This device only","ok"],d:"Shows which internet addresses THIS device is currently talking to - never other devices, never content.",use:"Spot unexpected background connections.",
  does:"Reads this computer's own connection table (the same information `netstat` shows) and groups it by category.",why:"Unexpected connections (to IPs you don't recognise, in odd categories) can indicate unwanted software.",expect:"A categorised list of this device's own active connections. This is not packet capture and never reads other devices' traffic."}
];
function cveCol(sev){return {critical:'#ff4d7d',high:'#e2574c',medium:'#e3b04b',low:'#7fa6d9'}[sev]||'#a7a293'}
const DEF=Object.fromEntries(TOOLS.map(t=>[t.id,t]));
W.TOOLS=TOOLS;

function hub(){const root=h("div");
 root.append(W.explain("The Toolbox","Wi-Fi scanning tells you about the air around you. These tools check the network you are actually connected to: who is on it, what is exposed, and whether anyone is tampering with it. Pick a tool - each one explains what it does before you run it."));
 root.append(h("div",{class:"tools"},TOOLS.map((t,i)=>h("button",{class:"tool",style:"--n:"+i,onclick:()=>{location.hash="tool/"+t.id}},
  h("span",{class:"tag badge "+t.tag[1]},t.tag[0]),h("div",{class:"ti"},ic(t.i,22)),h("h4",null,t.n),h("p",null,t.d),h("div",{class:"use"},"Use it to: "+t.use)))));
 return root}

/* ------------------------------------------------------------------ shared bits */
function shell(def,body){const root=h("div");
 root.append(h("a",{class:"back",href:"#tools"},ic("back",14),"All tools"),
  h("div",{class:"about"},h("div",null,h("b",null,"What it does"),def.does),h("div",null,h("b",null,"Why use it"),def.why),h("div",null,h("b",null,"What to expect"),def.expect)),body);return root}
const errBox=e=>h("div",{class:"hintbox"},h("b",null,e.message),e.hint?h("div",{style:"margin-top:4px"},"How to fix: "+e.hint):null);
async function runInto(area,btn,label,fn){btn.disabled=true;area.replaceChildren(h("div",{class:"empty",style:"padding:34px"},h("span",{class:"spin"}),h("div",{style:"margin-top:12px"},label)));
 try{area.replaceChildren(await fn())}catch(e){area.replaceChildren(errBox(e))}finally{btn.disabled=false}}
const lvColor={critical:"#ff4d7d",high:"#e2574c",medium:"#e3b04b",low:"#7fa6d9",info:"#a7a293",ok:"#6fbf9a"};
function findings(list){return list.length?list.map(f=>h("div",{class:"find",style:"--c:"+(lvColor[f.sev]||lvColor.info)},h("h5",null,W.sevpill(f.sev),f.title),h("dl",null,h("dt",null,"Details"),h("dd",null,f.detail),f.fix?[h("dt",null,"What to do"),h("dd",null,f.fix)]:null))):[h("div",{class:"find",style:"--c:"+lvColor.ok},h("h5",null,W.sevpill("ok"),"Nothing wrong found"))]}
const table=(heads,rows,mw)=>h("div",{class:"tw"},h("table",{class:"tbl",style:"min-width:"+(mw||600)+"px"},h("thead",null,h("tr",null,heads.map(x=>h("th",{style:"cursor:default"},x)))),h("tbody",null,rows)));

const B={};

B.router=()=>{const card=W.card("Router fingerprint","server","",0),inp=h("input",{class:"in",placeholder:"auto-detect your router",style:"max-width:280px"}),btn=h("button",{class:"btn pri"},ic("search"),"Identify"),area=h("div",{style:"margin-top:22px"});
 btn.onclick=()=>runInto(area,btn,"Reading the router's admin page…",async()=>{const r=await W.tool("router",{ip:inp.value.trim()});const wrap=h("div");
  if(!r.reachable){wrap.append(h("div",{class:"hintbox"},r.note||"No web admin page answered."));return wrap}
  wrap.append(h("div",{class:"kpis"},W.kpi("Address",r.ip,r.port+(r.https?" (https)":"")),W.kpi("Likely maker",r.vendor||"Unknown",""),W.kpi("Web server",r.server,""),W.kpi("Login required",r.requires_login?"Yes":"Unclear","",r.requires_login?"var(--ok)":"var(--warn)")));
  if(r.page_title)wrap.append(h("div",{class:"cap"},"Page title: “"+r.page_title+"”"));
  wrap.append(r.notes.length?h("div",null,...r.notes.map(n=>h("div",{class:"find",style:"--c:var(--warn)"},h("h5",null,W.sevpill("medium")," Known weak point in this software"),h("dl",null,h("dt",null,"Detail"),h("dd",null,n))))):h("div",{class:"find",style:"--c:var(--ok)"},h("h5",null,W.sevpill("ok"),"No known issues with this web server software")));
  wrap.append(h("div",{class:"mf",style:"justify-content:flex-start"},h("a",{class:"btn",href:r.admin_url,target:"_blank",rel:"noopener"},"Open admin page")),h("div",{class:"cap"},"This only reads the public login page - it never attempts to sign in. Never expose your router's admin page to the internet."));
  return wrap});
 card.append(h("div",{class:"toolbar"},inp,btn),area);return card};

/* ------------------------------------------------------------------ 12. locations */
B.locations=()=>{const card=W.card("My locations","map","",0),list=h("div"),name=h("input",{class:"in",placeholder:"Name this network, e.g. Home",style:"max-width:240px"}),add=h("button",{class:"btn pri"},ic("plus"),"Save current network");
 async function paint(){const locs=await W.api("/api/locations");list.replaceChildren(Object.keys(locs).length?h("div",null,Object.entries(locs).map(([n,L])=>h("div",{class:"hrow"},h("div",null,h("div",{class:"when"},n),h("div",{class:"meta"},"SSIDs: "+(L.ssids.join(", ")||"-")+"  ·  routers remembered: "+L.gateway_bssids.length)),h("button",{class:"btn sm icon danger",onclick:async()=>{await W.api("/api/locations/"+encodeURIComponent(n),{method:"DELETE"});paint()}},ic("trash",14))))):h("div",{class:"cap"},"No locations saved yet. Scan while connected to a network you trust, then save it here."))}
 add.onclick=async()=>{if(!S.cur||!S.cur.meta){W.toast("Run a scan first","warn");return}const mine=(S.cur.networks||[]).find(n=>n.connected);if(!mine){W.toast("Not connected to any scanned network right now","warn");return}
  const label=name.value.trim()||mine.name;try{await W.post("/api/locations",{name:label,gateway_bssid:mine.bssid,ssid:mine.ssid});W.toast("Saved '"+label+"'","ok");name.value="";paint()}catch(e){W.toast(e.message,"err")}};
 card.append(h("div",{class:"toolbar"},name,add),h("div",{class:"cap"},"Trusting a location does not change any security findings - it only stops this computer from treating your own router as unfamiliar."),list);paint();return card};

/* ------------------------------------------------------------------ 13. alert delivery */
B.alertcfg=()=>{const card=W.card("Alert delivery","activity","",0),area=h("div");card.append(area);
 async function paint(){const cfg=await W.api("/api/alerts/config");
  const wh=h("input",{class:"in",placeholder:"https://hooks.slack.com/services/…",value:cfg.webhook_url||"",style:"max-width:420px"});
  const eh=h("input",{class:"in",placeholder:"smtp.gmail.com",value:(cfg.email||{}).host||""}),ep=h("input",{class:"in",placeholder:"587",value:(cfg.email||{}).port||"587",style:"max-width:100px"}),
   eu=h("input",{class:"in",placeholder:"you@example.com",value:(cfg.email||{}).user||""}),ew=h("input",{class:"in",type:"password",placeholder:"app password",value:(cfg.email||{}).password||""}),
   eto=h("input",{class:"in",placeholder:"alerts-go-to@example.com",value:(cfg.email||{}).to||""});
  const save=h("button",{class:"btn pri"},ic("check"),"Save"),test=h("button",{class:"btn"},"Send test"),out=h("div",{class:"cap"});
  save.onclick=async()=>{try{await W.post("/api/alerts/config",{webhook_url:wh.value.trim(),email:{host:eh.value.trim(),port:+ep.value||587,user:eu.value.trim(),password:ew.value,to:eto.value.trim()}});W.toast("Saved","ok")}catch(e){W.toast(e.message,"err")}};
  test.onclick=async()=>{test.disabled=true;out.textContent="Sending…";try{const r=await W.post("/api/alerts/test",{});out.textContent=JSON.stringify(r.result)}catch(e){out.textContent="Failed: "+e.message}finally{test.disabled=false}};
  area.replaceChildren(h("div",{class:"field"},h("label",null,"Slack / Discord webhook URL")),wh,
   h("div",{class:"lbl"},"Email (SMTP)"),h("div",{class:"toolbar",style:"align-items:flex-end"},h("div",{class:"field",style:"margin:0"},h("label",null,"Host"),eh),h("div",{class:"field",style:"margin:0"},h("label",null,"Port"),ep),h("div",{class:"field",style:"margin:0"},h("label",null,"Username"),eu),h("div",{class:"field",style:"margin:0"},h("label",null,"Password"),ew),h("div",{class:"field",style:"margin:0"},h("label",null,"Send alerts to"),eto)),
   h("div",{class:"mf",style:"justify-content:flex-start"},save,test),out,h("div",{class:"cap"},"Used by Live Monitor (dashboard) and `watch` (command line) when they detect a new impostor or an open network. Nothing is sent unless one of these is filled in."))}
 paint();return card};

/* ------------------------------------------------------------------ 1. live connection */
B.link=()=>{const hist=[],card=W.card("Live signal","wifi","",0),out=h("div");card.append(out);
 function chart(){const Wd=600,H=150,mn=-100,mx=-30,pts=hist.slice(-60);if(pts.length<2)return h("div",{class:"cap"},"Collecting samples…");
  const X=i=>10+i*(Wd-20)/59,Y=v=>H-10-(Math.max(mn,Math.min(mx,v))-mn)/(mx-mn)*(H-20);
  const svg=sv("svg",{viewBox:"0 0 "+Wd+" "+H,class:"chart",preserveAspectRatio:"none"});
  [-40,-50,-60,-70,-80].forEach(v=>{svg.append(sv("line",{x1:0,x2:Wd,y1:Y(v),y2:Y(v),stroke:"rgba(201,164,92,.18)","stroke-dasharray":"3 5"}),sv("text",{x:Wd-4,y:Y(v)-3,"text-anchor":"end","font-size":10,fill:"#6f6b5f"},v))});
  svg.append(sv("polyline",{points:pts.map((v,i)=>X(i)+","+Y(v)).join(" "),fill:"none",stroke:"#ecd08e","stroke-width":2,"stroke-linejoin":"round"}));return svg}
 function paint(d){if(!d.connected){out.replaceChildren(W.empty("wifi","Not connected to Wi-Fi","Connect to a Wi-Fi network (Ethernet is not measured here).",null));return}
  hist.push(d.signal_dbm);const q=d.quality||{},col=q.pct>=70?"var(--ok)":q.pct>=45?"var(--warn)":"var(--bad)";
  out.replaceChildren(h("div",{class:"kpis"},W.kpi("Signal",d.signal_dbm+" dBm",q.label,col),W.kpi("Network",d.ssid||"-",d.bssid),W.kpi("Channel",(d.channel||"-")+"",d.band),
   W.kpi("Link speed",(d.rx_rate||"-")+" / "+(d.tx_rate||"-"),"Mbit/s down / up"),W.kpi("Security",d.auth||"-",d.cipher||""),
   d.estimated_distance_m!=null?W.kpi("Estimated distance","~"+d.estimated_distance_m+" m","to the access point"):null),
   h("div",{class:"meter"},h("i",{style:"left:calc("+(q.pct||0)+"% - 1px)"})),h("div",{class:"note"},"Poor ◂ ▸ Excellent  ·  "+(q.advice||"")),
   d.estimated_distance_note?h("div",{class:"hintbox"},d.estimated_distance_note):null,
   h("div",{class:"lbl"},"Last minute ("+hist.length+" samples)"),chart(),h("div",{class:"cap"},"Walk around with this open: the line shows how ",T("dbm","signal strength")," changes with position. Higher is better. See it on a floor-plan-free grid in the Coverage map tool."))}
 let busy=false;async function tick(){if(busy)return;busy=true;try{paint(await W.tool("link",{}))}catch(e){out.replaceChildren(errBox(e))}finally{busy=false}}
 const t=setInterval(tick,2000);W.onLeave(()=>clearInterval(t));tick();return card};

/* ------------------------------------------------------------------ 2. device discovery */
B.devices=()=>{const card=W.card("Device discovery","users","",0),cidr=h("input",{class:"in",placeholder:"auto-detect (e.g. 192.168.1.0/24)",style:"max-width:300px"}),
 btn=h("button",{class:"btn pri"},ic("radar"),"Find devices"),area=h("div",{style:"margin-top:22px"});
 W.tool("info",{}).then(i=>{cidr.placeholder=i.cidr+" (detected)"}).catch(()=>{});
 function render(res){const dev=res.devices,nKnown=dev.filter(d=>d.known||d.is_self||d.is_gateway).length,nNew=dev.length-nKnown,wrap=h("div");
  wrap.append(h("div",{class:"kpis"},W.kpi("Devices found",dev.length,"on "+res.cidr),W.kpi("Recognised",nKnown,"you, router, labelled","var(--ok)"),W.kpi("Not recognised",nNew,nNew?"check these":"all clear",nNew?"var(--warn)":"var(--ok)"),W.kpi("Scanned",res.scanned,"addresses in "+res.seconds+" s")));
  if(nNew)wrap.append(h("div",{class:"hintbox",style:"margin:0 0 16px"},nNew+" device"+(nNew>1?"s are":" is")+" not recognised yet. Phones often use a "+"randomised address for privacy, so 'unknown' is not always bad. If you know them all, press ‘Trust everything currently here’."));
  const rows=dev.map(d=>{const status=d.is_self?h("span",{class:"badge ac"},"THIS DEVICE"):d.is_gateway?h("span",{class:"badge ac"},"ROUTER"):d.known?h("span",{class:"badge ok"},"KNOWN · "+d.label):h("span",{class:"badge warn"},"NEW");
   const acts=h("div",{style:"display:flex;gap:6px"});
   if(d.mac&&!d.known&&!d.is_self&&!d.is_gateway)acts.append(h("button",{class:"btn sm",onclick:async e=>{const lab=prompt("Name this device (e.g. 'Mum's phone')",d.hostname||d.vendor||"");if(!lab)return;
     try{await W.post("/api/known",{mac:d.mac,label:lab});d.known=true;d.label=lab;W.toast("Saved","ok");area.replaceChildren(render(res))}catch(x){W.toast(x.message,"err")}}},"I know this"));
   acts.append(h("button",{class:"btn sm",onclick:()=>{S.pending.host=d.ip;location.hash="tool/ports"}},"Scan ports"));
   return h("tr",{class:d.known||d.is_self||d.is_gateway?"":"rg"},h("td",null,h("div",{class:"nm"},d.hostname||d.vendor||"Unknown device")),h("td",{class:"mono"},d.ip),
    h("td",null,h("div",{class:"mono"},d.mac||"-"),d.randomized?h("span",{class:"vend"},"randomised address"):null),h("td",null,d.vendor||"-"),h("td",null,status),h("td",null,acts))});
  wrap.append(table(["Device","Address","Hardware (MAC)","Made by","Status",""],rows,820));
  if(nNew)wrap.append(h("div",{class:"mf",style:"justify-content:flex-start"},h("button",{class:"btn",onclick:async()=>{for(const d of dev){if(d.mac&&!d.known&&!d.is_self&&!d.is_gateway){await W.post("/api/known",{mac:d.mac,label:d.hostname||d.vendor||"Device"});d.known=true;d.label=d.hostname||d.vendor||"Device"}}W.toast("All current devices trusted","ok");area.replaceChildren(render(res))}},ic("check",16),"Trust everything currently here")));
  wrap.append(h("div",{class:"cap"},"Only devices that answered are listed. Quiet devices (some phones asleep) may not appear every time."));return wrap}
 btn.onclick=()=>runInto(area,btn,"Knocking on every address… (about 10 seconds)",async()=>{const res=await W.tool("discover",{cidr:cidr.value.trim()});return render(res)});
 card.append(h("div",{class:"toolbar"},h("div",{class:"field",style:"margin:0;flex:1;min-width:240px"},h("label",null,"Network to scan"),cidr),btn),area);return card};

/* ------------------------------------------------------------------ 3. port scanner */
B.ports=()=>{const card=W.card("Port scanner","server","",0),host=h("input",{class:"in",placeholder:"192.168.1.1",value:S.pending.host||"",style:"max-width:240px"}),
 preset=h("select",{class:"in",style:"max-width:300px"},...[["quick","Quick - 15 most important ports"],["common","Common services - about 30 ports"],["web","Web only - 80, 443, 8080…"],["full","Every port 1-1024 (slower)"],["custom","Custom list…"]].map(([v,l])=>h("option",{value:v},l))),
 custom=h("input",{class:"in",placeholder:"22,80,8000-8100",style:"max-width:240px;display:none"}),btn=h("button",{class:"btn pri"},ic("search"),"Scan ports"),area=h("div",{style:"margin-top:22px"});
 delete S.pending.host;
 if(!host.value)W.tool("info",{}).then(i=>{if(!host.value&&i.gateway)host.value=i.gateway}).catch(()=>{});
 preset.onchange=()=>{custom.style.display=preset.value==="custom"?"":"none"};
 btn.onclick=()=>runInto(area,btn,"Trying ports on "+(host.value||"…")+"…",async()=>{const r=await W.tool("portscan",{host:host.value.trim(),ports:preset.value==="custom"?custom.value:preset.value});
  const col={critical:"#ff4d7d",high:"#e2574c",medium:"#e3b04b",low:"#7fa6d9",info:"#a7a293"},wrap=h("div");
  wrap.append(h("div",{class:"kpis"},W.kpi("Device",r.ip,r.host!==r.ip?r.host:""),W.kpi("Ports tried",r.scanned,r.seconds+" s"),W.kpi("Open",r.open.length,"",r.open.length?"var(--warn)":"var(--ok)")),h("div",{class:"explain",style:"margin:0 0 16px"},h("b",null,"Verdict"),r.verdict));
  wrap.append(r.open.length?table(["Port","Service","Risk","What it means","Banner"],r.open.map(o=>h("tr",null,h("td",{style:"font:600 20px Georgia,serif"},o.port),h("td",null,o.service),h("td",null,h("span",{class:"sev",style:"--c:"+col[o.level]},o.level)),h("td",{style:"white-space:normal;min-width:300px"},o.note),h("td",{class:"mono"},o.banner||"-"))),760):h("div",{class:"cap"},"No listening services found in that range."));
  const cveHits=r.open.flatMap(o=>(o.cves||[]).map(c=>({...c,port:o.port})));
  if(cveHits.length){wrap.append(h("div",{class:"lbl"},"Known vulnerabilities matched by version/banner"));
   cveHits.forEach(cv=>wrap.append(h("div",{class:"find",style:"--c:"+cveCol(cv.sev)},h("h5",null,W.sevpill(cv.sev),cv.title,cv.cve!=="general"?h("span",{class:"mono"},cv.cve):null,h("span",{class:"badge"},"port "+cv.port)),
    h("dl",null,h("dt",null,"Detail"),h("dd",null,cv.detail+(cv.detected_version?" (detected version "+cv.detected_version+")":"")),h("dt",null,"Fix"),h("dd",null,cv.fix)))));
   wrap.append(h("div",{class:"cap"},"Matched against a bundled reference (version "+(S.vulnVersion||"-")+") - not a live feed. Run ",h("code",null,"auditor.py vulndb refresh")," for the newest CVEs when you have internet access."))}
  wrap.append(h("div",{class:"cap"},"Only ",T("ports","open ports")," that answered are shown. Closed or filtered ports are invisible by design."));return wrap});
 card.append(h("div",{class:"toolbar",style:"align-items:flex-end"},h("div",{class:"field",style:"margin:0"},h("label",null,"Device address"),host),h("div",{class:"field",style:"margin:0"},h("label",null,"Which ports"),preset),h("div",{class:"field",style:"margin:0"},h("label",null,"\u00a0"),custom),btn),area);
 return card};

/* ------------------------------------------------------------------ 4. quality */
B.quality=()=>{const card=W.card("Connection quality","activity","",0),btn=h("button",{class:"btn pri"},ic("play"),"Run the test"),area=h("div",{style:"margin-top:22px"});
 btn.onclick=()=>runInto(area,btn,"Measuring (about 10 seconds)…",async()=>{const r=await W.tool("quality",{}),col={A:"var(--ok)",B:"var(--ok)",C:"var(--warn)",D:"var(--bad)",F:"var(--bad)"}[r.grade],wrap=h("div");
  wrap.append(h("div",{class:"verdict",style:"margin-bottom:22px"},h("div",{class:"big-grade",style:"--c:"+col},r.grade),h("div",null,h("h4",null,r.verdict),r.issues.length?h("ul",null,r.issues.map(i=>h("li",{style:"--c:var(--warn)"},i))):h("div",{class:"cap"},"No problems detected."))));
  wrap.append(table(["Target","Method","Replies","Average",T("latency","Best / worst",1),T("jitter","Jitter",1),T("loss","Lost",1)],r.results.map(x=>h("tr",null,h("td",null,h("b",null,x.name),h("div",{class:"mono"},x.host)),h("td",{class:"mono"},x.method),h("td",null,x.received+"/"+x.sent),
   h("td",{style:"font:600 20px Georgia,serif"},x.avg==null?"-":x.avg+" ms"),h("td",null,x.min==null?"-":x.min+" / "+x.max+" ms"),h("td",null,x.jitter+" ms"),h("td",null,h("span",{class:"badge "+(x.loss>=5?"bad":x.loss?"warn":"ok")},x.loss+"%")))),700));
  if(r.tips.length)wrap.append(h("div",{class:"lbl"},"What to try"),h("div",{class:"todo"},r.tips.map((t,i)=>h("div",{class:"todo-i",style:"--c:var(--gold);cursor:default"},h("div",{class:"n"},i+1),h("div",null,h("b",null,t))))));
  wrap.append(h("div",{class:"cap"},"Compare 'Your router' to the internet rows: if the router is slow, the problem is your Wi-Fi; if only the internet rows are slow, it is your provider."));return wrap});
 card.append(btn,area);return card};

/* ------------------------------------------------------------------ 5. internet & DNS */
B.internet=()=>{const card=W.card("Internet & DNS health","globe","",0),btn=h("button",{class:"btn pri"},ic("play"),"Check this network"),area=h("div",{style:"margin-top:22px"});
 btn.onclick=()=>runInto(area,btn,"Testing DNS, certificates and portals…",async()=>{const r=await W.tool("internet",{}),wrap=h("div"),bad=r.findings.some(f=>f.sev==="critical");
  wrap.append(h("div",{class:"explain",style:"margin:0 0 16px;border-color:"+(bad?"var(--rog)":"var(--gold)")},h("b",null,"Verdict"),r.verdict),...findings(r.findings));
  const d=r.dns;wrap.append(h("div",{class:"lbl"},"Internet & portal"),h("div",{class:"kpis"},W.kpi("Online",r.internet.online?"Yes":"No","",r.internet.online?"var(--ok)":"var(--bad)"),W.kpi("Captive portal",r.internet.captive_portal?"Detected":"None","",r.internet.captive_portal?"var(--warn)":"var(--ok)")));
  wrap.append(h("div",{class:"lbl"},"DNS (the internet's phone book)"),h("div",{class:"kpis"},W.kpi("DNS servers",d.servers.length?d.servers.join(", "):"unknown",""),W.kpi("Average lookup",d.avg_ms==null?"-":d.avg_ms+" ms","",d.avg_ms>200?"var(--warn)":""),W.kpi("Fake answers for bad names",d.nxdomain_hijack?"Yes":"No","",d.nxdomain_hijack?"var(--warn)":"var(--ok)"),W.kpi("Tampered known names",d.spoof_checks.length?"Yes":"No","",d.spoof_checks.length?"var(--bad)":"var(--ok)")));
  wrap.append(table(["Site","Lookup time","Result"],d.timings.map(t=>h("tr",null,h("td",null,t.name),h("td",null,t.ms+" ms"),h("td",null,h("span",{class:"badge "+(t.ok?"ok":"bad")},t.ok?"resolved":"failed")))),420));
  wrap.append(h("div",{class:"lbl"},"HTTPS certificates"),table(["Site","Result","Issued by"],r.tls.map(t=>h("tr",null,h("td",null,t.host),h("td",null,h("span",{class:"badge "+(t.ok?"ok":t.tampered?"bad":"warn")},t.ok?"genuine":t.tampered?"FAILED verification":"unreachable")),h("td",null,t.issuer||t.error||"-"))),520));
  wrap.append(h("div",{class:"cap"},"Why it matters: ",T("mitm","man-in-the-middle")," and ",T("dnshijack","DNS hijacking")," attacks are invisible unless you test for them."));return wrap});
 card.append(btn,area);return card};

/* ------------------------------------------------------------------ 6. ARP */
B.arp=()=>{const card=W.card("ARP spoof check","shield","",0),btn=h("button",{class:"btn pri"},ic("refresh"),"Re-check"),base=h("button",{class:"btn"},ic("check",16),"Save baseline (I trust this network)"),area=h("div",{style:"margin-top:22px"});
 const go=()=>runInto(area,btn,"Reading the ARP table…",async()=>{const r=await W.tool("arp",{}),bad=r.findings.some(f=>f.sev==="critical"),wrap=h("div");
  wrap.append(h("div",{class:"kpis"},W.kpi("Router",r.gateway||"-",r.gateway_mac||"hardware address unknown"),W.kpi("Saved baseline",r.baseline||"none",r.baseline?"compared each time":"press ‘Save baseline’"),W.kpi("Devices in table",r.entries.length,"")),
   h("div",{class:"explain",style:"margin:0 0 16px;border-color:"+(bad?"var(--rog)":"var(--gold)")},h("b",null,"Verdict"),r.verdict),...findings(r.findings));
  wrap.append(h("div",{class:"lbl"},"Address book (ARP table)"),table(["Address","Hardware","Made by",""],r.entries.map(e=>h("tr",null,h("td",{class:"mono"},e.ip),h("td",{class:"mono"},e.mac),h("td",null,e.vendor||"-"),h("td",null,e.is_gateway?h("span",{class:"badge ac"},"ROUTER"):null))),520),
   h("div",{class:"cap"},T("arpspoof","ARP spoofing")," shows up as your router's hardware address changing, or one device claiming several addresses."));return wrap});
 btn.onclick=go;base.onclick=async()=>{try{const r=await W.tool("arp-baseline",{});W.toast("Baseline saved: "+r.gateway+" = "+r.mac,"ok");go()}catch(e){W.toast(e.message+(e.hint?" - "+e.hint:""),"err")}};
 card.append(h("div",{class:"toolbar"},btn,base),area);go();return card};

/* ------------------------------------------------------------------ 7. saved profiles */
B.saved=()=>{const card=W.card("Saved Wi-Fi networks","lock","",0),btn=h("button",{class:"btn pri"},ic("play"),"Audit saved networks"),area=h("div",{style:"margin-top:22px"});
 btn.onclick=()=>runInto(area,btn,"Reading saved profiles (passwords are never read)…",async()=>{const r=await W.tool("saved",{}),col={high:"#e2574c",medium:"#e3b04b",ok:"#6fbf9a"},wrap=h("div");
  wrap.append(h("div",{class:"kpis"},W.kpi("Saved networks",r.profiles.length,""),W.kpi("Need attention",r.risky,"",r.risky?"var(--warn)":"var(--ok)"),W.kpi("Auto-connect to risky",r.profiles.filter(p=>p.risk==="high").length,"",r.profiles.some(p=>p.risk==="high")?"var(--bad)":"var(--ok)")));
  wrap.append(r.profiles.length?table(["Network","Security","Auto-connect","Verdict","Why / what to do"],r.profiles.map(p=>h("tr",null,h("td",null,h("b",null,p.name)),h("td",null,p.security),h("td",null,p.autoconnect?h("span",{class:"badge warn"},"yes"):"no"),
   h("td",null,h("span",{class:"sev",style:"--c:"+col[p.risk]},p.risk==="ok"?"fine":p.risk)),h("td",{style:"white-space:normal;min-width:320px"},p.note,p.fix?h("div",{class:"vend"},p.fix):null))),800):h("div",{class:"cap"},"No saved Wi-Fi networks found."));
  wrap.append(h("div",{class:"cap"},"Why it matters: a remembered ",T("open","open network")," name lets an attacker run an ",T("eviltwin","evil twin")," - your device joins it automatically."));return wrap});
 card.append(btn,area);return card};

/* ------------------------------------------------------------------ 8. info */
B.info=()=>{const card=W.card("Network info","list","",0),area=h("div");card.append(area);
 W.tool("info",{}).then(i=>{const row=(k,v,why)=>h("div",{style:"padding:14px 0;border-bottom:1px solid var(--line2);display:grid;grid-template-columns:200px 1fr;gap:6px 24px"},h("div",{class:"lbl",style:"margin:2px 0"},k),h("div",null,h("b",{style:"font:600 22px Georgia,serif"},v||"-"),h("div",{class:"note",style:"margin:2px 0 0"},why)));
  area.replaceChildren(row("Your address",i.ip,"Your device's address on this network."),row("Network range",i.cidr,"Every device on the network shares this range. Subnet mask "+i.netmask+"."),
   row("Router (gateway)",i.gateway,"The device that connects you to the internet."),row("DNS servers",(i.dns||[]).join(", "),"The phone book that turns names into addresses."),
   row("Adapter",i.iface||"-","The network card in use."),row("This computer",i.hostname+(i.mac?" · "+i.mac:""),"How other devices see you."),
   row("IPv6",i.ipv6_global&&i.ipv6_global.length?i.ipv6_global.join(", "):"None detected",i.ipv6_internet?"IPv6 internet access is working.":(i.ipv6&&i.ipv6.length?"Link-local only - no IPv6 internet access.":"This network may not offer IPv6, or it is disabled.")))}).catch(e=>area.replaceChildren(errBox(e)));
 return card};

/* ------------------------------------------------------------------ 9. passphrase tester (runs entirely in the browser) */
const COMMON=["password","12345678","123456789","qwerty","iloveyou","admin","welcome","letmein","wifi","internet","11111111","abc123","passw0rd","football","monkey","dragon","sunshine","princess","master","login","router","default","changeme","guest"];
W.analyzePass=function(pw){const len=pw.length;let pool=0;if(/[a-z]/.test(pw))pool+=26;if(/[A-Z]/.test(pw))pool+=26;if(/\d/.test(pw))pool+=10;if(/[^A-Za-z0-9]/.test(pw))pool+=33;
 let bits=len*Math.log2(Math.max(pool,1));const issues=[],lower=pw.toLowerCase();
 const hit=COMMON.find(c=>lower.includes(c));if(hit){bits=Math.min(bits,22);issues.push("Contains the very common word or pattern “"+hit+"” - attackers try these first.")}
 if(/^(.)\1+$/.test(pw)){bits=Math.min(bits,6);issues.push("One character repeated.")}
 if(/^\d+$/.test(pw)){bits=Math.min(bits,len*3.32);issues.push("Digits only - very few combinations.")}
 if(/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|zxcv)/i.test(pw)){bits-=12;issues.push("Contains a keyboard or number sequence.")}
 if(/(.{2,})\1/.test(pw)){bits-=6;issues.push("Contains repeated chunks.")}
 if(/^[a-z]+$/i.test(pw)&&len<14){bits*=.65;issues.push("Letters only, which is easy to guess from word lists.")}
 if(len>0&&len<8)issues.push("Shorter than 8 characters - Wi-Fi (WPA2/WPA3) requires at least 8.");
 if(len>63)issues.push("Longer than 63 characters - WPA2 does not accept that.");
 bits=Math.max(0,bits);const secs=Math.pow(2,bits)/2/1e6;
 const fmt=s=>s<1?"instantly":s<60?Math.round(s)+" seconds":s<3600?Math.round(s/60)+" minutes":s<86400?Math.round(s/3600)+" hours":s<31536000?Math.round(s/86400)+" days":s<3.15e9?Math.round(s/31536000).toLocaleString()+" years":"longer than the age of civilisation";
 const level=bits<28?0:bits<40?1:bits<60?2:bits<80?3:4;
 return {bits:Math.round(bits),time:fmt(secs),level,label:["Very weak","Weak","Fair","Strong","Excellent"][level],issues}};
B.pass=()=>{const card=W.card("Passphrase tester","key","",0),inp=h("input",{class:"in pwin",type:"password",placeholder:"Type or paste a password to test",autocomplete:"off",spellcheck:"false",style:"max-width:520px"}),
 show=h("button",{class:"btn",onclick:()=>{inp.type=inp.type==="password"?"text":"password";show.textContent=inp.type==="password"?"Show":"Hide"}},"Show"),out=h("div",{style:"margin-top:20px"});
 function paint(){const pw=inp.value;if(!pw){out.replaceChildren(h("div",{class:"cap"},"Nothing is sent anywhere: this runs entirely in your browser."));return}
  const a=W.analyzePass(pw),cols=["var(--bad)","var(--bad)","var(--warn)","var(--ok)","var(--ok)"],c=cols[a.level];
  out.replaceChildren(h("div",{class:"strength"},[0,1,2,3,4].map(i=>h("i",{style:i<=a.level?"background:"+c:""}))),
   h("div",{class:"kpis"},W.kpi("Strength",a.label,"about "+a.bits+" bits",c),W.kpi("Time to crack",a.time,"offline, 1 million guesses/s (powerful GPU vs WPA2)"),W.kpi("Length",pw.length,"characters")),
   a.issues.length?h("div",null,...a.issues.map(i=>h("div",{class:"find",style:"--c:var(--warn)"},h("h5",null,i)))):h("div",{class:"find",style:"--c:var(--ok)"},h("h5",null,"No obvious patterns found")),
   h("div",{class:"explain",style:"margin-top:14px"},h("b",null,"A good Wi-Fi password"),"Use four or more random words, for example ‘copper-lantern-orbit-maple’: 20+ characters, easy to type, and far stronger than a short mix of symbols. Never reuse a password from another account."))}
 inp.addEventListener("input",paint);card.append(h("div",{class:"toolbar"},inp,show),out);paint();return card};

/* ------------------------------------------------------------------ 10. MAC lookup */
B.mac=()=>{const card=W.card("Address & vendor lookup","search","",0),inp=h("input",{class:"in",placeholder:"00:14:6C:5D:E1:90",style:"max-width:300px"}),btn=h("button",{class:"btn pri"},"Look up"),out=h("div",{style:"margin-top:20px"});
 const go=async()=>{try{const r=await W.tool("mac",{mac:inp.value});out.replaceChildren(h("div",{class:"kpis"},W.kpi("Address",r.mac,""),W.kpi("Made by",r.vendor,""),W.kpi("Randomised",r.locally_administered?"Yes":"No","",r.locally_administered?"var(--warn)":"var(--ok)")),h("div",{class:"cap"},r.note))}catch(e){out.replaceChildren(errBox(e))}};
 btn.onclick=go;inp.addEventListener("keydown",e=>{if(e.key==="Enter")go()});card.append(h("div",{class:"toolbar"},inp,btn),out,h("div",{class:"cap"},"Learn about ",T("mac","MAC addresses")," and ",T("oui","vendor lookups"),"."));return card};

/* ------------------------------------------------------------------ 14. speed test */
B.speedtest=()=>{const card=W.card("Speed test","zap","",0),btn=h("button",{class:"btn pri"},ic("play"),"Run speed test"),area=h("div",{style:"margin-top:22px"});
 btn.onclick=()=>runInto(area,btn,"Downloading a test file (a few seconds)…",async()=>{const r=await W.tool("speedtest",{});
  const col=r.mbps>=100?"var(--ok)":r.mbps>=25?"var(--ok)":r.mbps>=5?"var(--warn)":"var(--bad)",wrap=h("div");
  wrap.append(h("div",{class:"kpis"},W.kpi("Download speed",r.mbps+" Mbps",r.rating,col),W.kpi("Server",r.server,""),W.kpi("Data transferred",r.mb_transferred+" MB",r.seconds+" s")));
  wrap.append(h("div",{class:"cap"},r.note));return wrap});
 card.append(btn,area,h("div",{class:"cap",style:"margin-top:14px"},"Needs an internet connection. Results can vary with server load, time of day and what else is using your network."));return card};

/* ------------------------------------------------------------------ 15. coverage map */
B.coverage=()=>{const card=W.card("Coverage map","map","",0);
 const locSel=h("select",{class:"in",style:"max-width:220px"}),newLoc=h("input",{class:"in",placeholder:"New location name, e.g. Home",style:"max-width:220px"}),
  addLoc=h("button",{class:"btn"},ic("plus"),"Add"),clearBtn=h("button",{class:"btn ghost sm danger"},ic("trash",14),"Clear this map"),
  grid=h("div",{style:"position:relative;width:100%;max-width:640px;aspect-ratio:16/10;border:1px solid var(--line3);background:repeating-linear-gradient(0deg,rgba(201,164,92,.07) 0 1px,transparent 1px 40px),repeating-linear-gradient(90deg,rgba(201,164,92,.07) 0 1px,transparent 1px 40px);cursor:crosshair;margin:16px 0"}),
  stats=h("div"),hint=h("div",{class:"explain"},h("b",null,"How to use it"),"Pick or add a location, stand somewhere, read the signal shown below, then click that spot on the grid below to drop a marker. Walk to the next spot and repeat. Click a marker to remove it.");
 let curLoc="";
 function dot(x,y,dbm,id){const col=dbm>=-60?"#6fbf9a":dbm>=-75?"#e3b04b":"#e2574c";
  return h("div",{style:"position:absolute;left:"+(x*100)+"%;top:"+(y*100)+"%;transform:translate(-50%,-50%);width:26px;height:26px;border-radius:50%;background:"+col+";border:2px solid #0b0d12;box-shadow:0 0 10px "+col+";cursor:pointer;display:grid;place-items:center;font:700 10px sans-serif;color:#0b0d12",title:dbm+" dBm",onclick:async e=>{e.stopPropagation();if(id){await W.api("/api/coverage/"+encodeURIComponent(curLoc)+"/"+id,{method:"DELETE"});paintGrid()}}},dbm)}
 async function paintGrid(){const r=await W.api("/api/coverage/"+encodeURIComponent(curLoc));grid.replaceChildren(...r.points.map(p=>dot(p.x,p.y,p.dbm,p.id)));
  const s=r.summary;stats.replaceChildren(s.count?h("div",{class:"kpis"},W.kpi("Points logged",s.count,""),W.kpi("Average signal",s.avg_dbm+" dBm",""),W.kpi("Weak spots",s.weak_pct+"%",s.weak_spots+" point(s) under -75 dBm",s.weak_pct>30?"var(--bad)":s.weak_pct>0?"var(--warn)":"var(--ok)")):h("div",{class:"cap"},"No points yet - click the grid below after reading your signal."));
  const opt=[...locSel.options].find(o=>o.value===curLoc);if(opt)opt.textContent=curLoc+" ("+r.points.length+" points)";
  return r.points.length}
 async function paintLocs(keep){const locs=await W.api("/api/coverage/locations");const names=locs.map(l=>l.location);
  if(keep&&!names.includes(keep))names.unshift(keep);                 // a just-added, still-empty location has no points yet
  locSel.replaceChildren(...names.map(n=>{const found=locs.find(l=>l.location===n);return h("option",{value:n},n+(found?" ("+found.n+" points)":" (new)"))}));
  curLoc=keep||curLoc||names[0]||"";if(curLoc)locSel.value=curLoc;if(curLoc)paintGrid();else stats.replaceChildren(h("div",{class:"cap"},"Add a location name above to start."))}
 locSel.onchange=()=>{curLoc=locSel.value;paintGrid()};
 addLoc.onclick=()=>{const n=newLoc.value.trim();if(!n)return;newLoc.value="";paintLocs(n)};
 clearBtn.onclick=async()=>{if(!curLoc||!confirm("Clear all points for '"+curLoc+"'?"))return;const kept=curLoc;await W.api("/api/coverage/"+encodeURIComponent(curLoc),{method:"DELETE"});paintLocs(kept)};
 let busy=false;
 grid.onclick=async e=>{if(!curLoc){W.toast("Add a location name first","warn");return}if(busy)return;busy=true;grid.style.opacity=".6";
  const rect=grid.getBoundingClientRect(),x=(e.clientX-rect.left)/rect.width,y=(e.clientY-rect.top)/rect.height;
  try{let dbm=null;
   try{const link=await W.tool("link",{});dbm=link.connected?link.signal_dbm:null}catch(_){}      // always read fresh - this is the whole point of walking to a new spot
   if(dbm==null){W.toast("Not connected to Wi-Fi right now","warn");return}
   await W.api("/api/coverage/"+encodeURIComponent(curLoc),{method:"POST",body:JSON.stringify({x,y,dbm})});await paintGrid()}
  finally{busy=false;grid.style.opacity="1"}};
 card.append(hint,h("div",{class:"toolbar"},locSel,newLoc,addLoc,clearBtn),grid,stats);paintLocs();return card};

/* ------------------------------------------------------------------ 16. guest network check */
B.guestcheck=()=>{const card=W.card("Guest network check","shield","",0),btn=h("button",{class:"btn pri"},ic("play"),"Check this network"),area=h("div",{style:"margin-top:22px"});
 btn.onclick=()=>runInto(area,btn,"Looking at what else is reachable from here…",async()=>{const r=await W.tool("guestcheck",{});const col={ok:"var(--ok)",medium:"var(--warn)",high:"var(--bad)"}[r.risk],wrap=h("div");
  wrap.append(h("div",{class:"kpis"},W.kpi("Network name",r.ssid||"-",r.looks_like_guest_name?"looks like a guest network":"doesn't look like a guest name"),W.kpi("Other devices reachable",r.reachable_other_devices,"",col)),
   h("div",{class:"explain",style:"margin:0 0 16px;border-color:"+col},h("b",null,"Verdict"),r.verdict));
  if(r.devices.length)wrap.append(table(["Address","Hardware","Made by"],r.devices.map(d=>h("tr",null,h("td",{class:"mono"},d.ip),h("td",{class:"mono"},d.mac||"-"),h("td",null,d.vendor||"-"))),460));
  wrap.append(h("div",{class:"cap"},r.note));return wrap});
 card.append(btn,area);return card};

/* ------------------------------------------------------------------ 17. my network activity */
B.activity=()=>{const card=W.card("My network activity","activity","",0),out=h("div");card.append(out);
 const CATCOL={"Web (encrypted)":"var(--ok)","Web (unencrypted)":"var(--warn)","Email":"var(--ac)","DNS":"var(--ac)","File transfer":"var(--warn)","Remote access":"var(--bad)","Streaming/media":"var(--ac)","Database":"var(--warn)","Peer-to-peer":"var(--warn)","Other":"var(--mut)"};
 (async()=>{try{const r=await W.tool("activity",{});
   const wrap=h("div");wrap.append(h("div",{class:"kpis"},W.kpi("Active connections",r.total,""),...Object.entries(r.by_category).slice(0,3).map(([k,v])=>W.kpi(k,v,"",CATCOL[k]))));
   wrap.append(r.connections.length?table(["Category","Talking to","State"],r.connections.map(c=>h("tr",null,h("td",null,h("span",{class:"badge",style:"color:"+CATCOL[c.category]+";border-color:"+CATCOL[c.category]},c.category)),h("td",{class:"mono"},c.remote+":"+c.remote_port),h("td",null,c.state))),520):h("div",{class:"cap"},"No active connections to outside addresses right now."));
   wrap.append(h("div",{class:"cap"},r.note));out.replaceChildren(wrap)}catch(e){out.replaceChildren(errBox(e))}})();
 return card};

function toolView(id){const def=DEF[id];if(!def)return hub();return shell(def,B[id]())}
W.views.tools=hub;W.views.tool=()=>toolView(S.arg);
W.toolDef=id=>DEF[id];
})(WA);
