#!/usr/bin/env node
/*
 * Palisade security regression gate  (node 22+, no external packages)
 * ------------------------------------------------------------------
 * The functional gate (harness.mjs + check-frozen.mjs) proves the demo dataset still yields the
 * same evidence numbers. It does not exercise a single security control: every 2.8 fix could be
 * reverted with it green (docs/SECURITY-AUDIT-2.9.md, finding G4). This gate does. It drives Chromium over the
 * DevTools protocol against a real file:// URL -- CSP enforced, Page.setBypassCSP never sent --
 * feeds the page SYNTHETIC hostile inputs through the same entry points the drop zone and the
 * file pickers use, and asserts the outcome.
 *
 * The inputs are markup canaries (an element carrying data-pal-canary), prototype-named keys,
 * formula prefixes, oversized lines and malformed archives. None is a working exploit: a canary
 * proves markup was created, which is the defect, without carrying a payload. All hostnames are
 * invented; all addresses are RFC 5737 documentation addresses.
 *
 *   node baseline/security-gate.mjs "file://$PWD/palisade.html" [outDir]
 *
 * Exits 0 only if every check passes. Writes <outDir>/security-gate.json when outDir is given.
 * Run against v2.8 it is the negative control: the first prototype-key input breaks that page,
 * and the checks recorded up to that point are reported with the error.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const TARGET_URL = process.argv[2];
const OUT_DIR = process.argv[3] ? path.resolve(process.argv[3]) : null;
if (!TARGET_URL) { console.error('usage: node security-gate.mjs <file-url> [outDir]'); process.exit(2); }
const CHROMIUM = process.env.CHROMIUM || '/usr/bin/chromium';
const sleep = ms => new Promise(r => setTimeout(r, ms));

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl); this.id = 0; this.pending = new Map(); this.listeners = [];
    this.ready = new Promise((res, rej) => { this.ws.addEventListener('open', () => res()); this.ws.addEventListener('error', () => rej(new Error('ws error'))); });
    this.ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) { const { res, rej } = this.pending.get(msg.id); this.pending.delete(msg.id); msg.error ? rej(new Error(JSON.stringify(msg.error))) : res(msg.result); }
      else if (msg.method) for (const l of this.listeners) l(msg.method, msg.params, msg.sessionId);
    });
  }
  on(fn) { this.listeners.push(fn); }
  send(method, params = {}, sessionId) { const id = ++this.id; const p = { id, method, params }; if (sessionId) p.sessionId = sessionId; return new Promise((res, rej) => { this.pending.set(id, { res, rej }); this.ws.send(JSON.stringify(p)); }); }
  close() { try { this.ws.close(); } catch {} }
}

/* Everything below runs INSIDE the page, as an async function body, and returns the results. */
const SUITE = String.raw`
const T0=performance.now();
const ok=(name,pass,detail)=>R.push({name,pass:!!pass,detail:detail===undefined?"":String(detail).slice(0,300)});
const protoKeys=()=>Object.getOwnPropertyNames(Object.prototype).length;
const P0=protoKeys(), OBJ0=Object.getOwnPropertyNames(Object).length;
const canaries=root=>(root||document).querySelectorAll("[data-pal-canary]").length;
const reset=()=>{ S=newState(); invalidateFusion(); if(typeof _remedyCache!=="undefined"&&_remedyCache.clear) _remedyCache.clear(); try{renderAll();}catch(e){} };
const X=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const nessus=hosts=>'<?xml version="1.0" ?><NessusClientData_v2><Report name="t">'+hosts.map(h=>
  '<ReportHost name="'+X(h.ip)+'"><HostProperties>'
  +(h.nb!==undefined?'<tag name="netbios-name">'+h.nb+'</tag>':'')
  +'<tag name="host-ip">'+X(h.ip)+'</tag>'+(h.mac?'<tag name="mac-address">'+X(h.mac)+'</tag>':'')
  +(h.os?'<tag name="operating-system">'+h.os+'</tag>':'')+(h.end?'<tag name="HOST_END">'+X(h.end)+'</tag>':'')
  +'</HostProperties>'+(h.items||[]).map(i=>'<ReportItem port="'+(i.port||0)+'" svc_name="'+X(i.svc||"general")+'" protocol="'+(i.protoRaw!==undefined?i.protoRaw:X(i.proto||"tcp"))
  +'" severity="'+(i.sev||0)+'" pluginID="'+X(i.pid)+'" pluginName="'+(i.pnameRaw!==undefined?i.pnameRaw:X(i.pname||"p"))+'" pluginFamily="'+X(i.family||"General")+'">'
  +(i.out!==undefined?'<plugin_output>'+X(i.out)+'</plugin_output>':'')
  +(i.solution?'<solution>'+X(i.solution)+'</solution>':'')
  +(i.patch?'<patch_publication_date>'+X(i.patch)+'</patch_publication_date>':'')
  +(i.cves||[]).map(c=>'<cve>'+c+'</cve>').join("")+'</ReportItem>').join("")+'</ReportHost>').join("")+'</Report></NessusClientData_v2>';
const F=(t,n)=>new File([t],n);
const cap=fn=>{DL_CAPTURE=[]; try{fn();}finally{}; const o=DL_CAPTURE; DL_CAPTURE=null; return o;};
const sessionOf=extra=>JSON.stringify(Object.assign({meta:{tool:"Palisade",ver:"2.9",saved:"2026-08-01T00:00:00Z"},config:JSON.parse(JSON.stringify(DEFAULT_CONFIG))},extra));
const timed=async fn=>{const t=performance.now(); await fn(); return performance.now()-t;};
/* RFC 4180 reader that, like Excel/LibreOffice/Python csv, ends a record at a bare CR */
const csvParse=t=>{const rows=[];let row=[],f="",q=false;for(let i=0;i<t.length;i++){const c=t[i];
  if(q){if(c==='"'){if(t[i+1]==='"'){f+='"';i++;}else q=false;}else f+=c;}
  else if(c==='"')q=true; else if(c===','){row.push(f);f="";}
  else if(c==='\r'||c==='\n'){row.push(f);rows.push(row);row=[];f="";if(c==='\r'&&t[i+1]==='\n')i++;}
  else f+=c;} if(f!==""||row.length){row.push(f);rows.push(row);} return rows;};

/* ---------- 0. the policy is in force ---------- */
{ const m=document.querySelectorAll('meta[http-equiv="Content-Security-Policy" i]');
  const inHead=[...m].filter(x=>x.parentNode===document.head);
  ok("policy: exactly one CSP <meta>, inside <head>", m.length===1&&inHead.length===1, m.length+" found, "+inHead.length+" in head");
  const pol=(inHead[0]&&inHead[0].content)||"";
  ok("policy: default/connect/img/object/frame/base/form all 'none'", ["default-src 'none'","connect-src 'none'","img-src 'none'","object-src 'none'","frame-src 'none'","base-uri 'none'","form-action 'none'"].every(d=>pol.includes(d))&&!/script-src-(?:elem|attr)/.test(pol)&&!/'unsafe-(?:inline|eval|hashes)'/.test(pol.replace(/style-src[^;]*/,"")), pol.slice(0,140));
  const seen=[]; const h=e=>seen.push(e.effectiveDirective||e.violatedDirective);
  document.addEventListener("securitypolicyviolation",h);
  try{ setTimeout("window.__pal_eval_canary=1",0); }catch(e){}
  await new Promise(r=>setTimeout(r,250));
  document.removeEventListener("securitypolicyviolation",h);
  ok("policy: enforced (string timer refused, positive control)", window.__pal_eval_canary===undefined&&seen.some(d=>/script-src/.test(d)), JSON.stringify(seen));
}
ok("static body: CUI opt-ins unchecked at load", ["pkgInclSession","aiInclHosts","rptHosts"].every(id=>!$(id)||!$(id).checked));

/* ---------- 1. prototype-named keys from scan files ---------- */
reset();
await ingestFiles([F(nessus([{nb:"WS-PROTO",ip:"192.0.2.21",os:"Microsoft Windows 10",items:[
  {pid:"__proto__",pname:"Proto plugin",sev:3,port:445,family:"Windows"},
  {pid:"constructor",pname:"Ctor plugin",sev:4,port:445},
  {pid:"20811",pname:"Microsoft Windows Installed Software Enumeration (credentialed check)",sev:0,out:"The following software are installed on the remote host :\n\nconstructor  [version 1.0]\n__proto__  [version 2.0]\ntoString  [version 3.0]\nConstructor 2.0  [version 2.0]\nVLC media player  [version 3.0.20]"}]}]),"proto.nessus")]);
ok("pluginID / DisplayName '__proto__': Object.prototype untouched", protoKeys()===P0&&({}).sev===undefined&&({}).ports===undefined, protoKeys()+" vs "+P0);
ok("pluginID 'constructor': Object untouched, finding kept", Object.getOwnPropertyNames(Object).length===OBJ0&&!!(S.hosts["WS-PROTO"]&&Object.prototype.hasOwnProperty.call(S.hosts["WS-PROTO"].findings,"constructor")));
ok("DisplayName 'constructor' etc.: ingest completed (assets built)", !!S.assets["WS-PROTO"]&&Object.keys(S.software).some(k=>/^constructor\|/.test(k)), Object.keys(S.assets).join(","));
await ingestFiles([F(nessus([{nb:"WS-AFTER",ip:"192.0.2.22",items:[{pid:"10001",pname:"x",sev:1,port:22}]}]),"after.nessus")]);
ok("a later clean ingest still works", !!S.assets["WS-AFTER"]);
{ const sv=cap(()=>saveSession())[0]; let reloaded=false;
  reset(); await loadSession(F(sv.text,"s.json")); reloaded=!!S.hosts["WS-PROTO"]&&!!S.hosts["WS-AFTER"];
  ok("session saved after hostile names reloads", reloaded, Object.keys(S.hosts).join(",")); }
reset();
await ingestFiles([F('Plugin ID,Name,Risk,IP Address,Port,Protocol\n70001,__proto__,Medium,192.0.2.23,443,tcp\n','proto.csv')]);
try{renderAll();}catch(e){}
ok("CSV plugin Name '__proto__': no pollution, renders", protoKeys()===P0&&vulnGroups().length>=1);

/* ---------- 2. markup from scan and session values ---------- */
reset();
await ingestFiles([F(nessus([{nb:"WS-DRAWER",ip:"192.0.2.24",items:[{pid:"11011",pname:"SMB",sev:0,port:445,protoRaw:'tcp&lt;b data-pal-canary=1&gt;x&lt;/b&gt;&lt;style&gt;#parseWarnings{display:none}&lt;/style&gt;'}]}]),"drawer.nessus")]);
openHostDetail(Object.keys(S.hosts)[0]);
ok("protocol attribute: no markup in the asset drawer", canaries()===0&&!document.querySelector("#hostDrawerBody style"), canaries());
closeHostDetail();
const C='<b data-pal-canary=1>c</b><style>#statusbar{display:none}</style>';
reset();
await loadSession(F(sessionOf({
  hosts:{"WS-S1":{key:"WS-S1",name:"WS-S1",ip:"192.0.2.25",os:"Windows",blob:"",sw:[],ports:{"tcp/443":{proto:"tcp",port:"443",svc:"",evidence:[]}},findings:{"1":{id:"1",name:"F",sev:"4",cvss:"9.1",cves:[],ports:[]}}}},
  ppsm:{"tcp/443":{proto:"tcp",port:"443"+C,svc:"",app:"",include:true,boundaries:[],hosts:["WS-S1"],srcIp:"",dstIp:"",notes:""}},
  trend:[{taken:"2026-06-01",label:"a",stats:{hosts:C,crit:C,high:1,catI:C,stigScore:C,overdue:1,eol:0,stigOpen:2}},{taken:"2026-07-01",label:"b",stats:{hosts:1,crit:"1e999",high:2,catI:0,stigScore:50,overdue:0,eol:0,stigOpen:1}}],
  listings:{hw:[],sw:[],files:[{name:"l.csv",rows:C,hw:C,sw:0,skipped:0,kindSource:"x",matched:[],ignored:[]}],conflicts:[]},
  intel:{rows:{},files:[{name:"i.csv",rows:C,cveRows:0,noCve:0,matched:[],ignored:[]}],scoreSource:"blended"},
  stigResults:{"WS-S1":{"T|1":{title:"T",version:"1",release:"",source:"",when:"",rules:[{ruleId:"r",vid:"V-1",status:'<!-- '+C,severity:"high"}]}}},
  software:{"W|1":{name:"W",version:"1",hosts:["WS-S1"],include:true,approval:"Authorized"},"W|":{name:"W",version:"",hosts:{length:C},include:false,rpm:true,approval:"Not Reviewed"},"W|2":{name:"W",version:"2",hosts:["WS-S1"],include:true,approval:"Approved"}}
}),"hostile-session.json"));
document.querySelectorAll(".tabpane").forEach(p=>p.classList.add("active"));
setScView("rules"); renderTrend(); renderListings(); renderIntel(); renderSoftware();
ok("session values: no markup anywhere in the app", canaries()===0, canaries());
document.querySelectorAll(".tabpane").forEach(p=>p.classList.remove("active")); setScView("summary"); gotoTab("overview");
{ const html=buildReport(RPT_SECTIONS.map(x=>x.id),{cap:40,hosts:true});
  const doc=new DOMParser().parseFromString(html,"text/html");
  ok("session values: no markup in the exported report", canaries(doc)===0&&!doc.querySelector("body style,meta[http-equiv=refresh]"), canaries(doc)); }
ok("session values: types coerced (sev, cvss, approval, Infinity)", S.hosts["WS-S1"].findings["1"].sev===4&&S.hosts["WS-S1"].findings["1"].cvss===9.1&&S.software["W|1"].approval==="Not Reviewed"&&S.trend[1].stats.crit===null);

/* ---------- 3. session shape: [] where a map belongs ---------- */
reset();
await loadSession(F(sessionOf({hosts:{"WS-A":{key:"WS-A",name:"WS-A",ip:"192.0.2.26",sw:[{n:"Tool",v:"1"}],ports:{},findings:{}}},software:[],assets:[],stig:{overrides:[],device:[],comments:[]}}),"arr.json"));
{ const k=Object.keys(S.software)[0]; if(k) setApproval(k,"Denied"); toggleStig("WS-A",S.config.catalog[0].name);
  const j=JSON.parse(cap(()=>saveSession())[0].text);
  ok("array-shaped maps: edits survive Save session", !Array.isArray(j.software)&&k&&j.software[k]&&j.software[k].approval==="Denied"&&j.stig.overrides["WS-A"], k); }

/* ---------- 4. transactional loads ---------- */
reset(); loadDemoData();
{ const before=Object.keys(S.hosts).sort().join(","), st=S;
  await loadBaseline(F(sessionOf({hosts:{"EVIL":{key:"EVIL",name:"EVIL",sw:5}},config:{columns:[{name:"x",patterns:[]}]}}),"bad-baseline.json"));
  ok("bad / legacy baseline never replaces the working dataset", S===st&&Object.keys(S.hosts).sort().join(",")===before, Object.keys(S.hosts).join(","));
  await loadBaseline(F('{"taken":"2026-06-30T00:00:00Z","hosts":{}}',"raw.json"));
  let threw=false; try{renderAll();}catch(e){threw=true;}
  ok("malformed raw snapshot is refused, not stored", S.baseline===null||!threw, String(threw)); }
{ const f1=getIntelFusion(); const keep=S; S=newState(); const f2=getIntelFusion(); S=keep;
  ok("fusion cache is bound to its state object", getIntelFusion()!==f2&&f1!==f2); }
{ const before=JSON.stringify(S.config.deviceRules), keep=S.config;
  $("cfgBox").value=JSON.stringify({catalog:[null,{name:"X",patterns:["re:(?:(.+))+$"]}],deviceRules:[{prefix:"K-"}]});
  applyConfig();
  ok("applyConfig: hostile config normalised or rolled back, detection still runs", Array.isArray(S.config.deviceRules)&&(()=>{try{runDetection();return true;}catch(e){return false;}})()); }

/* ---------- 5. CSV / TSV exports ---------- */
reset();
await ingestFiles([F(nessus([{nb:"WS-01&#13;FAKE-ROW",ip:"192.0.2.27",os:"Microsoft Windows 10",items:[{pid:"11011",pname:"SMB",sev:0,port:445}]}]),"cr.nessus")]);
{ const out=cap(()=>{exportSTIG();exportIpSummary();});
  const leaked=out.some(o=>csvParse(o.text).some(r=>r[0]==="FAKE-ROW"||r[0].startsWith("FAKE-ROW")));
  ok("bare CR in a hostname cannot fabricate a CSV row", !leaked); }
await loadProfile(F(JSON.stringify({meta:{kind:"Compliance-Compiler-Profile"},settings:{banner:"=1+1\n@SUM(1)",boundaryDefaults:["B1"]},config:JSON.parse(JSON.stringify(DEFAULT_CONFIG))}),"p.json"));
rebuildPPSMFromHosts();
{ const st=cap(()=>exportSTIG())[0].text, pp=cap(()=>exportPPSM())[0].text;
  const first=csvParse(st)[0][0], ppl=pp.split("\n");
  ok("banner from a profile is neutralised in the STIG CSV and the PPSM registry", !/^[=@+\-]/.test(first)&&!/^[=@+\-]/.test(ppl[0]), JSON.stringify(first)+" | "+JSON.stringify(ppl[0]));
  const hdr=PPSM_HEADERS.length, row=ppl.find(l=>/\t445\t/.test(l));
  ok("PPSM registry rows have exactly as many cells as the header", row&&row.split("\t").length===hdr, row?row.split("\t").length+" vs "+hdr:"no row"); }

/* ---------- 6. HW/SW listings ---------- */
reset();
await ingestFiles([F("Hostname,Software,Version,Approval Status\nWS-L,AppA,1,Unapproved\nWS-L,AppB,1,Not Authorized\nWS-L,AppC,1,Disapproved\nWS-L,AppD,1,Never approved\nWS-L,AppE,1,Approved\nWS-L,AppF,1,Fully vetted\n","sw-listing.csv")]);
{ const ap=n=>{const k=Object.keys(S.software).find(k=>S.software[k].name===n);return k&&S.software[k].approval;};
  ok("listing approval wording: negations are Denied, unknown left Not Reviewed", ["AppA","AppB","AppC","AppD"].every(n=>ap(n)==="Denied")&&ap("AppE")==="Approved"&&ap("AppF")==="Not Reviewed", ["AppA","AppB","AppC","AppD","AppE","AppF"].map(ap).join(",")); }
reset();
await ingestFiles([F("Device,IP Address,Manufacturer,Model,Serial Number,Location\nCORE-SW,192.0.2.30,Cisco,C9300,FOC1,Rm 1\n","hw-listing.csv")]);
ok("listing with no hostname column is not minted as scan hosts", Object.keys(S.hosts).length===0&&/not recognized/.test($("parseWarnings").textContent));

/* ---------- 7. ReDoS on built-in parsers (time budget per input) ---------- */
reset();
{ const swLine="["+"[1".repeat(100)+"1".repeat(20000);
  const t1=await timed(()=>ingestFiles([F(nessus([{nb:"WS-R1",ip:"192.0.2.31",items:[{pid:"20811",pname:"Software Enumeration",sev:0,out:"The following software are installed :\n"+swLine}]}]),"r1.nessus")]));
  const t2=await timed(()=>ingestFiles([F(nessus([{nb:"WS-R2",ip:"192.0.2.32",items:[{pid:"19506",pname:"Nessus Scan Information",sev:0,out:"Scan name : x"+" ".repeat(200000)+"y"}]}]),"r2.nessus")]));
  const t3=await timed(()=>ingestFiles([F(nessus([{nb:"WS-R3",ip:"192.0.2.33",items:[{pid:"10860",pname:"Microsoft Windows SMB Use Host SID to Enumerate Local Users",sev:0,out:"a"+" ".repeat(20000)+"b"}]}]),"r3.nessus")]));
  const t4=await timed(async()=>{await ingestFiles([F(nessus([{nb:"WS-R4",ip:"192.0.2.34",items:[{pid:"99",pname:"-".repeat(150000)+"x",sev:3,port:80}]}]),"r4.nessus")]); renderAll();});
  ok("ReDoS: built-in parsers finish under 4 s each on hostile lines", Math.max(t1,t2,t3,t4)<4000, [t1,t2,t3,t4].map(x=>Math.round(x)).join(" / ")+" ms"); }
{ const bypass=["(a+)+$","(?:(a+))+$","(a{1,})+$","(a{1,}){1,}$","(a|aa)+$","(?:(.+))+$","([^\\n]{1,})+$","((ab)+)+$"];
  const builtins=[]; const add=p=>{if(/^re:/i.test(String(p)))builtins.push(String(p).slice(3));};
  DEFAULT_CONFIG.catalog.forEach(c=>{(c.patterns||[]).forEach(add);(c.osPatterns||[]).forEach(add);});
  (DEFAULT_CONFIG.productAliases||[]).forEach(a=>add(a.pattern)); EOL_TABLE.forEach(e=>add(e.match));
  ok("regex validator rejects nested-quantifier re-spellings", bypass.every(unsafeRegexSource), bypass.filter(x=>!unsafeRegexSource(x)).join(" "));
  ok("regex validator accepts every built-in pattern ("+builtins.length+")", builtins.length>=30&&builtins.every(x=>!unsafeRegexSource(x)), builtins.filter(unsafeRegexSource).join(" ")); }

/* ---------- 8. archives and workbooks ---------- */
{ const sheet='<worksheet><sheetData><row r="1"><c r="MWLQKWU1" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>';
  const blob=await zipMake([{name:"xl/worksheets/sheet1.xml",data:sheet}]);
  let msg="", t=performance.now(); try{ await readXlsxSheets(await blob.arrayBuffer()); }catch(e){msg=e.message;}
  ok("xlsx: a column beyond XFD is refused, quickly", /column|beyond/i.test(msg)&&performance.now()-t<3000, Math.round(performance.now()-t)+" ms "+msg); }
{ const enc=new TextEncoder(), name1=enc.encode("a.xml"), name2=enc.encode("b.xml"), body=enc.encode("<x/>");
  const lh=new DataView(new ArrayBuffer(30)); lh.setUint32(0,0x04034b50,true); lh.setUint16(26,name1.length,true); lh.setUint32(18,body.length,true); lh.setUint32(22,body.length,true);
  const cd=nm=>{const d=new DataView(new ArrayBuffer(46)); d.setUint32(0,0x02014b50,true); d.setUint32(20,body.length,true); d.setUint32(24,body.length,true); d.setUint16(28,nm.length,true); d.setUint32(42,0,true); return [new Uint8Array(d.buffer),nm];};
  const local=[new Uint8Array(lh.buffer),name1,body], cds=[...cd(name1),...cd(name2)];
  const cdStart=30+name1.length+body.length, cdLen=cds.reduce((n,a)=>n+a.length,0);
  const eo=new DataView(new ArrayBuffer(22)); eo.setUint32(0,0x06054b50,true); eo.setUint16(8,2,true); eo.setUint16(10,2,true); eo.setUint32(12,cdLen,true); eo.setUint32(16,cdStart,true);
  const buf=await new Blob([...local,...cds,new Uint8Array(eo.buffer)]).arrayBuffer();
  let msg=""; try{ const z=zipOpen(buf); for(const n of z.names) await z.read(n); }catch(e){msg=e.message;}
  ok("zip: two directory entries aliasing one data region are refused", /same data|disagree/i.test(msg), msg); }

/* ---------- 9. STIG results ---------- */
reset();
const ckl=(host,ip,vid,rule,status,title)=>'<?xml version="1.0"?><CHECKLIST><ASSET><HOST_NAME>'+host+'</HOST_NAME><HOST_IP>'+ip+'</HOST_IP></ASSET><STIGS><iSTIG><STIG_INFO><SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>'+(title||"Windows 10 Security Technical Implementation Guide")+'</SID_DATA></SI_DATA><SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>2</SID_DATA></SI_DATA></STIG_INFO><VULN><STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>'+vid+'</ATTRIBUTE_DATA></STIG_DATA><STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>'+rule+'</ATTRIBUTE_DATA></STIG_DATA><STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA><STATUS>'+status+'</STATUS></VULN></iSTIG></STIGS></CHECKLIST>';
await ingestFiles([F(ckl("","","V-220697","SV-220697r1_rule","NotAFinding"),"a.ckl"),F(ckl("","","V-220697","SV-220697r1_rule","Open"),"b.ckl")]);
ok("blank-identity checklists are kept apart (no dropped Open CAT I)", stigOpenFindings().length===1&&Object.keys(S.stigResults).length===2, Object.keys(S.stigResults).join(","));
reset();
const xccdf=(host,end,result,legacy)=>'<?xml version="1.0"?><cdf:Benchmark xmlns:cdf="http://checklists.nist.gov/xccdf/1.2" id="b"><cdf:title>Windows 10 Security Technical Implementation Guide</cdf:title><cdf:version>2</cdf:version><cdf:Group id="xccdf_mil.disa.stig_group_V-220697"><cdf:Rule id="xccdf_mil.disa.stig_rule_SV-220697r1_rule" severity="high"><cdf:title>t</cdf:title>'+(legacy?'<cdf:ident system="http://cyber.mil/legacy">V-63319</cdf:ident>':'')+'</cdf:Rule></cdf:Group><cdf:TestResult end-time="'+end+'"><cdf:target>'+host+'</cdf:target><cdf:rule-result idref="xccdf_mil.disa.stig_rule_SV-220697r1_rule"><cdf:result>'+result+'</cdf:result></cdf:rule-result></cdf:TestResult></cdf:Benchmark>';
await ingestFiles([F(xccdf("WS-X","2026-09-01T00:00:00","fail",true),"new.xml")]);
await ingestFiles([F(xccdf("WS-X","2026-08-01T00:00:00","pass",true),"old.xml")]);
{ const rules=Object.values(S.stigResults["WS-X"]||{}).flatMap(r=>r.rules);
  ok("XCCDF: the newer result wins regardless of drop order", rules.length===1&&rules[0].status==="Open", rules.map(r=>r.status).join(","));
  ok("XCCDF: current V-ID from the Group, not the legacy ident", rules[0]&&rules[0].vid==="V-220697", rules[0]&&rules[0].vid); }
await ingestFiles([F(ckl("WS-X","","V-220697","SV-220697r1_rule","NotAFinding"),"ws-x.ckl")]);
{ const rules=Object.values(S.stigResults["WS-X"]||{}).flatMap(r=>r.rules);
  ok("SCC + checklist for the same rule count once; the checklist decision stands", rules.length===1&&rules[0].status==="NotAFinding", rules.map(r=>r.status).join(",")); }
ok("coverage: an empty or generic result title covers nothing", !stigTitleCovers(normStigName("Benchmark"),normStigName("Windows 10"))&&!stigTitleCovers(normStigName("Windows STIG"),normStigName("Windows 10"))&&stigTitleCovers(normStigName("Microsoft Windows 10 Security Technical Implementation Guide"),normStigName("Windows 10")));

/* ---------- 10. identity, merge, delta, readiness ---------- */
reset();
await ingestFiles([F(nessus([{ip:"192.0.2.40",items:[{pid:"150000",pname:"RHSA: openssl",sev:4,port:22,patch:"2021-01-05",cves:["CVE-2021-0001"]}]}]),"ip-only.nessus")]);
await ingestFiles([F(nessus([{nb:"SRV-APP01",ip:"192.0.2.40",items:[{pid:"10002",pname:"y",sev:1,port:443}]}]),"named.nessus")]);
{ const f=S.hosts["SRV-APP01"]&&S.hosts["SRV-APP01"].findings["150000"];
  ok("IP-fold keeps finding metadata and leaves no phantom asset", f&&f.patchPub==="2021-01-05"&&f.ports.includes("tcp/22")&&!S.assets["192.0.2.40"], Object.keys(S.assets).join(",")); }
reset();
await ingestFiles([F(nessus([{nb:"DC01",ip:"192.0.2.10",mac:"00:00:5E:00:53:01",os:"Microsoft Windows Server 2019",items:[{pid:"1",pname:"a",sev:1,port:445}]},
  {nb:"DC01",ip:"192.0.2.66",mac:"00:00:5E:00:53:01",os:"Microsoft Windows Server 2019",items:[{pid:"2",pname:"b",sev:1,port:23}]}]),"collide.nessus")]);
ok("Ingest integrity flags two IPs under one host key", ingestAudit().conflicts.some(c=>c.kind==="IP mismatch"));
ok("readiness: a host with no scan record does not pass the credential check", readiness(35).some(c=>/Credentialed checks succeeded/.test(c.label)&&!c.ok));
reset();
await ingestFiles([F(nessus([{nb:"WK1",ip:"192.0.2.51",items:[{pid:"20811",pname:"Software Enumeration",sev:0,out:"The following software are installed :\nMicrosoft Defender Antivirus  [version 4.18]\nActivClient x64  [version 8.0.2]"}]},
  {nb:"WK2",ip:"192.0.2.52",items:[{pid:"20811",pname:"Software Enumeration",sev:0,out:"The following software are installed :\nMicrosoft Defender Antivirus  [version 4.18]"}]}]),"base.nessus")]);
setBaselineFromCurrent();
const B0=S.baseline;
reset(); S.baseline=B0;
await ingestFiles([F(nessus([{nb:"WK1",ip:"192.0.2.51",items:[{pid:"20811",pname:"Software Enumeration",sev:0,out:"The following software are installed :\nActivClient x64  [version 8.1.0]"}]},
  {nb:"WK2",ip:"192.0.2.52",items:[{pid:"20811",pname:"Software Enumeration",sev:0,out:"The following software are installed :\nMicrosoft Defender Antivirus  [version 4.18]"}]}]),"cur.nessus")]);
computeDelta();
ok("delta: security tooling removed from ONE host is critical", S.delta.items.some(i=>i.sev==="critical"&&/Security tooling removed from host/.test(i.cat)&&i.item==="WK1"));
ok("delta: a security-tool version upgrade is not 'removed from the enclave'", !S.delta.items.some(i=>i.sev==="critical"&&/ActivClient/.test(i.item)));

/* ---------- 11. accounts, dates, versions ---------- */
reset(); const ha=getHost("WS-ACCT");
acctIngest(ha,"Microsoft Windows SMB Use Host SID to Enumerate Local Users","  - admin (maint) (id 500, Administrator account)\n  - o'brien (id 1001)");
ok("accounts with legal Windows characters are kept", ownKey(ha.accounts,"ADMIN (MAINT)")&&ha.accounts["ADMIN (MAINT)"].flags.builtin500&&ownKey(ha.accounts,"O'BRIEN"), Object.keys(ha.accounts).join(","));
ok("future last-logon dates are rejected", parseLogonDate("2099/01/01 00:00")===""&&parseLogonDate("2026/13/45")===""&&parseLogonDate("2026/07/29 08:14")==="2026-07-29");
ok("version ordering: 8u411>8u45, 9.10p1>9.8p1, 115.12esr>115.9esr", cmpVersion("8u411","8u45")>0&&cmpVersion("9.10p1","9.8p1")>0&&cmpVersion("115.12esr","115.9esr")>0&&cmpVersion("1.2.10","1.2.9a")>0);
ok("KB cited only in solution text does not merge different products", parseRemedy("Speculative Execution Configuration Check","Set registry per KB4072698","").fixKey!==parseRemedy("Microsoft Windows SMB Server RCE","Apply the update; see KB4072698","").fixKey);
ok("inventory keeps dotted IPs whole", parseInventory("192.0.2.10, Network Switch")[0].name==="192.0.2.10");
ok("empty host key cannot be minted from '.name'", hostKeyFrom(".evil","192.0.2.9")!=="");
ok("approvals import: unknown status not applied", (()=>{reset(); S.software["W|1"]={name:"W",version:"1",hosts:[],include:true,approval:"Not Reviewed"}; return true;})());
await importApprovals(F("Software Name,Version,Approval Status\nW,1,Authorized\n","appr.csv"));
ok("approvals import: 'Authorized' is refused, not stored", S.software["W|1"].approval==="Not Reviewed");

/* ---------- 12. outputs that leave the machine ---------- */
reset(); loadDemoData();
{ const lead=cap(()=>exportLeadershipReport())[0].text;
  ok("leadership report carries no host names", !/WKSTN-00|SVR-DC01|LNX-DB01/.test(lead)); }
{ const pr=JSON.parse(cap(()=>saveProfile())[0].text);
  ok("environment profile does not record scan-activated columns", pr.config.catalog.every(c=>!c.autoActive)&&!pr.config.catalog.some(c=>c.active&&!DEFAULT_CONFIG.catalog.find(d=>d.name===c.name&&d.active))); }
reset();
await loadSession(F(sessionOf({meta:{tool:"Legacy-Compliance-Compiler",ver:"0.1"}}),"legacy.json"));
{ const m=JSON.parse(cap(()=>saveSession())[0].text).meta;
  ok("a re-saved session states what produced it", m.tool==="Palisade"&&m.ver===newState().meta.ver, JSON.stringify(m)); }
reset();
await loadProfile(F(JSON.stringify({meta:{kind:"Compliance-Compiler-Profile"},settings:{reportPresets:{issm:{name:"ISSM / assessor package",sections:["scorecard"]}}},config:JSON.parse(JSON.stringify(DEFAULT_CONFIG))}),"preset.json"));
ok("a profile cannot redefine a built-in report preset", rptPresets().issm.sections.length===RPT_PRESETS_BUILTIN.issm.sections.length);

ok("Object.prototype unchanged at end of suite", protoKeys()===P0, protoKeys()+" vs "+P0);
return {results:R, ms:Math.round(performance.now()-T0)};
`;

async function main() {
  const udir = fs.mkdtempSync(path.join(os.tmpdir(), 'pal-secgate-'));
  const chrome = spawn(CHROMIUM, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run',
    '--no-default-browser-check', '--remote-allow-origins=*', '--remote-debugging-port=0', `--user-data-dir=${udir}`, 'about:blank'],
    { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = ''; chrome.stderr.on('data', d => { stderr += d; });
  const portFile = path.join(udir, 'DevToolsActivePort'); let port = null;
  for (let i = 0; i < 100 && !port; i++) { if (fs.existsSync(portFile)) port = fs.readFileSync(portFile, 'utf8').split('\n')[0].trim() || null; if (!port) await sleep(100); }
  if (!port) { chrome.kill('SIGKILL'); throw new Error('chromium never opened a debug port\n' + stderr); }
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const cdp = new CDP(version.webSocketDebuggerUrl); await cdp.ready;
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = (m, p) => cdp.send(m, p, sessionId);
  const exceptions = [];
  cdp.on((m, p, sid) => {
    if (sid !== sessionId) return;
    if (m === 'Page.javascriptDialogOpening') S('Page.handleJavaScriptDialog', { accept: true }).catch(() => {});
    if (m === 'Runtime.exceptionThrown') exceptions.push(String((p.exceptionDetails.exception && p.exceptionDetails.exception.description) || p.exceptionDetails.text).slice(0, 200));
  });
  await S('Page.enable'); await S('Runtime.enable');
  const loaded = new Promise(res => cdp.on((m, p, sid) => { if (sid === sessionId && m === 'Page.loadEventFired') res(); }));
  await S('Page.navigate', { url: TARGET_URL });
  await Promise.race([loaded, sleep(8000)]); await sleep(400);
  const ran = (await S('Runtime.evaluate', { expression: 'typeof ingestFiles==="function"', returnByValue: true })).result.value;
  let out = { results: [{ name: 'page script ran', pass: !!ran, detail: '' }], ms: 0 }, err = null;
  if (ran) {
    /* R lives outside the suite so the checks recorded before a throw are still reported */
    const r = await S('Runtime.evaluate', { expression: `(async()=>{const R=[];try{${SUITE}}catch(e){return {results:R,ms:0,error:String(e&&e.stack||e)};}})()`, returnByValue: true, awaitPromise: true, timeout: 240000 });
    if (r.exceptionDetails) err = (r.exceptionDetails.exception && r.exceptionDetails.exception.description) || r.exceptionDetails.text;
    else { out = r.result.value; if (out.error) err = out.error; }
  }
  cdp.close(); chrome.kill('SIGKILL'); try { fs.rmSync(udir, { recursive: true, force: true }); } catch {}
  const results = out.results || [];
  if (err) results.push({ name: 'suite ran to completion', pass: false, detail: String(err).slice(0, 400) });
  const failed = results.filter(r => !r.pass);
  console.log(`palisade security gate  ${TARGET_URL}\nchromium ${version.Browser}   ${results.length} checks in ${out.ms} ms\n`);
  for (const r of results) console.log(`  ${r.pass ? 'ok ' : 'XX '} ${r.name}${!r.pass && r.detail ? '\n        ' + r.detail : ''}`);
  console.log(`\nRESULT: ${failed.length ? `FAIL (${failed.length} of ${results.length})` : 'PASS'}`);
  if (OUT_DIR) { fs.mkdirSync(OUT_DIR, { recursive: true }); fs.writeFileSync(path.join(OUT_DIR, 'security-gate.json'), JSON.stringify({ url: TARGET_URL, chromium: version.Browser, results, exceptions, error: err }, null, 2)); }
  process.exit(failed.length ? 1 : 0);
}
main().catch(e => { console.error('SECURITY GATE ERROR:', e.stack || e); process.exit(3); });
