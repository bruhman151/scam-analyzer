"use strict";
const $ = (id) => document.getElementById(id);
let latest = null, previewUrl = null, controller = null, generation = 0;
const examples = {
  otp: ["text", "เจ้าหน้าที่ขอให้ส่งรหัส O T P เพื่อปลดล็อกบัญชี"],
  task: ["text", "เติมเงินก่อนเพื่อปลดล็อกรายได้และถอนเงินจากการทำภารกิจ"],
  normal: ["text", "รหัส OTP 123456 สำหรับเข้าสู่ระบบ ห้ามบอกรหัสนี้กับใคร"],
  url: ["url", "https://bank.example.org@192.0.2.10/login"]
};
function kind() { return document.querySelector("input[name=kind]:checked").value; }
function clearResult() {
  generation++; if(controller) controller.abort(); controller=null;
  $("submit").disabled=false; $("submit").textContent="วิเคราะห์ความเสี่ยง ↗";
  latest=null; $("result").hidden=true; $("empty").hidden=false; $("error").hidden=true;
}
function mode() {
  clearResult(); const image=kind()==="image", url=kind()==="url";
  $("text-input").hidden=image; $("image-input").hidden=!image;
  $("content-label").textContent=url?"วาง URL ที่ต้องการตรวจ":"วางข้อความที่ต้องการวิเคราะห์";
  $("content").placeholder=url?"https://example.org/…":"เช่น ข้อความจาก SMS, แชต หรืออีเมล…";
  $("input-hint").textContent=url?"ตรวจโครงสร้าง URL โดยไม่เปิดลิงก์":"ไทย / English · สูงสุด 5,000 ตัวอักษร";
}
document.querySelectorAll("input[name=kind]").forEach(el=>el.addEventListener("change",mode));
$("content").addEventListener("input",()=>{ $("count").textContent=Array.from($("content").value).length.toLocaleString()+" / 5,000"; clearResult(); });
function setInput(type,text) {
  document.querySelector('input[name=kind][value="'+type+'"]').checked=true;
  mode(); $("content").value=text; $("content").dispatchEvent(new Event("input")); $("content").focus();
}
document.querySelectorAll("[data-example]").forEach(el=>el.addEventListener("click",()=>setInput(...examples[el.dataset.example])));
$("image").addEventListener("change",()=>{
  clearResult(); if(previewUrl) URL.revokeObjectURL(previewUrl);
  const file=$("image").files[0]; $("preview").hidden=!file;
  if(file){previewUrl=URL.createObjectURL(file);$("preview").src=previewUrl;}
});
$("clear").addEventListener("click",()=>{
  clearResult(); $("content").value=""; $("count").textContent="0 / 5,000"; $("image").value="";
  if(previewUrl) URL.revokeObjectURL(previewUrl); previewUrl=null;
  $("preview").removeAttribute("src"); $("preview").hidden=true;
});
function textElement(tag,text,parent,className){
  const el=document.createElement(tag); el.textContent=text; if(className) el.className=className; parent.append(el); return el;
}
function showResult(data) {
  latest=data; $("empty").hidden=true; $("result").hidden=false;
  const labels={HIGH:"ความเสี่ยงสูง",MEDIUM:"ความเสี่ยงปานกลาง",LOW:"พบสัญญาณอ่อน"};
  $("risk").textContent=labels[data.risk]||"หลักฐานไม่พอ";
  $("risk").className="badge "+(data.risk||"").toLowerCase();
  $("score").textContent=data.score===null?"ยังไม่จัดระดับ":data.score+" / 100 คะแนน";
  $("summary").textContent=data.signals.length?"พบ "+data.signals.length+" สัญญาณที่ควรตรวจสอบ":"ยังไม่พบสัญญาณตามกฎที่ระบบรองรับ ไม่ได้ยืนยันว่าข้อมูลนี้ปลอดภัย";
  $("signals").replaceChildren();
  for(const s of data.signals){
    const card=textElement("div","",$("signals"),"signal");
    textElement("p",s.reason,card); textElement("code",s.evidence||"",card);
    const layerNames={phrase_context:"คำและบริบท",context:"บริบท",url_structure:"โครงสร้าง URL",combination:"สัญญาณร่วมกัน"};
    textElement("small",(layerNames[s.layer]||"รูปแบบข้อความ")+" · +"+s.weight+" คะแนน",card);
  }
  $("url-info").replaceChildren();
  for(const item of data.analysis.urls){
    textElement("p","ชื่อเว็บไซต์จริง: "+(item.host||"อ่านไม่ได้"),$("url-info"));
    for(const note of item.observations) textElement("p",note,$("url-info"));
  }
  $("ocr-result").hidden=!data.ocr;
  if(data.ocr){$("ocr-text").textContent=data.ocr.text;$("ocr-note").textContent=data.ocr.notice;}
  $("actions").replaceChildren(); for(const action of data.actions)textElement("li",action,$("actions"));
  $("notice").textContent=data.notice; $("json-output").textContent=JSON.stringify(data,null,2);
}
$("analyze-form").addEventListener("submit",async(event)=>{
  event.preventDefault(); clearResult(); const id=generation; const type=kind();
  let url="/analyze", options={method:"POST"};
  if(type==="image"){
    const file=$("image").files[0];
    if(!file||file.size>4*1024*1024){$("error").textContent="เลือกภาพ PNG/JPEG ไม่เกิน 4 MB";$("error").hidden=false;return;}
    const body=new FormData();body.append("image",file); options.body=body;url="/analyze/image";
  }else{
    if(!$("content").value.trim()){ $("error").textContent="กรุณาใส่ข้อมูลก่อนวิเคราะห์";$("error").hidden=false;return; }
    options.headers={"Content-Type":"application/json"};
    options.body=JSON.stringify({kind:type,content:$("content").value});
  }
  controller=new AbortController();options.signal=controller.signal;
  const timer=setTimeout(()=>controller?.abort(),20000);
  $("submit").disabled=true;$("submit").textContent=type==="image"?"กำลังอ่านข้อความจากภาพ…":"กำลังวิเคราะห์…";
  try{
    const response=await fetch(url,options);
    const data=await response.json().catch(()=>({error:"ระบบตอบกลับไม่สมบูรณ์ กรุณาลองใหม่"}));
    if(id!==generation)return;
    if(!response.ok)throw new Error(data.error||"วิเคราะห์ไม่สำเร็จ");
    showResult(data);
  }catch(error){
    if(id!==generation)return;
    $("error").textContent=error.name==="AbortError"?"ระบบใช้เวลานานเกินไป กรุณาลองใหม่":error.message;
    $("error").hidden=false;
  }finally{
    clearTimeout(timer);
    if(id===generation){controller=null;$("submit").disabled=false;$("submit").textContent="วิเคราะห์ความเสี่ยง ↗";}
  }
});
$("edit-ocr").addEventListener("click",()=>{if(latest?.ocr)setInput("text",latest.ocr.text);});
$("download").addEventListener("click",()=>{
  if(!latest)return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(latest,null,2)],{type:"application/json"}));
  const a=document.createElement("a");a.href=url;a.download="risk-analysis.json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
fetch("/health").then(r=>{if(!r.ok)throw new Error();return r.json();}).then(data=>{
  $("health").textContent=data.ocr.available?"ระบบพร้อม · ข้อความ / URL / ภาพ":"ระบบพร้อม · OCR ยังไม่ติดตั้ง";
  $("health").classList.add("ready");
}).catch(()=>{$("health").textContent="ยังเชื่อมต่อระบบไม่ได้";});
