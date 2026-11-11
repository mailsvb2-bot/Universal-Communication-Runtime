/** One-shot OS contact selection; never synchronizes telephone book or equates phone with Identity. */
export class PhonebookUnavailable extends Error { constructor(message){super(message);this.name="PhonebookUnavailable";} }
export function normalizeSelectedPhone(raw){
 if(typeof raw!=="string"||raw.length>128)return null;
 let phone=raw.replace(/[\s().-]/g,"");if(phone.startsWith("00"))phone="+"+phone.slice(2);
 return /^\+?[0-9]{7,15}$/.test(phone)?phone:null;
}
function nameOf(raw){
 if(typeof raw!=="string")throw new PhonebookUnavailable("Имя контакта отсутствует.");
 const s=raw.normalize("NFC").replace(/[\u0000-\u001f\u007f-\u009f]/g," ").replace(/\s+/g," ").trim();
 if(!s||s.length>128)throw new PhonebookUnavailable("Некорректное имя контакта.");
 return s;
}
function selected(name,phone){return Object.freeze({displayName:nameOf(name),phone:normalizeSelectedPhone(phone)});}
export async function pickSystemContact(api=globalThis.navigator){
 if(typeof api?.contacts?.select!=="function")throw new PhonebookUnavailable("Системный выбор контакта недоступен.");
 const list=await api.contacts.select(["name","tel"],{multiple:false});
 if(!Array.isArray(list)||!list.length)return null;
 return selected(list[0]?.name?.[0],list[0]?.tel?.[0]);
}
export function parseSingleVcard(contents){
 if(typeof contents!=="string"||new TextEncoder().encode(contents).byteLength>1048576)throw new PhonebookUnavailable("Файл слишком большой.");
 let lines=[];for(const line of contents.replace(/\r\n?/g,"\n").split("\n")){
  if(/^[ \t]/.test(line)&&lines.length)lines[lines.length-1]+=line.slice(1);
  else lines.push(line);
 }
 let count=0,inside=false,name="",n="",phone="";
 for(const line of lines){
  if(/^BEGIN:VCARD\s*$/i.test(line)){if(inside||++count>1)throw new PhonebookUnavailable("Нужен один контакт.");inside=true;continue;}
  if(/^END:VCARD\s*$/i.test(line)){if(!inside)throw new PhonebookUnavailable("Повреждённый vCard.");inside=false;continue;}
  if(!inside||line.length>4096)continue;
  const i=line.indexOf(":");if(i<1)continue;
  const header=line.slice(0,i).toUpperCase();if(/ENCODING=|CHARSET=/i.test(header))continue;
  const field=header.split(";")[0].split(".").pop(),value=line.slice(i+1);
  if(field==="FN"&&!name)name=value.replace(/\\[nN]/g," ").replace(/\\([,;\\])/g,"$1");
  if(field==="N"&&!n){const parts=value.split(";");n=[parts[1],parts[0]].filter(Boolean).join(" ");}
  if(field==="TEL"&&!phone)phone=value.replace(/^tel:/i,"");
 }
 if(count!==1||inside)throw new PhonebookUnavailable("Некорректный файл контакта.");
 return selected(name||n,phone);
}
export async function readSelectedVcard(file){
 if(!file||typeof file.size!=="number"||file.size<1||file.size>1048576||!/\.vcf$/i.test(file.name||""))throw new PhonebookUnavailable("Выберите небольшой .vcf с одним контактом.");
 const data=await file.arrayBuffer();if(data.byteLength<1||data.byteLength>1048576)throw new PhonebookUnavailable("Некорректный размер vCard.");
 let str;try{str=new TextDecoder("utf-8",{fatal:true}).decode(data);}catch{throw new PhonebookUnavailable("Нужна кодировка UTF-8.");}
 return parseSingleVcard(str);
}
export function checkedPublicInvite(input,origin){
 let url,host;try{url=new URL(input);host=new URL(origin);}catch{throw new PhonebookUnavailable("Некорректная ссылка.");}
 if(url.protocol!=="https:"||host.protocol!=="https:"||url.origin!==host.origin||url.pathname!=="/start"||url.hash||url.username||url.password||url.searchParams.size!==1||!/^[A-Za-z0-9_.:@-]{1,128}$/.test(url.searchParams.get("contact")||""))throw new PhonebookUnavailable("Ссылка приглашения не подтверждена.");
 return url.href;
}
export function smsDraftHref(phone,url,origin){
 const number=normalizeSelectedPhone(phone);if(!number)throw new PhonebookUnavailable("Некорректный номер.");
 const safe=checkedPublicInvite(url,origin);
 return "sms:"+number+"?body="+encodeURIComponent("Приглашаю тебя в PetrelLink: "+safe);
}
