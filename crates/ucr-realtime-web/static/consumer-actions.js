/** Consumer-only presentation helpers. All protected calls use canonical UCR Call authority. */
import {checkedPublicInvite} from "./phonebook.js";
export function friendlyCallError(error){
 const v=String(error instanceof Error?error.message:error??"");
 if(/already|duplicate|pending|ringing|незаверш|текущ/i.test(v))return "Сначала завершите текущий звонок.";
 if(/401|session|authenticate|Device changed|login|войд/i.test(v))return "Вход истёк. Подтвердите устройство.";
 if(/403|revoke|forbidden|denied|доступ/i.test(v))return "Доступ к звонку не подтверждён.";
 if(/offline|unavailable|connect|timeout|network|503/i.test(v))return "Нет соединения. Проверьте интернет.";
 return "Звонок не начался. Попробуйте снова.";
}
export function supportedContactMethods({hasPetrelLinkIdentity=false,hasSelectedPhone=false}={}){
 return Object.freeze({audio:Boolean(hasPetrelLinkIdentity),video:Boolean(hasPetrelLinkIdentity),telephone:Boolean(hasSelectedPhone),sms:Boolean(hasSelectedPhone),otherApps:"Наличие других мессенджеров не определяется"});
}
export function invitationText(url,origin){return "Приглашаю в PetrelLink: "+checkedPublicInvite(url,origin)+"\nПроверь мой контакт лично или через доверенный канал.";}
export async function sharePublicInvite({url,origin,navigatorLike,copyFallback}){
 const safe=checkedPublicInvite(url,origin);
 if(typeof navigatorLike?.share==="function"){
  try{await navigatorLike.share({title:"PetrelLink — приглашение",text:invitationText(safe,origin),url:safe});return "shared";}
  catch(e){return e?.name==="AbortError"?"cancelled":"unavailable";}
 }
 if(typeof copyFallback==="function"){await copyFallback(safe);return "copied";}
 return "unavailable";
}
