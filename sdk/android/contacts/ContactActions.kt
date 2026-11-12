package org.ucr.sdk.contacts
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
/** User-triggered OS actions; phone is never UCR Identity. */
object ContactActions {
 private fun phone(v:String):String?=v.replace(Regex("[\\s().-]"),"").takeIf{it.matches(Regex("\\+?[0-9]{7,15}"))}
 private fun valid(url:String):Boolean=try{
  val u=Uri.parse(url)
  u.scheme=="https"&&u.host=="app.petrellink.ru"&&u.port == -1&&u.userInfo==null&&u.path=="/start"&&
   u.fragment==null&&u.queryParameterNames==setOf("contact")&&
   (u.getQueryParameter("contact")?:"").matches(Regex("[A-Za-z0-9_.:@-]{1,128}"))
 }catch(_:Exception){false}
 private fun launch(ctx:Context,i:Intent):Boolean=try{
  if(ctx !is Activity)i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
  ctx.startActivity(i);true
 }catch(_:Exception){false}
 fun sms(ctx:Context,n:String,url:String):Boolean{
  val p=phone(n)?:return false
  if(!valid(url))return false
  return launch(ctx,Intent(Intent.ACTION_SENDTO,Uri.parse("smsto:$p")).apply{putExtra("sms_body","PetrelLink: $url")})
 }
 fun dial(ctx:Context,n:String):Boolean{
  val p=phone(n)?:return false
  return launch(ctx,Intent(Intent.ACTION_DIAL,Uri.parse("tel:$p")))
 }
 fun share(ctx:Context,url:String):Boolean{
  if(!valid(url))return false
  return launch(ctx,Intent.createChooser(Intent(Intent.ACTION_SEND).apply{
   type="text/plain";putExtra(Intent.EXTRA_TEXT,"PetrelLink: $url")
  },"Отправить приглашение"))
 }
}
