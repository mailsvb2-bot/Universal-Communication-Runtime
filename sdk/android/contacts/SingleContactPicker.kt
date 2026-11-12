package org.ucr.sdk.contacts
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.ContactsContract
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
/** One selected OS contact; no bulk READ_CONTACTS permission. */
class SingleContactPicker(activity:ComponentActivity,private val chosen:(Selection?)->Unit) {
 data class Selection(val displayName:String,val phone:String?)
 private val launcher=activity.registerForActivityResult(ActivityResultContracts.StartActivityForResult()){ result ->
  if(result.resultCode!=Activity.RESULT_OK)chosen(null)
  else chosen(read(activity,result.data?.data))
 }
 fun open(){launcher.launch(Intent(Intent.ACTION_PICK,ContactsContract.CommonDataKinds.Phone.CONTENT_URI))}
 private fun read(activity:ComponentActivity,uri:Uri?):Selection?{
  if(uri?.scheme!="content")return null
  val name=ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME
  val phone=ContactsContract.CommonDataKinds.Phone.NUMBER
  return try {
   activity.contentResolver.query(uri,arrayOf(name,phone),null,null,null)?.use {
    if(!it.moveToFirst())return@use null
    val ni=it.getColumnIndex(name);val pi=it.getColumnIndex(phone)
    if(ni<0)return@use null
    val display=it.getString(ni)?.trim()?.take(128).orEmpty()
    if(display.isEmpty())null else Selection(display,if(pi<0)null else it.getString(pi))
   }
  }catch(_:SecurityException){null}
 }
}
