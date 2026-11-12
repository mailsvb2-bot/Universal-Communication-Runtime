import Foundation
import MessageUI
import UIKit
/// Explicitly user-initiated SMS draft, never a cryptographic authentication.
@MainActor public final class ContactActions:NSObject,MFMessageComposeViewControllerDelegate{
 private var callback:((Bool)->Void)?
 private static func phone(_ raw:String)->String?{
  let v=raw.filter{ !" ().-\t\n".contains($0) }
  return v.range(of:"^\\+?[0-9]{7,15}$",options:.regularExpression) == nil ? nil : v
 }
 public static func validInvite(_ url:URL)->Bool{
  guard let c=URLComponents(url:url,resolvingAgainstBaseURL:false) else{return false}
  return c.scheme=="https" && c.host=="app.petrellink.ru" && c.port==nil &&
   c.user==nil && c.password==nil && c.fragment==nil && c.path=="/start" &&
   c.queryItems?.count==1 && c.queryItems?.first?.name=="contact" &&
   c.queryItems?.first?.value?.range(of:"^[A-Za-z0-9_.:@-]{1,128}$",options:.regularExpression) != nil
 }
 public func composeInvite(from parent:UIViewController,phone raw:String,url:URL,done:@escaping(Bool)->Void){
  guard callback == nil,MFMessageComposeViewController.canSendText(),
   let phone=Self.phone(raw),Self.validInvite(url) else{done(false);return}
  callback=done
  let vc=MFMessageComposeViewController();vc.messageComposeDelegate=self
  vc.recipients=[phone];vc.body="PetrelLink: \(url.absoluteString)"
  parent.present(vc,animated:true)
 }
 public func messageComposeViewController(_ controller:MFMessageComposeViewController,didFinishWith result:MessageComposeResult){
  let cb=callback;callback=nil
  controller.dismiss(animated:true){cb?(result == .sent)}
 }
}
