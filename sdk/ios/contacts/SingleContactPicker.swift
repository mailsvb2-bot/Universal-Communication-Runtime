import Contacts
import ContactsUI
import UIKit
/// One-shot OS selection. No phone-to-Identity inference.
@MainActor public final class SingleContactPicker: NSObject,CNContactPickerDelegate {
 public struct Selection { public let displayName:String;public let phone:String? }
 private var callback:((Selection?)->Void)?
 private var picker:CNContactPickerViewController?
 public func present(from parent:UIViewController,completion:@escaping(Selection?)->Void){
  guard picker == nil else {completion(nil);return}
  callback=completion
  let next=CNContactPickerViewController();next.delegate=self
  next.displayedPropertyKeys=[CNContactPhoneNumbersKey]
  picker=next;parent.present(next,animated:true)
 }
 public func contactPicker(_ picker:CNContactPickerViewController,didSelect contact:CNContact){
  let name=[contact.givenName,contact.familyName].filter{ !$0.isEmpty }.joined(separator:" ")
  finish(name.isEmpty ? nil : Selection(displayName:String(name.prefix(128)),phone:contact.phoneNumbers.first?.value.stringValue))
 }
 public func contactPickerDidCancel(_ picker:CNContactPickerViewController){finish(nil)}
 private func finish(_ value:Selection?){let cb=callback;callback=nil;picker=nil;cb?(value)}
}
