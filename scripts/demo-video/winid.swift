import CoreGraphics
import Foundation
// Prints "id width height layer x y" for every on-screen window of the owner given (sizes in points).
let owner = CommandLine.arguments[1]
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
for w in list where (w[kCGWindowOwnerName as String] as? String) == owner {
    let b = w[kCGWindowBounds as String] as! [String: CGFloat]
    print(w[kCGWindowNumber as String] as! Int, Int(b["Width"]!), Int(b["Height"]!), w[kCGWindowLayer as String] as! Int, Int(b["X"]!), Int(b["Y"]!))
}
