func a(p: String) {
    do { try write(p) } catch { }
    do { try write(p) } catch { os_log("write failed: %@", "\(error)") }
    do { try write(p) } catch let e as IOError { }
    do { try write(p) } catch let e as IOError { NSLog("io: \(e)") }
    do { try write(p) } catch { throw e }
    let v = try? write(p)
    let w = try! write(p)
}
