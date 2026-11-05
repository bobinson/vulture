import Foundation

func collect(handle: FileHandle) -> Data {
    var data = Data()
    while true {
        let chunk = handle.readData(ofLength: 4096)
        if chunk.isEmpty { break }
        // EXPECT-NEXT: clean known-gap: a labelled read argument (ofLength:) is not read as a pull (LLD 5.2.6)
        data.append(chunk)
    }
    return data
}
