// R4 Swift implicit `error` binding forwarded to the completion
func fetch(completion: (Result<Data, Error>) -> Void) {
    do {
        completion(.success(try load()))
    } catch { // EXPECT: finding known-gap: `completion` is a parameter whose type has nested parens, so it is not recognised
        completion(.failure(error))
    }
}
