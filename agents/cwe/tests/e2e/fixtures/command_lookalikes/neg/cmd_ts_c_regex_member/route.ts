export function f(req: any, entry: any) { return entry.regex.exec(req.url); } // EXPECT: clean
