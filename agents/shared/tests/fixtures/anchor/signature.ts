// signature.ts -- 0076 fixture: the measured signupCompletionChecker.ts case.
// The model cites the function SIGNATURE (54) and quotes the BODY (55-56).
// filler 003
// filler 004
// filler 005
// filler 006
// filler 007
// filler 008
// filler 009
// filler 010
// filler 011
// filler 012
// filler 013
// filler 014
// filler 015
// filler 016
// filler 017
// filler 018
// filler 019
// filler 020
// filler 021
// filler 022
// filler 023
// filler 024
// filler 025
// filler 026
// filler 027
// filler 028
// filler 029
// filler 030
// filler 031
// filler 032
// filler 033
// filler 034
// filler 035
// filler 036
// filler 037
// filler 038
// filler 039
// filler 040
// filler 041
// filler 042
// filler 043
// filler 044
// filler 045
// filler 046
// filler 047
// filler 048
// filler 049
// filler 050
// filler 051
// filler 052
// filler 053
export async function checkSignupCompletion(userId: string) {
  const record = await db.users.findUnique({ where: { id: userId } });
  if (!record) throw new Error("no such user");
  return record.completedAt !== null;
}
