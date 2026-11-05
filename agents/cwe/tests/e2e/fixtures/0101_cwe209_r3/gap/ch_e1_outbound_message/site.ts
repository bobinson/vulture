export async function onTurn(turn: any) {
  try {
    await planner.answer(turn.activity.text);
  } catch (err) {
    await turn.sendActivity(`Sorry, that failed: ${String(err)}`); // EXPECT: clean gap-E1-outbound-message
  }
}
