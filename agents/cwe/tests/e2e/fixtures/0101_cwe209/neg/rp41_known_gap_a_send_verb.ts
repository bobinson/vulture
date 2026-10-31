export async function onUpload(context: any) {
  try {
    await upload();
  } catch (err) {
    // EXPECT-NEXT: clean  known-gap a send verb with a non-response suffix is not a sink
    await context.sendActivity(`upload failed: ${String(err)}`);
  }
}
