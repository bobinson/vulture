export async function archiveLedger(req, res) {
  try {
    await ledgers.archive(req.body.id);
  } catch (e) {
    const first = e;
    audit.note0(req.body.id);
    audit.note1(req.body.id);
    audit.note2(req.body.id);
    audit.note3(req.body.id);
    audit.note4(req.body.id);
    audit.note5(req.body.id);
    audit.note6(req.body.id);
    audit.note7(req.body.id);
    audit.note8(req.body.id);
    audit.note9(req.body.id);
    audit.note10(req.body.id);
    audit.note11(req.body.id);
    audit.note12(req.body.id);
    audit.note13(req.body.id);
    audit.note14(req.body.id);
    audit.note15(req.body.id);
    audit.note16(req.body.id);
    audit.note17(req.body.id);
    audit.note18(req.body.id);
    audit.note19(req.body.id);
    const second = first;
    audit.mark0(req.body.id);
    audit.mark1(req.body.id);
    audit.mark2(req.body.id);
    audit.mark3(req.body.id);
    audit.mark4(req.body.id);
    audit.mark5(req.body.id);
    audit.mark6(req.body.id);
    audit.mark7(req.body.id);
    audit.mark8(req.body.id);
    audit.mark9(req.body.id);
    audit.mark10(req.body.id);
    audit.mark11(req.body.id);
    audit.mark12(req.body.id);
    audit.mark13(req.body.id);
    audit.mark14(req.body.id);
    audit.mark15(req.body.id);
    audit.mark16(req.body.id);
    audit.mark17(req.body.id);
    audit.mark18(req.body.id);
    audit.mark19(req.body.id);
    // EXPECT-NEXT: finding  the sink line and the nearest binding hold no marker; the chain reaches the catch two windows up
    res.status(500).json({ detail: second.message });
  }
}
