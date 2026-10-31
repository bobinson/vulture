export async function renameVault(req, res) {
  try {
    await vaults.rename(req.body.id, req.body.name);
  } catch (e) {
    const errorMessage = e.message;
    audit.step0(req.body.id);
    audit.step1(req.body.id);
    audit.step2(req.body.id);
    audit.step3(req.body.id);
    audit.step4(req.body.id);
    audit.step5(req.body.id);
    audit.step6(req.body.id);
    audit.step7(req.body.id);
    audit.step8(req.body.id);
    audit.step9(req.body.id);
    audit.step10(req.body.id);
    audit.step11(req.body.id);
    audit.step12(req.body.id);
    audit.step13(req.body.id);
    audit.step14(req.body.id);
    audit.step15(req.body.id);
    audit.step16(req.body.id);
    audit.step17(req.body.id);
    audit.step18(req.body.id);
    audit.step19(req.body.id);
    audit.step20(req.body.id);
    audit.step21(req.body.id);
    audit.step22(req.body.id);
    audit.step23(req.body.id);
    audit.step24(req.body.id);
    audit.step25(req.body.id);
    audit.step26(req.body.id);
    audit.step27(req.body.id);
    audit.step28(req.body.id);
    audit.step29(req.body.id);
    audit.step30(req.body.id);
    audit.step31(req.body.id);
    audit.step32(req.body.id);
    audit.step33(req.body.id);
    audit.step34(req.body.id);
    // EXPECT-NEXT: clean  known-gap an alias bound beyond the 30-line binding radius resolves unknown, and only the conventional names report unresolved
    res.status(500).send(errorMessage);
  }
}
