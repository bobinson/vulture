import { Router } from "express";
import { findParcel } from "./store";

export const router = Router();

router.get("/parcels/:name", (req, res) => {
  const file = findParcel(req.params.name);
  if (!file) {
    res.sendStatus(404);
    return;
  }
  res.sendFile(file); // EXPECT: finding check=cwe.input_validation.path_traversal
});
