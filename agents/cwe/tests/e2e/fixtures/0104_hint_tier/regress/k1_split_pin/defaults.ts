import { loadPiece } from "./entry";

export function loadDefaults(): Buffer {
  return loadPiece("defaults.json");
}
