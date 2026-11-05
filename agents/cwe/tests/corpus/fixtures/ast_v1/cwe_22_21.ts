// pins: a decorated parameter (@Query("f") name: string) is a request source by its decorator words (R-D) and reaches fs.readFile
export class DocController {
  show(@Query("f") name: string): void {
    fs.readFile("/srv/docs/" + name, () => {});
  }
}
