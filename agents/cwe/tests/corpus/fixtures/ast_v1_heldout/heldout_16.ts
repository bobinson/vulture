// held-out heldout_16 (CWE-78): RegExp exec of a pattern built from one parameter, over the lines of another parameter
export function markedLines (source: string, sectionKey: string) {
  const blocks = source.match(`marker begin.*${sectionKey}([^])*marker finish.*${sectionKey}`)
  if (blocks == null) {
    throw new Error('unbalanced markers for: ' + sectionKey)
  }
  let block = blocks[0]
  block = block.replace(/\s?[/#]{0,2} marker begin.*[\r\n]{0,2}/g, '')
  block = block.replace(/\s?[/#]{0,2} marker finish.*/g, '')
  block = block.trim()

  let lines = block.split('\r\n')
  if (lines.length === 1) lines = block.split('\n')
  const flagged = []
  const plain = []
  for (let i = 0; i < lines.length; i++) {
    if (new RegExp(`marker flag-line.*${sectionKey}`).exec(lines[i]) != null) {
      flagged.push(i + 1)
    } else if (new RegExp(`marker plain-line.*${sectionKey}`).exec(lines[i]) != null) {
      plain.push(i + 1)
    }
  }
  return { sectionKey, block, flagged, plain }
}
