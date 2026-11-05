// held-out heldout_04 (CWE-918): a UI translation lookup by a method parameter, its result applied in a subscribe callback
export class HintPanelComponent {
  readonly message = signal('')

  constructor (private readonly translate: Translator) {}

  applyHint (key: string) {
    this.translate.get(key).subscribe(text => {
      this.message.set(text)
    })
  }
}
