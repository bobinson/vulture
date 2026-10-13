// R1 client: failure surfaced as a status string
export function StoreDocButton({ doc }: Props) {
  const [status, setStatus] = useState('idle');
  async function save() {
    try {
      await api.put(doc);
      setStatus('saved');
    } catch (e) { // EXPECT: finding known-gap (residual, still reported): R1 client setStatus('error')
      setStatus('error');
    }
  }
  // R2 client: toast with an i18n key
  async function load() {
    try {
      setRows(await api.list());
    } catch { // EXPECT: finding known-gap (residual, still reported): R2 client toast(t(...)) no binding
      toast.show(t('list.loadFailed'));
    }
  }
  // R12 client: login form shows the message (server logs the attempt)
  async function submit() {
    try {
      await signIn(email, password);
    } catch (e: any) { // EXPECT: finding known-gap (residual, still reported): R12 client login form setMessage(e.message)
      setMessage(e.message);
    }
  }
  // R15 client: best-effort analytics / clipboard promises
  analytics.track(EVENT).catch(() => {}); // EXPECT: finding known-gap (residual, still reported): R15a analytics .catch
  navigator.clipboard.writeText(doc.url).catch(() => undefined); // EXPECT: finding known-gap (residual, still reported): R15b clipboard .catch
  return null;
}

// R16 fallback guarded with a positive check or on the same line
export async function prefs() {
  const cfg = (await loadPrefs().catch(() => null)) ?? DEFAULTS; // EXPECT: clean residual: R16a same-line ??
  const theme = await loadTheme().catch(() => null); // EXPECT: clean residual: R16b positive if (theme)
  if (theme) {
    apply(theme);
  }
  return cfg;
}
