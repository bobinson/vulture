export function Panel() {
  const [state, setState] = useState({ error: null });
  useEffect(() => { load().catch((err) => setState({ error: err.message })); }, []);
  return <div className="err">{state.error}</div>; // EXPECT: clean clean-not-a-response
}
