const F = () => <div><label>Can't</label><input onChange={e => eval(e.target.value)} placeholder="it's" /></div>; // EXPECT: finding
