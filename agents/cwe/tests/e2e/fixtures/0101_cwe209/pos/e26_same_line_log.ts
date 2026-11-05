// EXPECT-NEXT: finding  same line log
try { run() } catch (err) { console.error(err); res.status(500).json({ error: err.message }) }
