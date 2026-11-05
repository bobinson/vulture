export async function chat(req, res) {
  for await (const event of agent.stream(req.body)) {
    switch (event.type) {
      case 'k0':
        res.write(JSON.stringify({ v: event.v0 }));
        break;
      case 'k1':
        res.write(JSON.stringify({ v: event.v1 }));
        break;
      case 'k2':
        res.write(JSON.stringify({ v: event.v2 }));
        break;
      case 'k3':
        res.write(JSON.stringify({ v: event.v3 }));
        break;
      case 'k4':
        res.write(JSON.stringify({ v: event.v4 }));
        break;
      case 'k5':
        res.write(JSON.stringify({ v: event.v5 }));
        break;
      case 'k6':
        res.write(JSON.stringify({ v: event.v6 }));
        break;
      case 'k7':
        res.write(JSON.stringify({ v: event.v7 }));
        break;
      case 'k8':
        res.write(JSON.stringify({ v: event.v8 }));
        break;
      case 'k9':
        res.write(JSON.stringify({ v: event.v9 }));
        break;
      case 'k10':
        res.write(JSON.stringify({ v: event.v10 }));
        break;
      case 'k11':
        res.write(JSON.stringify({ v: event.v11 }));
        break;
      case 'k12':
        res.write(JSON.stringify({ v: event.v12 }));
        break;
      case 'k13':
        res.write(JSON.stringify({ v: event.v13 }));
        break;
      case 'k14':
        res.write(JSON.stringify({ v: event.v14 }));
        break;
      case 'k15':
        res.write(JSON.stringify({ v: event.v15 }));
        break;
      case 'error':
        res.write(JSON.stringify({ error: String(event.error) })); // EXPECT: finding tp-S-long-switch
        break;
    }
  }
}
