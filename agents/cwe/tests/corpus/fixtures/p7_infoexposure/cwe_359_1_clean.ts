export async function lookupCustomer(ssn: string) {
  const url = `https://records.example.com/v1/customer`
  const res = await fetch(url, { method: 'POST', body: JSON.stringify({ ssn }) })
  return res.json()
}
