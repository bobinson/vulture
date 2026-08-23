export async function lookupCustomer(ssn: string) {
  const url = `https://records.example.com/v1/customer?ssn=${ssn}`
  const res = await fetch(url)
  return res.json()
}
