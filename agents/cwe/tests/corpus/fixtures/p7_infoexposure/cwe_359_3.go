package payments

func chargeURL(pan string) string {
	return "https://pay.example.com/charge?card_number=" + pan
}
