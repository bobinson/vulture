package payments

func chargeURL(merchantID string) string {
	return "https://pay.example.com/charge?merchant_id=" + merchantID
}
