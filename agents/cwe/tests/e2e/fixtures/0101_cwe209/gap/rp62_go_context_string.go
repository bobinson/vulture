package quote

func priceHandler(c *Ctx) {
	if err := price(c); err != nil {
		// EXPECT-NEXT: clean  known-gap a String verb is not response-shaped
		c.String(500, err.Error())
	}
}
