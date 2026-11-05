// EXPECT-NEXT: clean  a sink spelled inside a string literal is not a write (was a known gap; closed by R209-I2, sinks are found on the literal-masked line)
const BAD_EXAMPLE = "res.send(err)"
