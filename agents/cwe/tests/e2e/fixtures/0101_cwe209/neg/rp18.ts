try { run() } catch (err) {
  // EXPECT-NEXT: clean
  mailer.sendMail({ to: ADMIN, text: err.message })
}
