try{f()}catch(err){
  // EXPECT-NEXT: clean  logged only
  console.error(err.message)
  res.status(500).send('error')
}
