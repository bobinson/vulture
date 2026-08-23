function nextBackoff(attempt, policy) {
  const jitter = policy.base * attempt * Math.random();
  return Math.min(policy.max, policy.base * attempt + jitter);
}
