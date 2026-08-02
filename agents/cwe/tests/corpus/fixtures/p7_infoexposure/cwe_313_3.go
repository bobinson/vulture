package config

func persist(apiKey string) error {
	return os.WriteFile("/etc/app/state", []byte(apiKey), 0o600)
}
