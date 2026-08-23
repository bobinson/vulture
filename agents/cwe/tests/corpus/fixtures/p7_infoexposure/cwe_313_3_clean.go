package config

func persist(hostName string) error {
	return os.WriteFile("/etc/app/state", []byte(hostName), 0o600)
}
