package remote

func dial(addr, user, hostsFile string, signer ssh.Signer) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{User: user}
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	callback, err := knownhosts.New(hostsFile)
	if err != nil {
		return nil, err
	}
	cfg.HostKeyCallback = callback
	return ssh.Dial("tcp", addr, cfg)
}
