package remote

func dial(addr, user string, signer ssh.Signer) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{User: user}
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	return ssh.Dial("tcp", addr, cfg)
}
