DEPLOY_HOST ?= web1
HOST ?= web1
USER ?= ops

publish:
	rsync -avz dist/ $(DEPLOY_HOST):/var/www

publish-home:
	scp app.tar $(USER)@$(HOST):
