gitea admin user create --username courses-server --password ">>COURSE_SERVER_GITEA_PASSWORD<<" --email i.have@no.email --admin
gitea admin auth add-oauth --name rz --provider openidConnect --key ">>GITEA_CLIENT_ID<<" --secret ">>GITEA_CLIENT_SECRET<<" --auto-discover-url ">>AUTH_SERVER_PUBLIC_URL<<"/.well-known/openid-configuration --config=/data/gitea/conf/app.ini
