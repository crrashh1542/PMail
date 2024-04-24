package res_init

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"os"
	"pmail/config"
	"pmail/db"
	"pmail/dto/parsemail"
	"pmail/hooks"
	"pmail/http_server"
	"pmail/models"
	"pmail/pop3_server"
	"pmail/services/setup/ssl"
	"pmail/session"
	"pmail/signal"
	"pmail/smtp_server"
	"pmail/utils/file"
)

func Init(serverVersion string) {

	if !config.IsInit {
		dirInit()

		log.Infof("Please click http://127.0.0.1 to continue.\n")
		go http_server.SetupStart()
		<-signal.InitChan
		http_server.SetupStop()
	}

	for {
		config.Init()
		// 启动前检查一遍证书
		ssl.Update(false)
		parsemail.Init()
		err := db.Init()
		if err != nil {
			panic(err)
		}
		models.SyncTables()
		session.Init()
		hooks.Init(serverVersion)
		// smtp server start
		go smtp_server.Start()
		go smtp_server.StartWithTLS()
		// http server start
		go http_server.HttpsStart()
		go http_server.HttpStart()
		// pop3 server start
		go pop3_server.Start()
		go pop3_server.StartWithTls()

		configStr, _ := json.Marshal(config.Instance)
		log.Warnf("Config File Info:  %s", configStr)

		<-signal.RestartChan
		log.Infof("Server Restart!")
		smtp_server.Stop()
		http_server.HttpsStop()
		http_server.HttpStop()
		pop3_server.Stop()
	}

}

func dirInit() {
	if !file.PathExist("./config") {
		err := os.MkdirAll("./config", 0744)
		if err != nil {
			panic(err)
		}
	}

	if !file.PathExist("./config/dkim") {
		err := os.MkdirAll("./config/dkim", 0744)
		if err != nil {
			panic(err)
		}
	}

	if !file.PathExist("./config/ssl") {
		err := os.MkdirAll("./config/ssl", 0744)
		if err != nil {
			panic(err)
		}
	}
}
