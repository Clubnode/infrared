package main

import (
	"flag"
	"github.com/cloudflare/tableflip"
	"github.com/haveachin/infrared"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

const (
	envPrefix     = "INFRARED_"
	envConfigPath = envPrefix + "CONFIG_PATH"
)

const (
	clfConfigPath = "config-path"
)

var (
	configPath = "./configs"
)

func envString(name string, value string) string {
	envString := os.Getenv(name)
	if envString == "" {
		return value
	}

	return envString
}

func initEnv() {
	configPath = envString(envConfigPath, configPath)
}

func initFlags() {
	flag.StringVar(&configPath, clfConfigPath, configPath, "path of all proxy configs")
	flag.Parse()
}

func init() {
	initEnv()
	initFlags()
}

func main() {
	log.SetPrefix(strconv.Itoa(os.Getpid()) + " ")
	log.Println("Loading global config")
	err := infrared.LoadGlobalConfig()
	if err != nil {
		log.Println(err)
		return
	}

	var cfgs []*infrared.ProxyConfig
	outCfgs := make(chan *infrared.ProxyConfig)

	log.Printf("Loading proxy configs from %s", configPath)
	cfgs, err = infrared.LoadProxyConfigsFromPath(configPath, false)
	if err != nil {
		log.Printf("Failed loading proxy configs from %s; error: %s", configPath, err)
		return
	}

	go func() {
		if err := infrared.WatchProxyConfigFolder(configPath, outCfgs); err != nil {
			log.Println("Failed watching config folder; error:", err)
			log.Println("SYSTEM FAILURE: CONFIG WATCHER FAILED")
		}
	}()

	var proxies []*infrared.Proxy
	for _, cfg := range cfgs {
		proxies = append(proxies, &infrared.Proxy{
			Config: cfg,
		})
	}

	gateway := infrared.Gateway{ReceiveProxyProtocol: infrared.Config.ReceiveProxyProtocol}
	go func() {
		for {
			cfg, ok := <-outCfgs
			if !ok {
				return
			}

			proxy := &infrared.Proxy{Config: cfg}
			if err := gateway.RegisterProxy(proxy); err != nil {
				log.Println("Failed registering proxy; error:", err)
			}
		}
	}()

	if infrared.Config.Tableflip.Enabled {
		log.Println("Starting tableflip upgrade listener")

		var err error
		infrared.Upg, err = tableflip.New(tableflip.Options{
			PIDFile: infrared.Config.Tableflip.PIDfile,
		})
		if err != nil {
			log.Printf("Failed to set up Tableflip Upgrader: %s", err)
			return
		}

		go func() {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGHUP)
			for range sig {
				err := infrared.Upg.Upgrade()
				if err != nil {
					log.Println("upgrade failed:", err)
				}
			}
		}()
	}

	if infrared.Config.Prometheus.Enabled {
		err := gateway.EnablePrometheus(infrared.Config.Prometheus.Bind)
		if err != nil {
			log.Println(err)
			return
		}

		if infrared.Config.TrackBandwidth {
			go func() {
				for {
					gateway.TrackBandwith()
				}
			}()
		}
	}

	log.Println("Starting gateway listeners")
	if err := gateway.ListenAndServe(proxies); err != nil {
		log.Fatal("Gateway exited; error: ", err)
	}

	if infrared.Config.Tableflip.Enabled {
		if err := infrared.Upg.Ready(); err != nil {
			panic(err)
		}
		<-infrared.Upg.Exit()
		log.Println("Starting tableflip shutdown for old instance")
		gateway.Close()

		gateway.WaitConnGroup()
		log.Println("Shutting down infrared")
	} else {
		gateway.KeepProcessActive()
	}
}