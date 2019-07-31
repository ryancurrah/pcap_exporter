package dns

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/prometheus/common/log"
)

type hitCache map[string]string
type missCache map[string]bool

type dnsCache struct {
	HitCache  hitCache
	MissCache missCache
}

var (
	cache   = dnsCache{}
	mutex   = sync.Mutex{}
	stop    = make(chan bool)
	stopAck = make(chan bool)
)

func (c dnsCache) GetHit(ip string) (record string) {
	mutex.Lock()
	if record, ok := cache.HitCache[ip]; ok {
		mutex.Unlock()
		log.Debugf("cache hit for ip %s", ip)
		return record
	}
	mutex.Unlock()
	log.Debugf("cache miss for ip %s", ip)
	return ""
}

func (c dnsCache) GetMiss(ip string) (exists bool) {
	mutex.Lock()
	if exists, ok := cache.MissCache[ip]; ok {
		mutex.Unlock()
		log.Debugf("ip %s is in miss cache", ip)
		return exists
	}
	mutex.Unlock()
	return false
}

func (c dnsCache) AddHit(ip, record string) {
	mutex.Lock()
	if cache.HitCache == nil {
		cache.HitCache = hitCache{}
	}
	cache.HitCache[ip] = record
	mutex.Unlock()
	log.Debugf("added ip %s with record %s to dns hit cache", ip, record)
}

func (c dnsCache) AddMiss(ip string) {
	mutex.Lock()
	if cache.MissCache == nil {
		cache.MissCache = missCache{}
	}
	cache.MissCache[ip] = true
	mutex.Unlock()
	log.Debugf("added ip %s to dns miss cache", ip)
}

func (c *dnsCache) Clear() {
	mutex.Lock()
	*c = dnsCache{}
	mutex.Unlock()
	log.Debug("cleared dns cache")
}

func Start() {
	go func() {
		for true {
			select {
			case <-stop:
				stopAck <- true
				return
			case <-time.After(10 * time.Minute):
				cache.Clear()
			}
		}
	}()
	log.Info("started dns cache")
}

func Stop() {
	select {
	case stop <- true:
		select {
		case <-stopAck:
			log.Info("stopped dns cache")
			return
		case <-time.After(200 * time.Millisecond):
			log.Warn("killing dns cache, due to not acknowledging stop")
		}
	case <-time.After(200 * time.Millisecond):
		log.Warn("killing dns cache, due to not stopping on time")
	}
}

func ReverseLookup(ip string) (record string, lookupTime float64, err error) {
	// if we have already tried looking this ip up don't try again
	alreadyMissed := cache.GetMiss(ip)
	if alreadyMissed {
		return record, 0.0, fmt.Errorf("ip address lookup has "+
			"failed before and is in miss cache not trying to lookup again: %s", ip)
	}

	// if we have ip in cache return record
	record = cache.GetHit(ip)
	if record != "" {
		return record, 0.0, err
	}

	// try looking up ip address
	start := time.Now()
	records, err := net.LookupAddr(ip)
	end := time.Now().Sub(start).Seconds()
	if err != nil {
		cache.AddMiss(ip)
		return "", 0.0, err
	}

	// add record to cache
	cache.AddHit(ip, records[0])
	return records[0], end, err
}
