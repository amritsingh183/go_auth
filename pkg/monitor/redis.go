package monitor

import (
	"context"
	"time"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

// redisHearBeat check redis connectivity
func redisHearBeat(r *redis.Client) {
	_, err := r.Ping(ctx).Result()
	if err != nil {
		logger.Log("Unable to connect with Redis " + "\u274c")
	} else {
		logger.Log("Connected with Redis " + "\u2714")
	}
	key := util.GenerateShortID(128)
	val := util.GenerateShortID(128)
	err = r.Set(ctx, key, val, 0).Err()
	if err != nil {
		logger.Log("Unable to store data in Redis " + "\u274c")
		return
	}
	err = r.Del(ctx, key).Err()
	if err != nil {
		logger.Log("Unable to delete data from Redis " + "\u274c")
		return
	}
	return
}

// StartMonitoringRedis ...
func StartMonitoringRedis(t time.Duration, r *redis.Client, stop chan bool) {
	ticker := time.NewTicker(t)
	go func() {
		for {
			select {
			case <-stop:
				logger.Log("Stopping monitoring of redis....")
				ticker.Stop()
				logger.Log("Redis monitoring is now stopped")
				return
			case <-ticker.C:
				redisHearBeat(r)
			}
		}
	}()
	return
}
