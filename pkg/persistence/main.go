package persistence

import (
	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"

	"github.com/go-redis/redis/v8"
)

// databases ...
type databases struct {
	Redis *DBRedis
}

// DB ...
var DB *databases

// Bootstrap ...
func Bootstrap(redisConfig *config.Redis) error {
	/*
		@todo validate redis config
		Genrally this would not configurable by the SDK users

		The redis server on which the Auth data is stored will be controlled by SDK Developers
	*/

	redisOpts := &redis.FailoverOptions{
		MasterName:       redisConfig.MasterName,
		SentinelPassword: redisConfig.SentinelPassword,
		SentinelAddrs:    redisConfig.SentinelAddress,
		Password:         redisConfig.Password,
		DB:               redisConfig.Database,
	}
	redisClient := redis.NewFailoverClient(redisOpts)

	DB = &databases{}
	DB.Redis = &DBRedis{
		Config: &config.Redis{},
	}
	DB.Redis.Client = redisClient
	DB.Redis.Config.Delimiter = redisConfig.Delimiter
	DB.Redis.Config.Prefix = redisConfig.Prefix

	return nil
}
