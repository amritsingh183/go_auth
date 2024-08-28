package persistence

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"
	"github.com/bsm/redislock"
	"github.com/go-redis/redis/v8"
)

const (
	//RedisNilValue RedisNilValue
	RedisNilValue = "redis: nil"
	MaxLockTime   = 500 * time.Millisecond
)

// DBRedis ...
type DBRedis struct {
	*redis.Client
	Config *config.Redis
}

// ChannelRedis ...
type ChannelRedis struct {
	Done  chan bool
	Value string
	Err   error
}

// ChannelRedisMap ...
type ChannelRedisMap struct {
	Done  chan bool
	Value map[string]string
	Err   error
}

func (dbs databases) makeRedisKey(k string) string {
	ukey := fmt.Sprintf("%s%s%s", dbs.Redis.Config.Prefix, dbs.Redis.Config.Delimiter, k)
	ukey = base64.StdEncoding.EncodeToString([]byte(ukey))
	return ukey
}

// HSetField ...Async Redis Hset, ingle field
// HSet("myhash", "key1", "value1")
func (dbs databases) HSetField(ctx context.Context, rc *ChannelRedis, hashName, key string, value interface{}) {
	hashName = dbs.makeRedisKey(hashName)
	locker := redislock.New(dbs.Redis)
	lock, err := locker.Obtain(ctx, dbs.Redis.Config.LockingKey, MaxLockTime, nil)
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	// Don't forget to defer Release.
	defer lock.Release(ctx)

	err = dbs.Redis.HSet(ctx, hashName, key, value).Err()
	if err != nil {
		rc.Err = err
	}
	rc.Done <- true
	return
}

// HSetFields ...Async Redis Hset, multiple fields
//
// HSet("myhash", map[string]interface{}{"key1": "value1", "key2": "value2"})
func (dbs databases) HSetFields(ctx context.Context, rc *ChannelRedis, hashName string, keyValuePairs map[string]interface{}) {
	hashName = dbs.makeRedisKey(hashName)
	locker := redislock.New(dbs.Redis)
	lock, err := locker.Obtain(ctx, dbs.Redis.Config.LockingKey, MaxLockTime, nil)
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	defer lock.Release(ctx)
	err = dbs.Redis.HSet(ctx, hashName, keyValuePairs).Err()
	if err != nil {
		rc.Err = err
	}
	rc.Done <- true
	return
}

// HashGet ...Async Redis HGet
//
// Returns empty string if the Hash itself does not exists or the key does not exists
func (dbs databases) HashGet(ctx context.Context, key, field string, rc *ChannelRedis) {
	ukey := dbs.makeRedisKey(key)
	locker := redislock.New(dbs.Redis)
	lock, err := locker.Obtain(ctx, dbs.Redis.Config.LockingKey, MaxLockTime, nil)
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	defer lock.Release(ctx)
	val, err := dbs.Redis.HGet(ctx, ukey, field).Result()
	if err != nil {
		if err.Error() == RedisNilValue {
			rc.Value = ""
			rc.Done <- true
			return
		}
		rc.Err = err
		rc.Done <- true
		return
	}
	rc.Value = val
	rc.Done <- true
	return
}

// HashExists ...Async Redis HExists.
// Checks for the existence of hash or hash and field
func (dbs databases) HashExists(ctx context.Context, key, field string, rc *ChannelRedis) {
	ukey := dbs.makeRedisKey(key)
	locker := redislock.New(dbs.Redis)
	lock, err := locker.Obtain(ctx, dbs.Redis.Config.LockingKey, MaxLockTime, nil)
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	defer lock.Release(ctx)
	exists, err := dbs.Redis.HExists(ctx, ukey, field).Result()
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	if exists {
		rc.Value = "true"
	} else {
		rc.Value = "false"
	}
	rc.Done <- true
	return
}

// HashGetAll ...Async Redis HGETALL
func (dbs databases) HashGetAll(ctx context.Context, key string, rc *ChannelRedisMap) {
	ukey := dbs.makeRedisKey(key)
	locker := redislock.New(dbs.Redis)
	lock, err := locker.Obtain(ctx, dbs.Redis.Config.LockingKey, MaxLockTime, nil)
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	defer lock.Release(ctx)
	val, err := dbs.Redis.HGetAll(ctx, ukey).Result()
	if err != nil {
		rc.Err = err
		rc.Done <- true
		return
	}
	rc.Value = val
	rc.Done <- true
	return
}
