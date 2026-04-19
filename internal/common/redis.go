package common

import (
	"context"

	"github.com/go-redis/redis/v8"

	"lumid_identity/internal/config"
)

var Redis *redis.Client

func OpenRedis(c *config.Config) error {
	Redis = redis.NewClient(&redis.Options{
		Addr:     c.Redis.Addr,
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})
	return Redis.Ping(context.Background()).Err()
}
