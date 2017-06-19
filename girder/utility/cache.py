from dogpile.cache import make_region

# cache regions should be configured to use memcached/redis in distributed deployments
cacheRegion = make_region().configure('dogpile.cache.memory')
