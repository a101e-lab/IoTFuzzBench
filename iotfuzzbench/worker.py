import time

import redis
import rq
import subprocess
from multiprocessing import Pool, TimeoutError


def my_worker():
    print(id)
    redis_connection = redis.Redis()
    with rq.Connection(redis_connection):
        queue = rq.Queue('build_n_run_queue',default_timeout=5400)
        worker = rq.Worker([queue])
        while queue.count + queue.deferred_job_registry.count > 0:
            worker.work(burst=True)
            time.sleep(5)


if __name__ == '__main__':
    my_worker()