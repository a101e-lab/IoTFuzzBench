# --coding:utf-8--
from rq import Queue
from redis import Redis
import rq
import time
from fuzz_job import fuzz_job
import yaml
import os
from rq import Retry

def fuzz_process_parameter_check(fuzzer_name,fuzzer_path,benchmark_name,benchmark_path,seed_name):
    print(fuzzer_name)
    print(fuzzer_path)
    print(benchmark_name)
    print(benchmark_path)
    print(seed_name)
    return 0

def run_experiment(config):
    print('Initializing the job queue.')
    queue = rq.Queue('build_n_run_queue',default_timeout=5400)
    queue.empty()


    benchmarks_to_test = config['benchmarks']
    fuzzers_to_test = config['fuzzers']
    jobs_list = []
    fuzz_minutes = 60

    result_dir = '../results_experiment/'
    if not os.path.exists(result_dir):
        os.mkdir(result_dir)
    subfolders = [ f.name for f in os.scandir(result_dir) if f.is_dir() ]
    if(len(subfolders)==0):
        dir_id = str(0)
    else:
        for i in range(200):
            if(str(i) not in subfolders):
                dir_id = str(i)
                break
    result_dir = os.path.join(result_dir,dir_id)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    for single_fuzzer in fuzzers_to_test:
        for single_benchmark in benchmarks_to_test:
            for single_seed in benchmarks_to_test[single_benchmark]['seed_list']:
                fuzzer_name = single_fuzzer
                if('boofuzz' in fuzzer_name):
                    fuzzer_path = os.path.join('../fuzzer/','boofuzz')
                else:
                    fuzzer_path = os.path.join('../fuzzer/',fuzzer_name)
                benchmark_name = single_benchmark
                benchmark_path = os.path.join('../benchmarks/',benchmark_name)
                seed_name = single_seed

                fuzz_process_parameter_check(fuzzer_name,fuzzer_path,benchmark_name,benchmark_path,seed_name)

                jobs_list.append(queue.enqueue(
                fuzz_job,
                fuzzer_name=fuzzer_name,
                fuzzer_path=fuzzer_path,
                benchmark_name=benchmark_name,
                benchmark_path=benchmark_path,
                seed_name=seed_name,
                result_base_dir = result_dir,MAX_WAIT_COUNT = fuzz_minutes,
                retry=Retry(max=3, interval=[10, 30, 60])))

    while True:
        print('Current status of jobs:')
        print('\tqueued:\t%d' % queue.count)
        print('\tstarted:\t%d' % queue.started_job_registry.count)
        print('\tdeferred:\t%d' % queue.deferred_job_registry.count)
        print('\tfinished:\t%d' % queue.finished_job_registry.count)
        print('\tfailed:\t%d' % queue.failed_job_registry.count)
        for job in jobs_list:
            print('  %s : %s\t(%s)' % (job.func_name, job.get_status(), job.id))

        if all([job.result is not None for job in jobs_list]): 
            break
        time.sleep(3)
    print('All done!')

def main():
    """Set up Redis connection and start the experiment."""
    redis_connection = Redis()

    config_path = './config.yml'

    with open(config_path, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    print(config)


    with rq.Connection(redis_connection):
        return run_experiment(config)


if __name__ == '__main__':
    main()