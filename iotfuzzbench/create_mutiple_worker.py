import subprocess
from multiprocessing import Pool, TimeoutError
import signal
import os

def main():
    worker_num = 10
    python3_path = '/the/path/of/python3'
    processes = []

    for i in range(worker_num):
        worker_log_file_name = 'worker_log_file_name_'+str(i)
        with open(worker_log_file_name, "w") as outfile:
            process = subprocess.Popen(python3_path+' worker.py', stdout=outfile,shell=True)
            processes.append(process)
    try:
        for process in processes:
            process.wait()
    except KeyboardInterrupt:
        for process in processes:
            process.send_signal(signal.SIGINT)
            process.kill()
            os.killpg(os.getpgid(process.pid),9)

if __name__ == '__main__':
    main()