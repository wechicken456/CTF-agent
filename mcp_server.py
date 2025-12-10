import os
import subprocess
import uuid
import shlex
import logging
import sys
import time
from dotenv import load_dotenv
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from contextlib import asynccontextmanager

import docker
from docker.errors import NotFound, APIError
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from dataclasses import dataclass, field, asdict
import psutil
import threading
import queue
import secrets 
from pathvalidate import sanitize_filename, sanitize_filepath
load_dotenv()

# MCP uses stdio transport, so logs MUST go to stderr
logging.basicConfig(
    filename=f"logs_{time.time()}",
    filemode="a",
    level=logging.INFO,
    format='%(asctime)s, [%(levelname)s], [%(message)s]',
    stream=sys.stderr
)
logger = logging.getLogger("SleepyKitty")

mcp = FastMCP("SleepyKitty")

@mcp.tool()
def echo_test(message: str) -> str:
    """
    Use this tool to verify the MCP server is working. 
    It returns your message back and also writes it to the logs.
    """
    logger.info(f"echo_test: {message}")
    return f"You said: {message}"


def wrap_status_str(status: str) -> str:
    return f"<Status>{status}</Status>"

def wrap_error_str(error: str) -> str:
    return f"<Error>{error}</Status>"

def generate_random_filename(suffix : str = "") -> str:
    return secrets.token_hex(12) + suffix

def create_file(filename: str, content: str, binary : bool = False):
    try:
        if not os.path.exists("/tmp/ctf_workspace"):
            os.mkdir("/tmp/ctf_workspace")
        filepath = "/tmp/ctf_workspace" + filename
        mode = "wb" if binary else "w"
        with open(filepath, mode) as f:
            if binary:
                f.write(content.encode() if isinstance(content, str) else content)
            else:
                f.write(content)
    except Exception as e:
        logger.info(f"create_file {filename} exception: {str(e)}")


def remove_file(filepath: str):
    try:
        os.remove(filepath)
    except Exception as e:
        logger.info(f"remove_file {filepath} exception: {str(e)}")

@dataclass
class EnigmaResponse:
    """EnIGMA-style structured response"""
    status: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    note: str = ""
    task_id: Optional[str] = None
    
    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None}


class ResourceMonitor:
    """Advanced resource monitoring with historical tracking"""

    def __init__(self, history_size=100):
        self.history_size = history_size
        self.usage_history = []
        self.history_lock = threading.Lock()

    def get_current_usage(self) -> Dict[str, float]:
        """Get current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            usage = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }

            # Add to history
            with self.history_lock:
                self.usage_history.append(usage)
                if len(self.usage_history) > self.history_size:
                    self.usage_history.pop(0)

            return usage

        except Exception as e:
            logger.error(f"💥 Error getting resource usage: {str(e)}")
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "memory_available_gb": 0,
                "disk_percent": 0,
                "disk_free_gb": 0,
                "network_bytes_sent": 0,
                "network_bytes_recv": 0,
                "timestamp": time.time()
            }

    def get_process_usage(self, pid: int) -> Dict[str, Any]:
        """Get resource usage for specific process"""
        try:
            process = psutil.Process(pid)
            return {
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent(),
                "memory_rss_mb": process.memory_info().rss / (1024**2),
                "num_threads": process.num_threads(),
                "status": process.status()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}

class ProcessPool:
    """Intelligent process pool with auto-scaling capabilities"""

    def __init__(self, min_workers=2, max_workers=20, scale_threshold=0.8):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_threshold = scale_threshold
        self.workers = []
        self.task_queue = queue.Queue()
        self.results = {}
        self.pool_lock = threading.Lock()
        self.active_tasks = {}
        self.performance_metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_task_time": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0
        }

        # Initialize minimum workers
        self._scale_up(self.min_workers)

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()

    def submit_task(self, task_id: str, func, *args, **kwargs) -> str:
        """Submit a task to the process pool"""
        task = {
            "id": task_id,
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "submitted_at": time.time(),
            "status": "queued"
        }

        with self.pool_lock:
            self.active_tasks[task_id] = task
            self.task_queue.put(task)

        logger.info(f"📋 Task submitted to pool: {task_id}")
        return task_id

    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of a submitted task"""
        with self.pool_lock:
            if task_id in self.results:
                return self.results[task_id]
            elif task_id in self.active_tasks:
                return {"status": self.active_tasks[task_id]["status"], "result": None}
            else:
                return {"status": "not_found", "result": None}

    def _worker_thread(self, worker_id: int):
        """Worker thread that processes tasks"""
        logger.info(f"🔧 Process pool worker {worker_id} started")

        while True:
            try:
                # Get task from queue with timeout
                task = self.task_queue.get(timeout=30)
                if task is None:  # Shutdown signal
                    break

                task_id = task["id"]
                start_time = time.time()

                # Update task status
                with self.pool_lock:
                    if task_id in self.active_tasks:
                        self.active_tasks[task_id]["status"] = "running"
                        self.active_tasks[task_id]["worker_id"] = worker_id
                        self.active_tasks[task_id]["started_at"] = start_time

                try:
                    # Execute task
                    result = task["func"](*task["args"], **task["kwargs"])

                    # Store result
                    execution_time = time.time() - start_time
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "completed",
                            "result": result,
                            "execution_time": execution_time,
                            "worker_id": worker_id,
                            "completed_at": time.time()
                        }

                        # Update performance metrics
                        self.performance_metrics["tasks_completed"] += 1
                        self.performance_metrics["avg_task_time"] = (
                            (self.performance_metrics["avg_task_time"] * (self.performance_metrics["tasks_completed"] - 1) + execution_time) /
                            self.performance_metrics["tasks_completed"]
                        )

                        # Remove from active tasks
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]

                    logger.info(f"✅ Task completed: {task_id} in {execution_time:.2f}s")

                except Exception as e:
                    # Handle task failure
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "failed",
                            "error": str(e),
                            "execution_time": time.time() - start_time,
                            "worker_id": worker_id,
                            "failed_at": time.time()
                        }

                        self.performance_metrics["tasks_failed"] += 1

                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]

                    logger.error(f"❌ Task failed: {task_id} - {str(e)}")

                self.task_queue.task_done()

            except queue.Empty:
                # No tasks available, continue waiting
                continue
            except Exception as e:
                logger.error(f"💥 Worker {worker_id} error: {str(e)}")

    def _monitor_performance(self):
        """Monitor pool performance and auto-scale"""
        while True:
            try:
                time.sleep(10)  # Monitor every 10 seconds

                with self.pool_lock:
                    queue_size = self.task_queue.qsize()
                    active_workers = len([w for w in self.workers if w.is_alive()])
                    active_tasks_count = len(self.active_tasks)

                # Calculate load metrics
                if active_workers > 0:
                    load_ratio = (active_tasks_count + queue_size) / active_workers
                else:
                    load_ratio = float('inf')

                # Auto-scaling logic
                if load_ratio > self.scale_threshold and active_workers < self.max_workers:
                    # Scale up
                    new_workers = min(2, self.max_workers - active_workers)
                    self._scale_up(new_workers)
                    logger.info(f"📈 Scaled up process pool: +{new_workers} workers (total: {active_workers + new_workers})")

                elif load_ratio < 0.3 and active_workers > self.min_workers:
                    # Scale down
                    workers_to_remove = min(1, active_workers - self.min_workers)
                    self._scale_down(workers_to_remove)
                    logger.info(f"📉 Scaled down process pool: -{workers_to_remove} workers (total: {active_workers - workers_to_remove})")

                # Update performance metrics
                try:
                    cpu_percent = psutil.cpu_percent()
                    memory_info = psutil.virtual_memory()

                    with self.pool_lock:
                        self.performance_metrics["cpu_usage"] = cpu_percent
                        self.performance_metrics["memory_usage"] = memory_info.percent

                except Exception:
                    pass  # Ignore psutil errors

            except Exception as e:
                logger.error(f"💥 Pool monitor error: {str(e)}")

    def _scale_up(self, count: int):
        """Add workers to the pool"""
        with self.pool_lock:
            for i in range(count):
                worker_id = len(self.workers)
                worker = threading.Thread(target=self._worker_thread, args=(worker_id,), daemon=True)
                worker.start()
                self.workers.append(worker)

    def _scale_down(self, count: int):
        """Remove workers from the pool"""
        with self.pool_lock:
            for _ in range(count):
                if len(self.workers) > self.min_workers:
                    # Signal worker to shutdown by putting None in queue
                    self.task_queue.put(None)
                    # Remove from workers list (worker will exit naturally)
                    if self.workers:
                        self.workers.pop()

    def get_pool_stats(self) -> Dict[str, Any]:
        """Get current pool statistics"""
        with self.pool_lock:
            active_workers = len([w for w in self.workers if w.is_alive()])
            return {
                "active_workers": active_workers,
                "queue_size": self.task_queue.qsize(),
                "active_tasks": len(self.active_tasks),
                "performance_metrics": self.performance_metrics.copy(),
                "min_workers": self.min_workers,
                "max_workers": self.max_workers
            }


# ======================= Async task Manager =============================
class EnhancedProcessManager:
    """Advanced process management with intelligent resource allocation"""

    def __init__(self):
        self.process_pool = ProcessPool(min_workers=4, max_workers=32)
        self.resource_monitor = ResourceMonitor()
        self.process_registry = {}
        self.registry_lock = threading.RLock()

        # Process termination and recovery
        self.termination_handlers = {}
        self.recovery_strategies = {}

        # Auto-scaling configuration
        self.auto_scaling_enabled = True
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0,
            "disk_high": 95.0,
            "load_high": 0.8
        }

        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()

    def execute_command_async(self, command: str, context: Dict[str, Any] = None) -> str:
        """Execute command asynchronously using process pool"""
        task_id = f"cmd_{int(time.time() * 1000)}_{hash(command) % 10000}"

        # Submit to process pool
        self.process_pool.submit_task(
            task_id,
            self._execute_command_internal,
            command,
            context or {}
        )

        return task_id

    def _execute_command_internal(self, command: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Internal command execution with enhanced monitoring"""
        start_time = time.time()

        try:
            resource_usage = self.resource_monitor.get_current_usage()

            # Adjust command based on resource availability
            if resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"]:
                # Add nice priority for CPU-intensive commands
                if not command.startswith("nice"):
                    command = f"nice -n 10 {command}"

            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )

            # Register process
            with self.registry_lock:
                self.process_registry[process.pid] = {
                    "command": command,
                    "process": process,
                    "start_time": start_time,
                    "context": context,
                    "status": "running"
                }

            # Monitor process execution
            stdout, stderr = process.communicate()
            execution_time = time.time() - start_time

            result = {
                "success": process.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": process.returncode,
                "execution_time": execution_time,
                "pid": process.pid,
                "resource_usage": self.resource_monitor.get_process_usage(process.pid)
            }

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            error_result = {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": execution_time,
                "error": str(e)
            }

            return error_result

        finally:
            # Cleanup process registry
            with self.registry_lock:
                if hasattr(process, 'pid') and process.pid in self.process_registry:
                    del self.process_registry[process.pid]

    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of async task"""
        return self.process_pool.get_task_result(task_id)

    def terminate_process_gracefully(self, pid: int, timeout: int = 30) -> bool:
        """Terminate process with graceful degradation"""
        try:
            with self.registry_lock:
                if pid not in self.process_registry:
                    return False

                process_info = self.process_registry[pid]
                process = process_info["process"]

                # Try graceful termination first
                process.terminate()

                # Wait for graceful termination
                try:
                    process.wait(timeout=timeout)
                    process_info["status"] = "terminated_gracefully"
                    logger.info(f"✅ Process {pid} terminated gracefully")
                    return True
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    process.kill()
                    process_info["status"] = "force_killed"
                    logger.warning(f"⚠️ Process {pid} force killed after timeout")
                    return True

        except Exception as e:
            logger.error(f"💥 Error terminating process {pid}: {str(e)}")
            return False

    def _monitor_system(self):
        """Monitor system resources and auto-scale"""
        while True:
            try:
                time.sleep(15)  

                # Get current resource usage
                resource_usage = self.resource_monitor.get_current_usage()

                # Auto-scaling based on resource usage
                if self.auto_scaling_enabled:
                    self._auto_scale_based_on_resources(resource_usage)

            except Exception as e:
                logger.error(f"💥 System monitoring error: {str(e)}")

    def _auto_scale_based_on_resources(self, resource_usage: Dict[str, float]):
        """Auto-scale process pool based on resource usage"""
        pool_stats = self.process_pool.get_pool_stats()
        current_workers = pool_stats["active_workers"]

        # Scale down if resources are constrained
        if (resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"] or
            resource_usage["memory_percent"] > self.resource_thresholds["memory_high"]):

            if current_workers > self.process_pool.min_workers:
                self.process_pool._scale_down(1)
                logger.info(f"📉 Auto-scaled down due to high resource usage: CPU {resource_usage['cpu_percent']:.1f}%, Memory {resource_usage['memory_percent']:.1f}%")

        # Scale up if resources are available and there's demand
        elif (resource_usage["cpu_percent"] < 60 and
              resource_usage["memory_percent"] < 70 and
              pool_stats["queue_size"] > 2):

            if current_workers < self.process_pool.max_workers:
                self.process_pool._scale_up(1)
                logger.info(f"📈 Auto-scaled up due to available resources and demand")

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive system and process statistics"""
        return {
            "process_pool": self.process_pool.get_pool_stats(),
            "resource_usage": self.resource_monitor.get_current_usage(),
            "active_processes": len(self.process_registry),
            "auto_scaling_enabled": self.auto_scaling_enabled,
            "resource_thresholds": self.resource_thresholds
        }

task_manager = EnhancedProcessManager()



# ======================= Tools that run directly on host ====================
def execute_command_sync(cmd: str, timeout = 30) -> Any:
    logger.info(f"execute_command_sync in progress for command: {cmd}...")
    try:
        start = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result = {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "execution_time": time.time() - start,
        }        
        logger.info(f"execute_command_sync call returned:\n{result}")
        return result

    except subprocess.TimeoutExpired:
        return ToolError(wrap_error_str("Request timed out"))

    except Exception as e:
        logger.info(f"execute_command_sync call exception: {str(e)}")
        return ToolError(wrap_error_str(f"call exception: {str(e)}"))



@mcp.tool()
def curl(url: str, method: str = "GET", headers :list[str] = [], additional_args: str = "") -> str | Any:
    """
    Makes HTTP requests
    Args:
        url: Target URL 
        method: (GET, POST, etc.)
        headers: Optional headers as a list of strings (e.g., ["Authorization: Bearer token, "X-Forwarded-For: ..."])
        additional_args (str): any extra command-line arguments to provide to curl as a string

    """
    http_methods = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT"
    ]
    logger.info(f"curl call: {method}, {url} {headers}")
    method = method.upper()
    if method.upper() not in http_methods:
        return f"Error: invalid argument method {method}. Need one of {http_methods}"

    cmd = f"curl -s -X {method}"
    for header in headers:
        cmd += f" -H '{header}'"
    cmd += f" {url}"
    
    cmd += f" {additional_args}"
    return execute_command_sync(cmd)

@mcp.tool()
def xxd(file_path : str, offset: int = 0, length : int = 0, additional_args : str = ""):
    """
    Create a hex dump of a file using xxd
    Args:
        file_path (str): full path or relative path 
        offset (int): offset from beginning of file to start from
        length (int): length of hex dump
        additional_args (str): any extra command-line arguments (as a string) to provide to xxd 
    """

    logger.info(f"xxd call: {file_path} {offset} {length} {additional_args}")
    command = f"xxd -s {str(offset)}"
    if length:
        command += f" -l {length}"
    if additional_args:
        command += f" {additional_args}"

    command += f" {file_path}"
    logger.info(f"Starting xxd command: {command}...")
    return execute_command_sync(command)

@mcp.tool()
def exiftool(filepath: str, output_format: str = "", tags: str = "", additional_args : str = ""):
    """
    Execute ExifTool for metadata extraction.

    Args:
        file_path: Path to file for metadata extraction
        output_format: Output format (json, xml, csv)
        tags: Specific tags to extract
        additional_args: any extra command-line arguments (as a string) to provide to exiftool

    Returns:
        Metadata extraction results
    """
    command = "exiftool"
    if output_format:
        command += f" -{output_format}" 
    if tags:
        command += f" -{tags}"

    if additional_args:
        command += f" {additional_args}"

    command += f" {filepath}"
    logger.info(f"exiftool call: {filepath} {output_format} {tags} {additional_args}")
    return execute_command_sync(command)

   
@mcp.tool()
def run_python_script(script_content: str, filename: str = ""):
    """
    Execute a Python script

    Args:
        script_content (str): Python script content to execute
        filename (str): name of file that script_content will be saved to (auto-generated if empty). It will be saved to "/tmp/ctf_workspace" directory. You MUST NOT pass in any path separator and MUST ONLY pass in the filename.

    Returns:
        script execution results
    """

    logger.info(f"run_python_script call: {script_content[:min(500,len(script_content))]}... {filename}")
    if filename == "":
        filename = generate_random_filename(suffix = ".py")
    create_file(filename, script_content)   
    command = f"uv run {filename}"
    result = execute_command_sync(command)
    remove_file(filename)
    return result


@mcp.tool()
def install_python_package(package: str):
    """
    Install a package in the current python virtual environment through `uv add`.

    Args:
        package: Name of the python package

    Returns:
        package installation results
    """
    logger.info(f"install_python_package call: {package}")
    command = f"uv add {package}"
    return execute_command_sync(command, timeout=120)
    
@mcp.tool()
def list_files(directory: str = "."):
    """
    List files in a directory on host machine.
    
    Args:
        directory: directory to list (relative to MCP server's base directory). Default to "."

    Returns:
        directory listing results
    """
    logger.info(f"list_files call: {directory}")
    command = f"ls -l {directory}"
    return execute_command_sync(command)

@mcp.tool()
def delete_file(filepath: str):
    """
    delete a file or directory on the host machine running the MCP server. You are only allowed to pass in files in "/tmp/ctf_workspace" directory.

    Args:
        filepath: path to file or directory to delete.

    Returns:
        Deletion results
    """
    
    logger.info(f"delete_file call: {filepath}")
    # sanitize paths first
    # remove redundant "." and ".." to prevent path traversal 
    filepath = os.path.normpath(filepath)
    if "/" in filepath:
        filepath = sanitize_filepath(filepath)
    else:
        filepath = sanitize_filename(filepath)

@mcp.tool()
def _create_file(filename: str, content: str, binary : bool = False):
    """
    Create a file with specified content on the host server at /tmp/workspace/

        Args:
            filename: Name of the file to create
            content: Content to write to the file
            binary: Whether the content is binary data
        Returns:
            File creation results
    """
    logger.info(f"_create_file call: {filename} {content[:min(100, len(content))]} {binary}")
    return create_file(filename, content, binary)

@mcp.tool()
def run_arbitrary_command_on_host(command: str) -> str | Any:
    """
    Runs a shell command on the host machine where this MCP server is running.
    Use this to run the tools that the MCP server doesn't expose, but exists on the host machine.

    WARNING: You MUST NOT run any type of interactive commands via this tool.
    """
    logger.info(f"Running host shell command: {command}")
    return execute_command_sync(command)

@mcp.tool()
def give_up():
    """
    Call this when you give up on solving this challenge. You may stop your response after printing out the results of calling this tool.

    Returns:
        a string telling the user that you have given up
    """
    return "LLM has given up. Stop solving now."

# ========================= Tools that run on docker containers ================
#PYTHON_CONTAINER_NAME = os.getenv("PYTHON_CONTAINER_NAME")
#WEB_CONTAINER_NAME = os.getenv("WEB_CONTAINER_NAME")
#NETWORK_CONTAINER_NAME = os.getenv("NETWORK_CONTAINER_NAME")
#
#def execute_async_command(container_name: str, command: str):
#
#
#try:
#    docker_client = docker.from_env()
#    logger.info(f"Docker client initialized...")
#except Exception as e:
#    logger.error(f"Docker cliet failed to initialize with exception: {str(e)}")
#    docker_client = None

@mcp.tool()
def run_ffuf_scan(
    url: str, 
    wordlist = "/opt/wordlist/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt",
    mode = "directory",
    match_codes = "200,204,301,302,307,401,403",
    additional_args = None) -> str | Any:
    """
    Submit a background task to perform a ffuf scan.

    Args:
        url: target
        wordlist (str): path to wordlist on the WEB docker container. Most of the times the prefix should be /opt/wordlist/
        mode (str): "directory" or "vhost" or "parameter". vhost is for fuzzing the "Host" header, "parameter" is for fuzzing URL parameters
        match_codes (str): keep only responses matching the status codes specified. Provide a list of status code separated by commas. 
        additional_args (str): any extra command-line arguments to provide to ffuf

    EXAMPLE:
        calling this function with default arguments is equal to the command line: 
        `ffuf -u {target} -w /opt/wordlist/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,204,301,302,307,401,403 {additional_args}
    """

    if not url:
        logger.warning("🌐 FFuf called without URL parameter!")
        return ToolError(wrap_error_str("URL parameter is required"))

    command = f"ffuf"

    if mode == "directory":
        command += f" -u {url}/FUZZ -w {wordlist}"
    elif mode == "vhost":
        command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
    elif mode == "parameter":
        command += f" -u {url}?FUZZ=value -w {wordlist}"
    else:
        command += f" -u {url} -w {wordlist}"

    command += f" -mc {match_codes}"

    if additional_args:
        command += f" {additional_args}"
    
    logger.info(f"🔍 Starting ffuf {mode} fuzzing: {url}")
    result = task_manager.execute_command_async(command)
    logger.info(f"📊 ffuf fuzzing completed for {url}")
    return result




if __name__ =="__main__":
    logger.info(f"SleepyKitty starting...")
    mcp.run()
