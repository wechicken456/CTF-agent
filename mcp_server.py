import os
import subprocess
import logging
import time
import csv
import secrets
from typing import Any
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from fastmcp import FastMCP
load_dotenv()

if not os.path.exists("/tmp/ctf_workspace"):
    os.makedirs("/tmp/ctf_workspace", exist_ok=True)

# MCP uses stdio transport, so logs MUST go to stderr
logging.basicConfig(
    filename=f"logs/logs_{time.time()}",
    filemode="a",
    level=logging.INFO,
    format='%(asctime)s, [%(levelname)s], [%(message)s]',
    #stream=sys.stderr
)
logger = logging.getLogger("SleepyKitty")

# ======================= Statistics Logging =======================
class StatsLogger:
    def __init__(self, log_dir: str = "logs/statistics"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.challenge_name = ""
        self.category = ""

    def _init_csv(self):
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'session_id', 'challenge_name', 'category',
                'tool_name', 'duration_sec', 'success', 'error_msg',
                'elapsed_session_sec'
            ])
    
    def set_challenge(self, name: str, category: str = ""):
        self.session_id = f"{category}_{name}_{secrets.token_hex(4)}"
        self.csv_file = os.path.join(self.log_dir, f"{self.session_id}.csv")
        self.challenge_name = name
        self.category = category
        self.session_start = time.time()
        self._init_csv()

    def log(self, tool_name: str, duration: float, success: bool, error_msg: str = ""):
        elapsed = time.time() - self.session_start
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                self.session_id,
                self.challenge_name,
                self.category,
                tool_name,
                round(duration, 4),
                success,
                error_msg,
                round(elapsed, 2)
            ])

stats = StatsLogger()

def track_tool(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        error_msg = ""
        success = True
        try:
            result = func(*args, **kwargs)
            if isinstance(result, str) and "<Error>" in result:
                success = False
                error_msg = result
            elif isinstance(result, dict) and not result.get("success", True):
                success = False
                error_msg = result.get("stderr", "")
            return result
        except Exception as e:
            success = False
            error_msg = str(e)
            raise
        finally:
            stats.log(func.__name__, time.time() - start, success, error_msg)
    return wrapper



mcp = FastMCP("SleepyKitty")

@mcp.tool()
def set_challenge_info(challenge_name: str, category: str = "") -> str:
    """
    Set the current challenge name and category for statistics tracking.
    Call this at the start of solving a challenge.
    """
    stats.set_challenge(challenge_name, category)
    return f"Tracking: {challenge_name} ({category}) - Session: {stats.session_id}"

@mcp.tool()
@track_tool
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

def create_temp_file(filepath: str, content: str, binary : bool = False):
    try:
        mode = "wb" if binary else "w"
        with open(filepath, mode) as f:
            if binary:
                f.write(content.encode() if isinstance(content, str) else content)
            else:
                f.write(content)
        return filepath
    except Exception as e:
        logger.info(f"create_temp_file {filepath} exception: {str(e)}")


def remove_file(filepath: str):
    try:
        os.remove(filepath)
    except Exception as e:
        logger.info(f"remove_file {filepath} exception: {str(e)}")


# ======================= Tools that run directly on host ====================
def execute_command_sync(cmd: str, timeout = 30) -> Any:
    logger.info(f"execute_command_sync in progress for command: {cmd}...")
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout,
        )
        duration = time.time() - start_time
        result = {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "execution_time": duration,
        }        
        logger.info(f"execute_command_sync call returned:\n{result}")
        return result

    except subprocess.TimeoutExpired:
        return wrap_error_str("Request timed out")

    except Exception as e:
        logger.info(f"execute_command_sync call exception: {str(e)}")
        return wrap_error_str(f"call exception: {str(e)}")



@mcp.tool()
@track_tool
def curl(url: str, method: str = "GET", headers :list[str] = [], additional_args: str = "") -> str | Any:
    """
    Makes HTTP requests
    Args:
        url: Target URL 
        method: (GET, POST, etc.)
        headers: Optional headers as a list of strings (e.g., ["Authorization: Bearer token", "X-Forwarded-For: ..."])
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
@track_tool
def xxd(file_path : str, offset: int = 0, length : int = 0, additional_args : str = ""):
    """
    Create a hex dump of a file using xxd
    Args:
        file_path (str): ABSOLUTE path to the file (e.g., /tmp/ctf_workspace/file.bin)
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
@track_tool
def exiftool(filepath: str, output_format: str = "", tags: str = "", additional_args : str = ""):
    """
    Execute ExifTool for metadata extraction.

    Args:
        filepath: ABSOLUTE path to file for metadata extraction (e.g., /tmp/ctf_workspace/image.jpg)
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
@track_tool
def run_python_script(script_content: str, filename: str = ""):
    """
    Execute a Python script. Only use this to run short snippets of Python code that don't need to be saved permanently.

    Args:
        script_content (str): Python script content to execute
        filename (str): name of file that script_content will be saved to (auto-generated if empty). It will be saved to "/tmp/ctf_workspace" directory. You MUST NOT pass in any path separator and MUST ONLY pass in the filename.

    Returns:
        script execution results
    """

    logger.info(f"run_python_script call: {script_content[:min(500,len(script_content))]}... {filename}")
    if filename == "":
        filename = generate_random_filename(suffix = ".py")
    full_filepath = os.path.join("/tmp/ctf_workspace", filename)
    create_temp_file(full_filepath, script_content)   
    command = f"uv run {full_filepath}"
    result = execute_command_sync(command)
    remove_file(full_filepath)
    return result


@mcp.tool()
@track_tool
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
@track_tool
def list_files(directory: str = "."):
    """
    List files in a directory on host machine.
    
    Args:
        directory: directory to list. Must be ABSOLUTE path. Without an absolute path, it is relative to the MCP server's base directory.

    Returns:
        directory listing results
    """
    logger.info(f"list_files call: {directory}")
    command = f"ls -l {directory}"
    return execute_command_sync(command)

@mcp.tool()
@track_tool
def checksec(binary: str, additional_args: str = "") -> str | Any:
    """
    Check security features of a binary using checksec.
    
    Args:
        binary: ABSOLUTE path to the binary file to analyze (e.g., /tmp/ctf_workspace/binary)
        additional_args: any extra command-line arguments to provide to checksec
        
    Returns:
        Security features analysis results
    """
    if not binary:
        logger.warning("🔧 Checksec called without binary parameter")
        return wrap_error_str("'binary' parameter is required and MUST BE absolute path not relative path")
    
    command = f"checksec --file={binary}"
    
    if additional_args:
        command += f" {additional_args}"
    
    logger.info(f"checksec call: {command}")
    result = execute_command_sync(command)
    logger.info(f"checksec completed for: {binary}")
    return result

@mcp.tool()
@track_tool
def ropgadget(binary: str, gadget_type: str = "", additional_args: str = "") -> str | Any:
    """
    Search for ROP gadgets in a binary using ROPgadget.
    
    Args:
        binary: ABSOLUTE path to the binary file to analyze (e.g., /tmp/ctf_workspace/binary)
        gadget_type: Specific gadget type to search for (e.g., 'pop|ret', 'jmp|call')
        additional_args: any extra command-line arguments to provide to ROPgadget
        
    Returns:
        ROP gadget search results
    """
    if not binary:
        logger.warning("ropgadget called without binary parameter")
        return wrap_error_str("'binary' parameter is required")
    
    command = f"ROPgadget --binary {binary}"
    
    if gadget_type:
        command += f" --only '{gadget_type}'"
    
    if additional_args:
        command += f" {additional_args}"
    
    logger.info(f"ropgadget call: {binary}")
    result = execute_command_sync(command)
    logger.info(f"ropgadget completed for: {binary}")
    return result

@mcp.tool()
@track_tool
def binwalk(file_path: str, extract: bool = False, additional_args: str = "") -> str | Any:
    """
    Execute Binwalk for firmware and file analysis.
    
    Args:
        file_path: ABSOLUTE path to the file to analyze (e.g., /tmp/ctf_workspace/firmware.bin)
        extract: Whether to extract files found during analysis
        additional_args: any extra command-line arguments to provide to binwalk
        
    Returns:
        Binwalk analysis results
    """
    if not file_path:
        logger.warning("binwalk called without file_path parameter")
        return wrap_error_str("'file_path' parameter is required")
    
    command = "binwalk"
    
    if extract:
        command += " -e"
    
    if additional_args:
        command += f" {additional_args}"
    
    command += f" {file_path}"
    
    logger.info(f"binwalk call: {file_path}")
    result = execute_command_sync(command)
    logger.info(f"binwalk completed for: {file_path}")
    return result

@mcp.tool()
@track_tool
def gdb(binary: str, commands: str = "", script_file: str = "", additional_args: str = "") -> str | Any:
    """
    Execute GDB for binary analysis and debugging.
    
    Args:
        binary: ABSOLUTE path to the binary to debug (e.g., /tmp/ctf_workspace/binary)
        commands: GDB commands to execute (will be written to temporary script)
        script_file: ABSOLUTE path to GDB script file to execute (e.g., /tmp/ctf_workspace/gdb_script.txt)
        additional_args: any extra command-line arguments to provide to gdb
        
    Returns:
        GDB analysis results
    """
    if not binary:
        logger.warning("gdb called without binary parameter")
        return wrap_error_str("'binary' parameter is required")
    
    command = f"gdb {binary}"
    temp_script = None
    
    if script_file:
        command += f" -x {script_file}"
    
    if commands:
        temp_script = "/tmp/ctf_workspace/gdb_commands.txt"
        try:
            with open(temp_script, "w") as f:
                f.write(commands)
            command += f" -x {temp_script}"
        except Exception as e:
            logger.info(f"gdb failed to create temp script: {str(e)}")
            return wrap_error_str(f"Failed to create GDB command script: {str(e)}")
    
    if additional_args:
        command += f" {additional_args}"
    
    command += " -batch"
    
    logger.info(f"gdb call: {binary}")
    result = execute_command_sync(command)
    logger.info(f"gdb completed for: {binary}")
    
    # Cleanup temporary script
    if temp_script and os.path.exists(temp_script):
        try:
            os.remove(temp_script)
        except Exception as e:
            logger.info(f"gdb failed to cleanup temp script: {str(e)}")
    
    return result

@mcp.tool()
@track_tool
def one_gadget(libc_path: str, level: int = 1, additional_args: str = "") -> str | Any:
    """
    Execute one_gadget to find one-shot RCE gadgets in libc.
    
    Args:
        libc_path: ABSOLUTE path to the libc binary to analyze (e.g., /tmp/ctf_workspace/libc.so)
        level: Constraint level (0, 1, or 2) - higher levels find more gadgets with more constraints
        additional_args: any extra command-line arguments to provide to one_gadget
        
    Returns:
        One-gadget analysis results with RCE gadgets and their constraints
    """
    if not libc_path:
        logger.warning("one_gadget called without libc_path parameter")
        return wrap_error_str("'libc_path' parameter is required")
    
    if level not in [0, 1, 2]:
        logger.warning(f"one_gadget called with invalid level: {level}")
        return wrap_error_str("'level' must be 0, 1, or 2")
    
    command = f"one_gadget {libc_path} --level {level}"
    
    if additional_args:
        command += f" {additional_args}"
    
    logger.info(f"one_gadget call: {libc_path} (level {level})")
    result = execute_command_sync(command)
    logger.info(f"one_gadget completed for: {libc_path}")
    return result

@mcp.tool()
@track_tool
def libc_database(action: str, symbols: str = "", libc_id: str = "", additional_args: str = "") -> str | Any:
    """
    Execute libc-database for libc identification and offset lookup.
    
    Args:
        action: Action to perform - 'find' (identify libc), 'dump' (get offsets), or 'download' (download libc)
        symbols: For 'find' action: space-separated "name address" (e.g., "printf 0x1234" or "system 0x5678")
        libc_id: For 'dump'/'download' actions: libc identifier from find results
        additional_args: any extra command-line arguments
        
    Returns:
        libc-database operation results
    """
    if action not in ["find", "dump", "download"]:
        logger.warning(f"libc_database called with invalid action: {action}")
        return wrap_error_str(f"'action' must be 'find', 'dump', or 'download', got '{action}'")
    
    if action == "find" and not symbols:
        logger.warning("libc_database find called without symbols")
        return wrap_error_str("'symbols' parameter is required for find action")
    
    if action in ["dump", "download"] and not libc_id:
        logger.warning(f"libc_database {action} called without libc_id")
        return wrap_error_str(f"'libc_id' parameter is required for {action} action")
    
    # Navigate to libc-database directory
    base_command = "cd /home/pwnphofun/Code/CTFs/libc-database 2>/dev/null || echo 'libc-database not found'"
    
    if action == "find":
        command = f"{base_command} && ./find {symbols}"
    elif action == "dump":
        command = f"{base_command} && ./dump {libc_id}"
    else:  # download
        command = f"{base_command} && ./download {libc_id}"
    
    if additional_args:
        command += f" {additional_args}"
    
    logger.info(f"libc_database call: {action} {symbols or libc_id}")
    result = execute_command_sync(command)
    logger.info(f"libc_database {action} completed")
    return result

@mcp.tool()
@track_tool
def create_file(filename: str, content: str, binary : bool = False):
    """
    Create a file with specified content on the host server. You MUST prefix your filename with the path /tmp/ctf_workspace/

        Args:
            filename: ABSOLUTE path of the file to create.
            content: Content to write to the file
            binary: Whether the content is binary data
        Returns:
            File creation results
    """
    logger.info(f"create_file call: {filename} {content[:min(100, len(content))]} {binary}")
    
    return create_temp_file(filename, content, binary)

@mcp.tool()
@track_tool
def run_shell_command(command: str) -> str | Any:
    """
    Runs a shell command on the host machine where this MCP server is running and returns the results.
    Use this to run the tools that the MCP server doesn't expose, but exists on the host machine.

    WARNING: You MUST NOT run any type of interactive commands via this tool.
    """
    logger.info(f"Running host shell command: {command}")
    return execute_command_sync(command)

@mcp.tool()
@track_tool
def give_up():
    """
    Call this when you give up on solving this challenge. You may stop your response after printing out the results of calling this tool.

    Returns:
        a string telling the user that you have given up
    """
    return "LLM has given up. Stop solving now."

@mcp.tool()
@track_tool
def run_ffuf_scan(
    url: str, 
    wordlist = "/opt/wordlist/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt",
    mode = "directory",
    match_codes = "200,204,301,302,307,401,403",
    additional_args = None) -> str | Any:
    """
    Perform a ffuf scan. If you are using a wordlist argument, make sure you have used other tools to verify that the wordlist exists at the location provided first before running this tool.

    Args:
        url: target
        wordlist (str): path to wordlist. Most of the times the prefix should be /opt/wordlist/ 
        mode (str): "directory" or "vhost" or "parameter". vhost is for fuzzing the "Host" header, "parameter" is for fuzzing URL parameters
        match_codes (str): keep only responses matching the status codes specified. Provide a list of status code separated by commas. 
        additional_args (str): any extra command-line arguments to provide to ffuf

    EXAMPLE:
        calling this function with default arguments is equal to the command line: 
        `ffuf -u {target} -w /opt/wordlist/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,204,301,302,307,401,403 {additional_args}
    """

    if not url:
        logger.warning("FFuf called without URL parameter!")
        return wrap_error_str("URL parameter is required")

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
    
    logger.info(f"Starting ffuf {mode} fuzzing: {url}")
    result = execute_command_sync(command)
    logger.info(f"ffuf fuzzing completed for {url}")
    return result




if __name__ =="__main__":
    logger.info(f"SleepyKitty starting...")
    mcp.run()
