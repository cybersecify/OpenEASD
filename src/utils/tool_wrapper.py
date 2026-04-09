"""Security tool integrations for OpenEASD (Docker or native binaries)."""

import subprocess
import json
import time
import tempfile
import os
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

PDTM_BIN = os.path.expanduser("~/.pdtm/go/bin")


class NativeToolWrapper:
    """Runs security tools as native binaries (no Docker)."""

    def __init__(self, binary: str, config: Dict[str, Any] = None):
        # Resolve binary: try as-is, then ~/.pdtm/go/bin/<name>
        if os.path.isabs(binary) or os.sep in binary:
            self.binary = binary
        else:
            pdtm_path = os.path.join(PDTM_BIN, binary)
            self.binary = pdtm_path if os.path.isfile(pdtm_path) else binary
        self.tool_name = os.path.basename(binary)
        self.config = config or {}
        self.timeout = self.config.get("timeout", 600)

    def run_tool(self, command: List[str], input_data: str = None,
                 volumes: Dict[str, str] = None, environment: Dict[str, str] = None) -> Dict[str, Any]:
        # command[0] is the binary name inside Docker commands — replace with resolved binary
        cmd = [self.binary] + command[1:]
        env = os.environ.copy()
        if environment:
            env.update(environment)

        logger.info(f"Running {self.tool_name} (native): {' '.join(cmd[1:])}")
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
            return {
                "tool": self.tool_name,
                "command": cmd,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            logger.error(f"{self.tool_name} timed out after {self.timeout}s")
            return {"tool": self.tool_name, "stdout": "", "stderr": "timeout",
                    "return_code": -1, "success": False, "timeout": True}
        except FileNotFoundError:
            logger.error(f"{self.tool_name} binary not found: {self.binary}")
            return {"tool": self.tool_name, "stdout": "", "stderr": f"binary not found: {self.binary}",
                    "return_code": -1, "success": False}
        except Exception as e:
            logger.error(f"Error running {self.tool_name}: {e}")
            return {"tool": self.tool_name, "stdout": "", "stderr": str(e),
                    "return_code": -1, "success": False}


def _make_wrapper(docker_image: str, binary_name: str, config: Dict[str, Any] = None):
    """Return NativeToolWrapper or DockerToolWrapper based on USE_DOCKER_TOOLS setting."""
    try:
        from django.conf import settings
        use_docker = getattr(settings, "USE_DOCKER_TOOLS", False)
    except Exception:
        use_docker = False

    if use_docker:
        return DockerToolWrapper(binary_name, docker_image, config)
    return NativeToolWrapper(binary_name, config)


class DockerToolWrapper:
    """Base class for Docker-based security tool wrappers."""

    def __init__(self, tool_name: str, image_name: str, config: Dict[str, Any] = None):
        self.tool_name = tool_name
        self.image_name = image_name
        self.config = config or {}
        self.timeout = self.config.get('timeout', 600)
        self.platform = 'linux/arm64'  # For Mac M1 compatibility

    def run_tool(self, command: List[str], input_data: str = None,
                 volumes: Dict[str, str] = None, environment: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Run Docker tool with specified command.

        Args:
            command: Command to run inside container
            input_data: Data to pass to stdin
            volumes: Dictionary of host:container volume mappings
            environment: Environment variables

        Returns:
            Dictionary containing stdout, stderr, and return code
        """
        docker_cmd = ['docker', 'run', '--rm', '--platform', self.platform]

        # Add volume mounts
        if volumes:
            for host_path, container_path in volumes.items():
                docker_cmd.extend(['-v', f'{host_path}:{container_path}'])

        # Add environment variables
        if environment:
            for key, value in environment.items():
                docker_cmd.extend(['-e', f'{key}={value}'])

        # Add image and command
        docker_cmd.append(self.image_name)
        docker_cmd.extend(command)

        logger.info(f"Running {self.tool_name}: {' '.join(command)}")
        logger.debug(f"Docker command: {' '.join(docker_cmd)}")

        try:
            result = subprocess.run(
                docker_cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            return {
                'tool': self.tool_name,
                'command': command,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'success': result.returncode == 0
            }

        except subprocess.TimeoutExpired:
            logger.error(f"{self.tool_name} timed out after {self.timeout} seconds")
            return {
                'tool': self.tool_name,
                'command': command,
                'stdout': '',
                'stderr': f'Tool timed out after {self.timeout} seconds',
                'return_code': -1,
                'success': False,
                'timeout': True
            }
        except Exception as e:
            logger.error(f"Error running {self.tool_name}: {str(e)}")
            return {
                'tool': self.tool_name,
                'command': command,
                'stdout': '',
                'stderr': str(e),
                'return_code': -1,
                'success': False,
                'error': str(e)
            }


class SubfinderWrapper:
    """Wrapper for Subfinder subdomain enumeration tool."""

    BINARY = "/opt/homebrew/bin/subfinder"

    def enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        cmd = [self.BINARY, "-d", domain, "-json", "-silent"]
        logger.info(f"Running subfinder: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            logger.error(f"subfinder not found at {self.BINARY}")
            return {"tool": "subfinder", "domain": domain, "subdomains": [], "count": 0}
        except subprocess.TimeoutExpired:
            logger.error("subfinder timed out")
            return {"tool": "subfinder", "domain": domain, "subdomains": [], "count": 0}

        subdomains = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                data = json.loads(line)
                subdomains.append({
                    "subdomain": data.get("host", ""),
                    "ip_address": data.get("ip", "") or None,
                    "source": data.get("source", "subfinder"),
                })
            except json.JSONDecodeError:
                subdomains.append({"subdomain": line.strip(), "ip_address": None, "source": "subfinder"})

        logger.info(f"subfinder found {len(subdomains)} subdomains for {domain}")
        return {"tool": "subfinder", "domain": domain, "subdomains": subdomains, "count": len(subdomains)}


class NaabuWrapper(DockerToolWrapper):
    """Wrapper for Naabu port scanner."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            'naabu',
            'projectdiscovery/naabu:latest',
            config
        )

    def scan_ports(self, targets: Union[str, List[str]],
                   ports: str = None, top_ports: int = None) -> Dict[str, Any]:
        """
        Scan ports on target hosts.

        Args:
            targets: Single target or list of targets
            ports: Port specification (e.g., "80,443,8080-8090")
            top_ports: Number of top ports to scan

        Returns:
            Dictionary containing open ports
        """
        # Create temporary file for targets if multiple
        temp_file = None
        if isinstance(targets, list):
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for target in targets:
                temp_file.write(f"{target}\n")
            temp_file.close()

            volumes = {temp_file.name: '/tmp/targets.txt'}
            command = ['naabu', '-list', '/tmp/targets.txt', '-json', '-silent']
        else:
            volumes = {}
            command = ['naabu', '-host', targets, '-json', '-silent']

        # Port specification
        if ports:
            command.extend(['-p', ports])
        elif top_ports:
            command.extend(['-top-ports', str(top_ports)])
        elif self.config.get('top_ports'):
            command.extend(['-top-ports', str(self.config['top_ports'])])

        # Rate limiting
        if self.config.get('rate'):
            command.extend(['-rate', str(self.config['rate'])])

        # Timeout
        if self.config.get('timeout'):
            command.extend(['-timeout', str(self.config['timeout'])])

        try:
            result = self.run_tool(command, volumes=volumes)

            # Parse JSON output
            open_ports = []
            if result['success'] and result['stdout']:
                for line in result['stdout'].strip().split('\n'):
                    if line:
                        try:
                            port_data = json.loads(line)
                            open_ports.append({
                                'host': port_data.get('host', ''),
                                'port': port_data.get('port', 0),
                                'protocol': port_data.get('protocol', 'tcp')
                            })
                        except json.JSONDecodeError:
                            continue

            return {
                'tool': 'naabu',
                'targets': targets,
                'open_ports': open_ports,
                'count': len(open_ports),
                'raw_result': result
            }

        finally:
            # Clean up temporary file
            if temp_file and os.path.exists(temp_file.name):
                os.unlink(temp_file.name)


class NmapWrapper(DockerToolWrapper):
    """Wrapper for Nmap service detection."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            'nmap',
            'instrumentisto/nmap:latest',
            config
        )

    def service_scan(self, host: str, ports: List[int] = None,
                    scripts: List[str] = None) -> Dict[str, Any]:
        """
        Perform service detection scan.

        Args:
            host: Target host
            ports: List of ports to scan
            scripts: NSE scripts to run

        Returns:
            Dictionary containing service information
        """
        command = ['nmap', '-sV', '-oX', '-']

        # Timing template
        timing = self.config.get('timing', 3)
        command.extend(['-T', str(timing)])

        # Scripts
        if scripts:
            command.extend(['--script', ','.join(scripts)])
        elif self.config.get('scripts'):
            command.extend(['--script', ','.join(self.config['scripts'])])

        # Port specification
        if ports:
            port_spec = ','.join(str(p) for p in ports)
            command.extend(['-p', port_spec])

        # Add host
        command.append(host)

        result = self.run_tool(command)

        # Parse XML output would require additional parsing
        # For now, return basic structure
        services = []
        if result['success']:
            # TODO: Parse XML output to extract service details
            # This would require xml.etree.ElementTree or similar
            pass

        return {
            'tool': 'nmap',
            'host': host,
            'services': services,
            'raw_result': result
        }


class NucleiWrapper(DockerToolWrapper):
    """Wrapper for Nuclei vulnerability scanner."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            'nuclei',
            'projectdiscovery/nuclei:latest',
            config
        )

    def vulnerability_scan(self, targets: Union[str, List[str]],
                          templates: List[str] = None,
                          severity: List[str] = None) -> Dict[str, Any]:
        """
        Perform vulnerability scan.

        Args:
            targets: Single target or list of targets
            templates: Template categories to use
            severity: Severity levels to include

        Returns:
            Dictionary containing vulnerability findings
        """
        # Create temporary file for targets if multiple
        temp_file = None
        if isinstance(targets, list):
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for target in targets:
                temp_file.write(f"{target}\n")
            temp_file.close()

            volumes = {temp_file.name: '/tmp/targets.txt'}
            command = ['nuclei', '-list', '/tmp/targets.txt', '-json']
        else:
            volumes = {}
            command = ['nuclei', '-target', targets, '-json']

        # Templates
        if templates:
            for template in templates:
                command.extend(['-tags', template])
        elif self.config.get('templates'):
            for template in self.config['templates']:
                command.extend(['-tags', template])

        # Severity filtering
        if severity:
            command.extend(['-severity', ','.join(severity)])

        # Rate limiting
        if self.config.get('rate_limit'):
            command.extend(['-rate-limit', str(self.config['rate_limit'])])

        # Timeout
        if self.config.get('timeout'):
            command.extend(['-timeout', str(self.config['timeout'])])

        try:
            result = self.run_tool(command, volumes=volumes)

            # Parse JSON output
            vulnerabilities = []
            if result['success'] and result['stdout']:
                for line in result['stdout'].strip().split('\n'):
                    if line:
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities.append({
                                'template_id': vuln_data.get('templateID', ''),
                                'template_name': vuln_data.get('info', {}).get('name', ''),
                                'severity': vuln_data.get('info', {}).get('severity', 'info'),
                                'host': vuln_data.get('host', ''),
                                'matched_at': vuln_data.get('matched-at', ''),
                                'description': vuln_data.get('info', {}).get('description', ''),
                                'reference': vuln_data.get('info', {}).get('reference', []),
                                'classification': vuln_data.get('info', {}).get('classification', {}),
                                'raw_data': vuln_data
                            })
                        except json.JSONDecodeError:
                            continue

            return {
                'tool': 'nuclei',
                'targets': targets,
                'vulnerabilities': vulnerabilities,
                'count': len(vulnerabilities),
                'raw_result': result
            }

        finally:
            # Clean up temporary file
            if temp_file and os.path.exists(temp_file.name):
                os.unlink(temp_file.name)


class ToolManager:
    """Manager class for all security tools."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.tools = {}
        self._initialize_tools()

    def _initialize_tools(self):
        """Initialize all tool wrappers."""
        self.tools['subfinder'] = SubfinderWrapper(
            self.config.get('tools', {}).get('subfinder', {})
        )
        self.tools['naabu'] = NaabuWrapper(
            self.config.get('tools', {}).get('naabu', {})
        )
        self.tools['nmap'] = NmapWrapper(
            self.config.get('tools', {}).get('nmap', {})
        )
        self.tools['nuclei'] = NucleiWrapper(
            self.config.get('tools', {}).get('nuclei', {})
        )

    def get_tool(self, tool_name: str) -> DockerToolWrapper:
        """Get tool wrapper by name."""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        return self.tools[tool_name]

    def check_tool_availability(self) -> Dict[str, bool]:
        """Check which tools are available."""
        availability = {}

        for tool_name, tool in self.tools.items():
            try:
                # Try to run tool with --help to check availability
                result = tool.run_tool(['--help'])
                availability[tool_name] = result['return_code'] == 0
            except Exception:
                availability[tool_name] = False

        return availability

    def update_tool_images(self) -> Dict[str, bool]:
        """Update all tool Docker images."""
        results = {}

        for tool_name, tool in self.tools.items():
            try:
                subprocess.run(
                    ['docker', 'pull', tool.image_name],
                    check=True,
                    capture_output=True
                )
                results[tool_name] = True
                logger.info(f"Updated {tool_name} image: {tool.image_name}")
            except subprocess.CalledProcessError as e:
                results[tool_name] = False
                logger.error(f"Failed to update {tool_name}: {e}")

        return results

    def get_tool_versions(self) -> Dict[str, str]:
        """Get version information for all tools."""
        versions = {}

        for tool_name, tool in self.tools.items():
            try:
                # Different tools have different version flags
                version_commands = {
                    'subfinder': ['-version'],
                    'naabu': ['-version'],
                    'nmap': ['--version'],
                    'nuclei': ['-version']
                }

                cmd = version_commands.get(tool_name, ['--version'])
                result = tool.run_tool(cmd)

                if result['success']:
                    # Extract version from output (simplified)
                    output = result['stdout'] + result['stderr']
                    versions[tool_name] = output.split('\n')[0][:100]  # First line, truncated
                else:
                    versions[tool_name] = 'Unknown'

            except Exception:
                versions[tool_name] = 'Error'

        return versions
