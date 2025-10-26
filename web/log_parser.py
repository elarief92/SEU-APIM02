"""
Log file parser for API request monitoring.
"""
import re
import os
from datetime import datetime
from django.conf import settings


class LogEntry:
    """Represents a single log entry."""
    
    def __init__(self, timestamp, level, logger, message, file_path, raw_line):
        self.timestamp = timestamp
        self.level = level
        self.logger = logger
        self.message = message
        self.file_path = file_path
        self.raw_line = raw_line
        
        # Parse HTTP request details if available
        self.method = None
        self.path = None
        self.http_version = None
        self.status_code = None
        self.response_size = None
        self.app_name = None
        self.duration = None
        
        self._parse_http_request()
        self._parse_app_info()
    
    def _parse_http_request(self):
        """Parse HTTP request details from message."""
        # Pattern: "METHOD /path HTTP/1.1" status_code response_size
        pattern = r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/([\d\.]+)"\s+(\d+)\s+(\d+)'
        match = re.search(pattern, self.message)
        
        if match:
            self.method = match.group(1)
            self.path = match.group(2)
            self.http_version = match.group(3)
            self.status_code = int(match.group(4))
            self.response_size = int(match.group(5))
    
    def _parse_app_info(self):
        """Parse application name and duration from message."""
        # Pattern: | App: application_name | Duration: X.XXXs
        app_pattern = r'\|\s*App:\s*([^|]+?)(?:\s*\||$)'
        app_match = re.search(app_pattern, self.message)
        
        if app_match:
            self.app_name = app_match.group(1).strip()
        
        # Parse duration if available
        duration_pattern = r'Duration:\s*([\d.]+)s'
        duration_match = re.search(duration_pattern, self.message)
        
        if duration_match:
            self.duration = float(duration_match.group(1))
    
    def is_http_request(self):
        """Check if this log entry is an HTTP request."""
        return self.method is not None
    
    def get_status_class(self):
        """Get Bootstrap class based on status code."""
        if not self.status_code:
            return 'secondary'
        if 200 <= self.status_code < 300:
            return 'success'
        elif 300 <= self.status_code < 400:
            return 'info'
        elif 400 <= self.status_code < 500:
            return 'warning'
        else:
            return 'danger'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'level': self.level,
            'logger': self.logger,
            'message': self.message,
            'method': self.method,
            'path': self.path,
            'status_code': self.status_code,
            'response_size': self.response_size,
            'app_name': self.app_name,
            'duration': self.duration,
            'status_class': self.get_status_class(),
        }


class LogParser:
    """Parser for Django log files."""
    
    # Log line pattern: [timestamp] LEVEL logger | message | File: path
    LOG_PATTERN = re.compile(
        r'\[([^\]]+)\]\s+'                       # [timestamp]
        r'(\w+)\s+'                               # LEVEL
        r'([^\|]+?)\s*\|\s*'                      # logger |
        r'(.+?)'                                  # message (at least one char)
        r'(?:\s*\|\s*File:\s*(.+?))?$'           # | File: path (optional, at end)
        , re.DOTALL
    )
    
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
    
    def parse_line(self, line):
        """Parse a single log line."""
        match = self.LOG_PATTERN.match(line.strip())
        
        if not match:
            return None
        
        timestamp_str, level, logger, message, file_path = match.groups()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp_str, '%H:%M:%S')
                # Use today's date for time-only timestamps
                timestamp = timestamp.replace(
                    year=datetime.now().year,
                    month=datetime.now().month,
                    day=datetime.now().day
                )
            except ValueError:
                timestamp = None
        
        return LogEntry(
            timestamp=timestamp,
            level=level.strip(),
            logger=logger.strip(),
            message=message.strip(),
            file_path=file_path.strip() if file_path else '',
            raw_line=line
        )
    
    def parse_file(self, max_lines=1000, reverse=True):
        """Parse log file and return entries."""
        entries = []
        
        if not os.path.exists(self.log_file_path):
            return entries
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                # Reverse to get newest first
                if reverse:
                    lines = reversed(lines)
                
                for line in lines:
                    if len(entries) >= max_lines:
                        break
                    
                    if line.strip():
                        entry = self.parse_line(line)
                        if entry:
                            entries.append(entry)
        
        except Exception as e:
            print(f"Error parsing log file: {e}")
        
        return entries
    
    def filter_entries(self, entries, search=None, method=None, status_code=None, 
                      level=None, start_date=None, end_date=None):
        """Filter log entries based on criteria."""
        filtered = entries
        
        if search:
            search = search.lower()
            filtered = [e for e in filtered if search in e.message.lower() or 
                       (e.path and search in e.path.lower())]
        
        if method:
            filtered = [e for e in filtered if e.method == method]
        
        if status_code:
            filtered = [e for e in filtered if e.status_code == int(status_code)]
        
        if level:
            filtered = [e for e in filtered if e.level == level]
        
        if start_date:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            filtered = [e for e in filtered if e.timestamp and e.timestamp >= start_dt]
        
        if end_date:
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            end_dt = end_dt.replace(hour=23, minute=59, second=59)
            filtered = [e for e in filtered if e.timestamp and e.timestamp <= end_dt]
        
        return filtered


def get_available_logs():
    """Get list of available log files."""
    logs_dir = os.path.join(settings.BASE_DIR, 'logs')
    log_files = []
    
    if os.path.exists(logs_dir):
        for filename in os.listdir(logs_dir):
            if filename.endswith('.log'):
                file_path = os.path.join(logs_dir, filename)
                file_size = os.path.getsize(file_path)
                
                # Format file size appropriately
                if file_size < 1024:
                    size_display = f"{file_size} B"
                elif file_size < 1024 * 1024:
                    size_display = f"{round(file_size / 1024, 1)} KB"
                else:
                    size_display = f"{round(file_size / (1024 * 1024), 2)} MB"
                
                log_files.append({
                    'name': filename,
                    'path': file_path,
                    'size': file_size,
                    'size_mb': round(file_size / (1024 * 1024), 2),
                    'size_display': size_display
                })
    
    return sorted(log_files, key=lambda x: x['name'])

