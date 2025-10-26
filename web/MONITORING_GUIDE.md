# Server Monitoring Dashboard Guide

## Overview

The SEU API Management dashboard now includes real-time server monitoring capabilities that track CPU, memory, disk, and network usage with live graphs.

## Features

### 📊 Real-Time Metrics

The dashboard displays live server metrics that update every 5 seconds:

1. **CPU Usage**
   - Current CPU percentage
   - Number of CPU cores
   - CPU frequency

2. **Memory Usage**
   - Current memory percentage
   - Used/Total memory in GB
   - Available memory

3. **Disk Usage**
   - Current disk percentage
   - Used/Total disk space in GB
   - Free disk space

4. **System Info**
   - Active process count
   - System uptime in hours

### 📈 Live Charts

Two interactive charts show historical data:

1. **CPU Usage History** - Line chart showing CPU percentage over time
2. **Memory Usage History** - Line chart showing memory percentage over time

Charts maintain the last 20 data points (approximately 100 seconds of data).

## Technical Implementation

### Backend (Python)

**Library Used:** `psutil` - Cross-platform library for system and process utilities

**Endpoint:** `/web/api/metrics/`

**Response Format:**
```json
{
  "timestamp": 1234567890.123,
  "cpu": {
    "percent": 45.2,
    "count": 8,
    "frequency": 2400.0
  },
  "memory": {
    "percent": 62.5,
    "used_gb": 10.2,
    "total_gb": 16.0,
    "available_gb": 5.8
  },
  "disk": {
    "percent": 55.3,
    "used_gb": 250.5,
    "total_gb": 500.0,
    "free_gb": 249.5
  },
  "network": {
    "bytes_sent_mb": 1234.56,
    "bytes_recv_mb": 5678.90,
    "packets_sent": 123456,
    "packets_recv": 234567
  },
  "system": {
    "process_count": 245,
    "uptime_hours": 72.5
  }
}
```

### Frontend (JavaScript)

**Library Used:** Chart.js v4.4.0 - Simple yet flexible JavaScript charting library

**Features:**
- Automatic data fetching via Fetch API
- Real-time chart updates
- Smooth animations
- Responsive design

**Update Frequency:** 5 seconds (configurable in template)

## Files Modified/Created

1. **`requirements.txt`** - Added `psutil==6.1.1`
2. **`web/views.py`** - Added `system_metrics_view()` function
3. **`web/urls.py`** - Added `/api/metrics/` route
4. **`templates/web/dashboard.html`** - Updated with monitoring section and charts

## Usage

### Accessing the Dashboard

1. Log in to the web interface at `http://localhost:8000/web/login/`
2. Navigate to the dashboard (automatic after login)
3. The monitoring section appears at the top with real-time metrics

### Customizing Update Frequency

Edit the `setInterval` value in `dashboard.html`:

```javascript
// Change from 5000 (5 seconds) to desired milliseconds
setInterval(fetchMetrics, 5000);  // 5 seconds
setInterval(fetchMetrics, 10000); // 10 seconds
```

### Customizing Chart Data Points

Edit the `maxDataPoints` value in `dashboard.html`:

```javascript
// Change from 20 to desired number of points
const maxDataPoints = 20;  // Shows last 20 data points
const maxDataPoints = 60;  // Shows last 60 data points
```

## Performance Considerations

### CPU Usage

The `psutil.cpu_percent(interval=1)` call blocks for 1 second to calculate accurate CPU usage. This is intentional but means the API endpoint takes ~1 second to respond.

**Optimization Options:**

1. **Cache metrics:** Store metrics in memory and update in background
2. **Adjust interval:** Use `interval=0.1` for faster response (less accurate)
3. **Use async:** Implement async views for non-blocking calls

### Memory Impact

The monitoring itself uses minimal resources:
- `psutil` library: ~2-5 MB RAM
- Chart data: ~1 KB per data point × 2 charts × 20 points = ~40 KB
- Total overhead: < 10 MB

### Network Traffic

Each metrics request transfers approximately:
- Request: < 1 KB
- Response: ~1 KB (JSON data)
- Total per update: ~2 KB
- Per minute (12 updates): ~24 KB
- Per hour: ~1.4 MB

## Security

### Authentication Required

The metrics endpoint requires authentication:
```python
if not request.session.get('authenticated'):
    return JsonResponse({'error': 'Unauthorized'}, status=401)
```

Only logged-in users can access system metrics.

### CORS Considerations

If accessing from external domains, add CORS headers in settings:
```python
CORS_ALLOW_HEADERS = [..., 'authorization']
```

## Troubleshooting

### Issue: Metrics not updating

**Solutions:**
1. Check browser console for JavaScript errors
2. Verify `/web/api/metrics/` endpoint is accessible
3. Ensure user is authenticated
4. Check network tab in browser DevTools

### Issue: Charts not displaying

**Solutions:**
1. Verify Chart.js CDN is loading
2. Check browser console for errors
3. Clear browser cache
4. Verify canvas elements exist in HTML

### Issue: High CPU usage

**Solutions:**
1. Increase update interval (from 5s to 10s or more)
2. Reduce `maxDataPoints` to show less history
3. Implement caching for metrics

### Issue: Permission errors on Linux

Some system metrics may require elevated permissions:

```bash
# Run as root (not recommended for production)
sudo python manage.py runserver

# Or use capabilities (Linux only)
sudo setcap cap_net_raw=+ep venv/bin/python
```

## Browser Compatibility

The dashboard works on all modern browsers:

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ✅ Mobile browsers (responsive design)

## Future Enhancements

Potential improvements:

1. **Historical Data Storage**
   - Store metrics in database
   - View historical trends
   - Generate reports

2. **Alerting System**
   - Set threshold alerts
   - Email notifications
   - Slack/Discord webhooks

3. **Additional Metrics**
   - Per-process CPU/memory
   - API request rates
   - Database query times
   - Error rates

4. **Export Capabilities**
   - Export charts as images
   - Download metrics as CSV
   - Generate PDF reports

5. **Custom Dashboards**
   - User-configurable layouts
   - Widget drag-and-drop
   - Saved dashboard presets

## API Endpoints

### Get System Metrics

**URL:** `/web/api/metrics/`

**Method:** `GET`

**Authentication:** Required (session-based)

**Response:** JSON object with system metrics

**Example:**
```bash
curl -X GET http://localhost:8000/web/api/metrics/ \
  -H "Cookie: sessionid=your_session_id"
```

## Dependencies

- **Python:** `psutil==6.1.1`
- **JavaScript:** Chart.js v4.4.0 (CDN)
- **CSS:** Bootstrap 5 (existing)

## Support

For issues or questions:
1. Check logs: `logs/APIM.log`
2. Review browser console
3. Verify psutil installation: `pip show psutil`

## License

This monitoring feature is part of the SEU API Management system.

