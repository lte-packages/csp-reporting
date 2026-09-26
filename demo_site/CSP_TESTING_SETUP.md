# CSP Testing Demo Setup

## Overview
A Django demo site configured for testing Content Security Policy (CSP) reporting functionality. This setup provides a complete development and testing environment for CSP violation collection and verification.

## What's Been Set Up

### 1. **Home Page** (`/`)
- Beautiful, themed landing page
- Overview of CSP testing capabilities
- Navigation to testing tools
- Information about CSP configuration and monitoring

### 2. **CSP Violation Test Page** (`/test-violation/`)
- Two intentional CSP violation triggers:
  1. **Inline Script Violation**: Uses `onclick` attribute
  2. **External Image Load**: Attempts to load image from untrusted source
- Documentation of expected violations
- Instructions for monitoring and verifying reports

### 3. **Django CSP Middleware Integration**
- Middleware configured in `settings.py`
- CSP violation reports automatically collected at `/csp/report/`
- Violations stored in the `csp_reporting.CSPReport` model

### 4. **CSP Configuration** (django-csp >= 4.0 format)
```python
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", "'unsafe-inline'"),
        'style-src': ("'self'", "'unsafe-inline'"),
        'img-src': ("'self'", "data:", "https:"),
        'font-src': ("'self'",),
        'connect-src': ("'self'",),
        'frame-ancestors': ("'self'",),
        'base-uri': ("'self'",),
        'form-action': ("'self'",),
        'report-uri': '/csp/report/',
    }
}
```

### 5. **Modern Theming**
- Professional color scheme with primary (#0066cc) and accent (#ff6600) colors
- Responsive grid layout
- Clear navigation structure
- Styled cards, buttons, and alerts
- All CSS inline in base template for development simplicity

## Development & Testing Workflow

### Starting the Server
```bash
cd demo_site
python manage.py runserver 8000
```

### Testing Workflow
1. **Visit home page**: `http://localhost:8000/`
2. **Trigger violations**: Navigate to `/test-violation/`
3. **Verify collection**: Check `/admin/` → CSPReport model
4. **Monitor violations**: Review violation details (directive, URI, etc.)

### Viewing Collected Reports
- Django Admin: `http://localhost:8000/admin/`
- Navigate to **CSPReport** model to view all collected violations
- Each report contains:
  - Violated directive
  - Blocked URI
  - Timestamp
  - Additional violation context

## Key Files Created/Modified

### Created Files
- `demo_site/views.py` - Home and test violation views
- `demo_site/templates/base.html` - Base template with styling
- `demo_site/templates/home.html` - Home page content
- `demo_site/templates/test_violation.html` - Violation test page

### Modified Files
- `demo_site/settings.py` - Added CSP middleware and configuration
- `demo_site/urls.py` - Added routes for home, violation test, and CSP reporting

## CSP Policy Details

### Current Directives
- **default-src**: Only 'self' allowed
- **script-src**: 'self' and 'unsafe-inline' (for development testing)
- **style-src**: 'self' and 'unsafe-inline' (for inline styles)
- **img-src**: 'self', data: URIs, and https: sources
- **font-src**: Only 'self'
- **connect-src**: Only 'self' (AJAX, WebSocket)
- **frame-ancestors**: Only 'self'
- **report-uri**: `/csp/report/` for violation collection

### Testing Violations
The `/test-violation/` page includes:
1. Inline event handler (script-src violation)
2. External image load attempt (img-src violation)

## Notes for Development
- CSP is currently in **enforce mode** (not report-only)
- Development settings use `'unsafe-inline'` for scripts and styles for ease of development
- For production, tighten CSP directives and remove 'unsafe-inline'
- All violations are automatically collected and timestamped

## Next Steps for Enhancement
- Create a violations dashboard for visualization
- Add filtering/search to violation reports
- Implement metrics tracking over time
- Add automated CSP policy refinement suggestions
- Create test cases for CI/CD integration
