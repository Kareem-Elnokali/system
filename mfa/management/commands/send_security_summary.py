from django.core.management.base import BaseCommand
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.urls import reverse
from django.utils import timezone
from django.core.cache import cache
from datetime import timedelta, datetime, time
from io import BytesIO, StringIO
import csv
from email.mime.image import MIMEImage
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except Exception:
    matplotlib = None
    plt = None
from django.contrib.auth import get_user_model
from django.db.models import Q
from mfa.models import MFASettings, MFADevice, MFALog
class Command(BaseCommand):
    help = "Send Security Center summary email based on MFASettings schedule."
    def add_arguments(self, parser):
        parser.add_argument('--force', action='store_true', help='Send regardless of next_send_at')
        parser.add_argument('--dry-run', action='store_true', help='Compute and log, but do not send email or update schedule')
        parser.add_argument('--to', nargs='+', help='Override recipients for a one-off send (space-separated emails)')
        parser.add_argument('--dump-html', help='Write rendered HTML to the given file path and skip sending')
    def handle(self, *args, **options):
        now = timezone.now()
        settings_obj = MFASettings.load()
        override_recipients = options.get('to') or []
        is_override = len(override_recipients) > 0
        if not is_override:
            if not settings_obj.report_enabled:
                self.stdout.write(self.style.NOTICE('Report disabled. Nothing to do.'))
                return
        if not is_override:
            if not (settings_obj.report_recipients or '').strip():
                self.stdout.write(self.style.WARNING('No recipients configured. Skipping send.'))
                return
        if not is_override and not options['force']:
            if not settings_obj.report_next_send_at or settings_obj.report_next_send_at > now:
                self.stdout.write(self.style.NOTICE('Not due yet. Next send at: %s' % (settings_obj.report_next_send_at,)))
                return
        User = get_user_model()
        twenty_four_hours_ago = now - timedelta(hours=24)
        total_users_val = User.objects.count()
        users_with_totp_val = MFADevice.objects.filter(name='Authenticator', confirmed=True).values('user').distinct().count()
        mfa_adoption_rate_pct = int(round((users_with_totp_val / total_users_val) * 100)) if total_users_val else 0
        failure_terminal = ['login_fail', 'login_fail_superuser_attempt']
        success_primary = ['login_success']
        success_fallback = [
            'passkey_auth_success',
            'email_verify_success',
            'totp_verify_success',
            'backup_code_login_success',
            'backup_code_used',
        ]
        failed_attempts_24h_val = MFALog.objects.filter(
            event__in=failure_terminal,
            created_at__gte=twenty_four_hours_ago
        ).count()
        successes_24h_val = MFALog.objects.filter(created_at__gte=twenty_four_hours_ago, event__in=success_primary).count()
        if successes_24h_val == 0:
            successes_24h_val = MFALog.objects.filter(created_at__gte=twenty_four_hours_ago, event__in=success_fallback).count()
        stats = {
            'total_users': total_users_val,
            'users_with_totp': users_with_totp_val,
            'superusers_count': User.objects.filter(is_superuser=True).count(),
            'successes_24h': successes_24h_val,
            'mfa_adoption_rate_pct': mfa_adoption_rate_pct,
            'failed_attempts_24h': failed_attempts_24h_val,
        }
        labels = []
        successes_series = []
        failures_series = []
        successes_pct = []
        failures_pct = []
        email_chart = []
        bar_px_height = 120
        tz = timezone.get_current_timezone()
        for i in range(6, -1, -1):
            day_start = (now - timedelta(days=i)).astimezone(tz)
            day_start = day_start.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start.replace(hour=23, minute=59, second=59, microsecond=999999)
            labels.append(day_start.strftime('%Y-%m-%d'))
            f = MFALog.objects.filter(created_at__gte=day_start, created_at__lte=day_end, event__in=failure_terminal).count()
            s = MFALog.objects.filter(created_at__gte=day_start, created_at__lte=day_end, event__in=success_primary).count()
            if s == 0:
                s = MFALog.objects.filter(created_at__gte=day_start, created_at__lte=day_end, event__in=success_fallback).count()
            failures_series.append(f)
            successes_series.append(s)
            total = f + s
            if total:
                fp = int(round((f/total)*100))
                sp = max(0, 100 - fp)
            else:
                fp = 0
                sp = 0
            failures_pct.append(fp)
            successes_pct.append(sp)
            spx = int(round((sp/100.0) * bar_px_height))
            fpx = bar_px_height - spx
            if sp > 0 and spx == 0:
                spx = 1
                fpx = max(0, bar_px_height - spx)
            if fp > 0 and fpx == 0:
                fpx = 1
                spx = max(0, bar_px_height - fpx)
            email_chart.append({
                'label': labels[-1],
                'successes': s,
                'failures': f,
                'successes_pct': sp,
                'failures_pct': fp,
                'successes_px': spx,
                'failures_px': fpx,
                'total': total,
            })
        site_name = getattr(settings, 'SITE_NAME', 'Site')
        subject = f"Security Center — {site_name} Summary ({now.strftime('%Y-%m-%d %H:%M')})"
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or getattr(settings, 'SERVER_EMAIL', None) or 'no-reply@example.com'
        if is_override:
            raw_tokens = [e.strip().lower() for e in override_recipients if e.strip()]
        else:
            raw_tokens = [e.strip().lower() for part in settings_obj.report_recipients.split(',') for e in part.split() if e.strip()]
        recipients = []
        seen = set()
        for r in raw_tokens:
            if '@' not in r or '.' not in r.split('@')[-1]:
                continue
            if r not in seen:
                seen.add(r)
                recipients.append(r)
        if not recipients:
            self.stdout.write(self.style.WARNING('Recipients list is empty after normalization. Skipping send.'))
            return
        site_domain = getattr(settings, 'SITE_DOMAIN', 'localhost:8000')
        scheme = 'https' if not settings.DEBUG else 'http'
        dashboard_url = f"{scheme}://{site_domain}{reverse('mfa:admin_dashboard')}"
        short_labels = [lbl[5:10] if len(lbl) >= 5 else lbl for lbl in labels]
        bar_height = bar_px_height
        bar_width = 14
        gutter = 18
        email_chart_html = []
        email_chart_html.append(
            f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 4px 4px;border-collapse:collapse;">'
            f'<tbody><tr>'
        )
        while len(email_chart) < 7:
            lbl = (now - timedelta(days=(6 - len(email_chart)))).strftime('%Y-%m-%d')
            email_chart.append({
                'label': lbl,
                'successes': 0,
                'failures': 0,
                'successes_pct': 0,
                'failures_pct': 0,
                'successes_px': 0,
                'failures_px': 0,
                'total': 0,
            })
        for idx, d in enumerate(email_chart):
            email_chart_html.append('<td align="center" valign="bottom">')
            email_chart_html.append(
                f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
                f'style="border-collapse:collapse;background:#e5e7eb;margin:0 auto;border:1px solid #e2e8f0;" width="{bar_width}"><tbody>'
            )
            succ_rows = max(0, int(d.get('successes_px', 0)))
            fail_rows = max(0, int(d.get('failures_px', 0)))
            used = succ_rows + fail_rows
            pad_rows = max(0, bar_height - used)
            for _ in range(pad_rows):
                email_chart_html.append(
                    f'<tr><td height="1" style="line-height:1px;mso-line-height-rule:exactly;font-size:0;padding:0;">'
                    f'<div style="display:block;height:1px;background:#e5e7eb;">&nbsp;</div>'
                    f'</td></tr>'
                )
            for _ in range(fail_rows):
                email_chart_html.append(
                    f'<tr><td height="1" style="line-height:1px;mso-line-height-rule:exactly;font-size:0;padding:0;">'
                    f'<div style="display:block;height:1px;background:#ef4444;">&nbsp;</div>'
                    f'</td></tr>'
                )
            for i in range(succ_rows):
                radius = 'border-top-left-radius:6px;border-top-right-radius:6px;' if i == (succ_rows - 1) else ''
                email_chart_html.append(
                    f'<tr><td height="1" style="line-height:1px;mso-line-height-rule:exactly;font-size:0;padding:0;">'
                    f'<div style="display:block;height:1px;background:#22c55e;{radius}">&nbsp;</div>'
                    f'</td></tr>'
                )
            email_chart_html.append('</tbody></table>')
            s_val = int(d.get('successes', 0) or 0)
            f_val = int(d.get('failures', 0) or 0)
            email_chart_html.append(
                '<div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#334155;padding-top:6px;">'
                f'<span style="display:inline-block;width:8px;height:8px;border-radius:999px;background:#22c55e;vertical-align:middle;margin-right:4px;"></span>'
                f'<span style="vertical-align:middle;margin-right:8px;">{s_val}</span>'
                f'<span style="display:inline-block;width:8px;height:8px;border-radius:999px;background:#ef4444;vertical-align:middle;margin-right:4px;"></span>'
                f'<span style="vertical-align:middle;">{f_val}</span>'
                '</div>'
            )
            bar_lbl = str(d.get('label', ''))
            bar_lbl_short = bar_lbl[5:10] if len(bar_lbl) >= 10 else bar_lbl
            email_chart_html.append(
                f'<div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#64748b;padding-top:4px;">{bar_lbl_short}</div>'
            )
            email_chart_html.append('</td>')
            if idx < len(email_chart) - 1:
                email_chart_html.append(f'<td width="{gutter}" style="width:{gutter}px;font-size:0;line-height:0;">&nbsp;</td>')
        email_chart_html.append('</tr></tbody></table>')
        email_chart_html = ''.join(email_chart_html)
        snippet = email_chart_html[:160].replace('\n', '')
        self.stdout.write(self.style.NOTICE(f'email_chart_html len={len(email_chart_html)} snippet={snippet}'))
        week_success_total = sum(successes_series)
        week_failure_total = sum(failures_series)
        prev_start = (now - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)
        prev_end = (now - timedelta(days=7)).replace(hour=23, minute=59, second=59, microsecond=999999)
        prev_fail = MFALog.objects.filter(created_at__gte=prev_start, created_at__lte=prev_end, event__in=failure_terminal).count()
        prev_succ = MFALog.objects.filter(created_at__gte=prev_start, created_at__lte=prev_end, event__in=success_primary).count()
        if prev_succ == 0:
            prev_succ = MFALog.objects.filter(created_at__gte=prev_start, created_at__lte=prev_end, event__in=success_fallback).count()
        def pct_delta(cur, prev):
            """Symmetric percent change bounded to [-200, 200].
            Formula: 200 * (cur - prev) / (cur + prev), handles prev=0 gracefully.
            """
            try:
                cur = int(cur or 0)
                prev = int(prev or 0)
                denom = (cur + prev)
                if denom == 0:
                    return 0
                val = 200.0 * (cur - prev) / denom
                if val > 200:
                    val = 200
                if val < -200:
                    val = -200
                return int(round(val))
            except Exception:
                return 0
        deltas = {
            'success_pct': pct_delta(week_success_total, prev_succ),
            'failure_pct': pct_delta(week_failure_total, prev_fail),
        }
        html_body = render_to_string('email/admin_summary.html', {
            'site_name': site_name,
            'stats': stats,
            'dashboard_url': dashboard_url,
            'generated_at': now,
            'chart_labels': labels,
            'chart_successes': successes_series,
            'chart_failures': failures_series,
            'chart_successes_pct': successes_pct,
            'chart_failures_pct': failures_pct,
            'email_chart': email_chart,
            'email_bar_px_height': bar_px_height,
            'email_chart_html': email_chart_html,
            'week_success_total': week_success_total,
            'week_failure_total': week_failure_total,
            'prev_week_success_total': prev_succ,
            'prev_week_failure_total': prev_fail,
            'week_deltas': deltas,
        })
        text_body = (
            f"{site_name} Security Summary\n"
            f"Total users: {stats['total_users']}\n"
            f"MFA enabled (TOTP): {stats['users_with_totp']}\n"
            f"MFA adoption rate: {stats['mfa_adoption_rate_pct']}%\n"
            f"Superadmins: {stats['superusers_count']}\n"
            f"Successes (24h): {stats['successes_24h']}\n"
            f"Failed attempts (24h): {stats['failed_attempts_24h']}\n"
            f"Dashboard: {dashboard_url}\n"
        )
        self.stdout.write(self.style.NOTICE(f"email_chart days: {len(email_chart)}; sample: {email_chart[0] if email_chart else '[]'}"))
        dump_path = options.get('dump_html')
        if dump_path:
            try:
                mode = 'wb'
                with open(dump_path, mode) as f:
                    html_bytes = html_body.encode('utf-8')
                    f.write(html_bytes)
                self.stdout.write(self.style.SUCCESS(f'Rendered HTML written to {dump_path}'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Failed to write HTML to {dump_path}: {e}'))
            return
        if options['dry_run']:
            self.stdout.write(self.style.SUCCESS('Dry run: Would send to %s' % (', '.join(recipients))))
            self.stdout.write(text_body)
            return
        lock_key = 'mfa:send_security_summary:lock_override' if is_override else 'mfa:send_security_summary:lock'
        got_lock = cache.add(lock_key, now.isoformat(), timeout=300)
        if not got_lock and not options['force']:
            self.stdout.write(self.style.NOTICE('Another send is in progress or was just performed. Skipping.'))
            return
        try:
            msg = EmailMultiAlternatives(subject=subject, body=text_body, from_email=from_email, to=recipients)
            if donut_cid and 'buf' in locals():
                img = MIMEImage(buf.getvalue(), _subtype='png')
                img.add_header('Content-ID', f'<{donut_cid}>')
                img.add_header('Content-Disposition', 'inline', filename='mfa_donut.png')
                msg.attach(img)
            try:
                days = max(1, int(getattr(settings_obj, 'report_csv_days', 7) or 7))
                since_dt = now - timedelta(days=days)
                logs_qs = MFALog.objects.filter(created_at__gte=since_dt).order_by('created_at')
                buf_csv = StringIO()
                writer = csv.writer(buf_csv, quoting=csv.QUOTE_ALL, lineterminator='\n')
                writer.writerow(['created_at', 'user_id', 'event', 'method', 'ip_address', 'user_agent', 'details'])
                def _clean(s: str) -> str:
                    try:
                        s = (s or '').replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
                        s = ' '.join(s.split())
                        return s
                    except Exception:
                        return s or ''
                for log in logs_qs.iterator(chunk_size=1000):
                    writer.writerow([
                        log.created_at.strftime('%Y-%m-%d %H:%M:%S%z'),
                        log.user_id or '',
                        log.event,
                        _clean(log.method)[:5000],
                        _clean(log.ip_address)[:5000],
                        _clean(log.user_agent)[:5000],
                        _clean(log.details)[:5000],
                    ])
                csv_bytes = ('\ufeff' + buf_csv.getvalue()).encode('utf-8')
                filename = f"mfa_logs_last_{days}d_{now.strftime('%Y%m%d')}.csv"
                msg.attach(filename, csv_bytes, 'text/csv')
            except Exception:
                pass
            msg.attach_alternative(html_body, 'text/html')
            msg.send(fail_silently=False)
            if not is_override:
                settings_obj.report_last_sent_at = now
                settings_obj.report_next_send_at = now + timedelta(days=max(1, settings_obj.report_frequency_days))
                settings_obj.save(update_fields=['report_last_sent_at', 'report_next_send_at'])
            self.stdout.write(self.style.SUCCESS('Sent summary to %s' % (', '.join(recipients))))
        finally:
            try:
                cache.delete(lock_key)
            except Exception:
                pass
