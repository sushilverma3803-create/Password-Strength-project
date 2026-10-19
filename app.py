from datetime import datetime, timezone
import functools
import hashlib
import io
import json
import os
import re
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from config import Config
from models import db, User, SavedPassword, StrengthReport, AnalysisAudit, CompromisedPassword, AuditLog
from analyzer import analyze_password
from generator import generate_secure_password
from breach_checker import check_password_breach
from recommendations_engine import SecurityRecommendationsEngine
from pdf_exporter import generate_pdf_report


def login_required(view):
    """Decorator to require login for specific routes."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user_id = session.get('user_id')
        if not user_id:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'authenticated': False}), 401
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.path))

        user = db.session.get(User, user_id)
        if not user:
            session.clear()
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'User session expired. Please log in again.', 'authenticated': False}), 401
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login', next=request.path))

        return view(**kwargs)
    return wrapped_view


def mask_password(password: str) -> str:
    """Create a masked preview string of a password (e.g. ab••••••12)."""
    if not password:
        return '••••••••'
    if len(password) <= 4:
        return '•' * len(password)
    return password[:2] + ('•' * (len(password) - 4)) + password[-2:]


def log_security_event(event_type: str, description: str, user_id=None):
    """Log an audit event to SQLite database with IP and User-Agent telemetry."""
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
        if ',' in ip:
            ip = ip.split(',')[0].strip()
        ua = (request.headers.get('User-Agent') or 'Unknown')[:250]
        uid = user_id if user_id is not None else session.get('user_id')

        log = AuditLog(
            user_id=uid,
            event_type=event_type,
            description=description,
            ip_address=ip[:45],
            user_agent=ua
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


def create_app(config_override=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_override:
        app.config.update(config_override)

    # Initialize extensions
    db.init_app(app)

    # Ensure tables exist and seed common compromised passwords
    with app.app_context():
        db.create_all()
        seed_common_breaches()

    @app.before_request
    def ensure_database_schema():
        if not getattr(app, '_schema_ready', False):
            try:
                db.create_all()
                app._schema_ready = True
            except Exception as e:
                app.logger.warning(f"Schema verification note: {e}")

    @app.context_processor
    def inject_current_user():
        """Make current_user available to all templates."""
        user_id = session.get('user_id')
        user = db.session.get(User, user_id) if user_id else None
        return dict(current_user=user)

    # -------------------------------------------------------------------------
    # Web UI Routes
    # -------------------------------------------------------------------------
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if session.get('user_id'):
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            data = request.get_json(silent=True) if request.is_json else request.form
            username = (data.get('username') or '').strip()
            email = (data.get('email') or '').strip().lower()
            password = data.get('password') or ''
            confirm_password = data.get('confirm_password') or ''

            errors = []
            if not username or len(username) < 3:
                errors.append('Username must be at least 3 characters long.')
            elif not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
                errors.append('Username can only contain letters, numbers, underscores, and hyphens.')

            if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                errors.append('Please provide a valid email address.')

            if not password or len(password) < 6:
                errors.append('Password must be at least 6 characters long.')

            if password != confirm_password:
                errors.append('Passwords do not match.')

            if not errors:
                if User.query.filter_by(username=username).first():
                    errors.append('Username is already registered. Please choose another.')
                elif User.query.filter_by(email=email).first():
                    errors.append('Email is already registered. Please log in or use another email.')

            if errors:
                if request.is_json:
                    return jsonify({'success': False, 'errors': errors}), 400
                for err in errors:
                    flash(err, 'danger')
                return render_template('register.html', username=username, email=email)

            # Create user with bcrypt password hashing
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            # Auto log in the newly registered user
            session['user_id'] = user.id
            session['username'] = user.username

            log_security_event('AUTH_REGISTER', f"New operator account registered: {user.username}", user_id=user.id)

            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'Account created successfully!',
                    'redirect': url_for('dashboard')
                })

            flash(f'Welcome aboard, {user.username}! Your account was created successfully.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if session.get('user_id'):
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            data = request.get_json(silent=True) if request.is_json else request.form
            identifier = (data.get('identifier') or '').strip()
            password = data.get('password') or ''
            next_url = request.args.get('next') or url_for('dashboard')

            if not identifier or not password:
                msg = 'Please enter both your username/email and password.'
                if request.is_json:
                    return jsonify({'success': False, 'message': msg}), 400
                flash(msg, 'danger')
                return render_template('login.html', identifier=identifier)

            user = User.query.filter(
                (User.username == identifier) | (User.email == identifier.lower())
            ).first()

            if not user or not user.check_password(password):
                log_security_event('AUTH_LOGIN_FAILED', f"Failed authentication attempt for identifier: {identifier}")
                msg = 'Invalid credentials. Please verify your username/email and password.'
                if request.is_json:
                    return jsonify({'success': False, 'message': msg}), 401
                flash(msg, 'danger')
                return render_template('login.html', identifier=identifier)

            # Set session
            session['user_id'] = user.id
            session['username'] = user.username

            log_security_event('AUTH_LOGIN_SUCCESS', f"Operator {user.username} authenticated successfully", user_id=user.id)

            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'Logged in successfully!',
                    'redirect': next_url,
                    'user': user.to_dict()
                })

            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_url)

        return render_template('login.html')

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        uid = session.get('user_id')
        uname = session.get('username', 'Unknown')
        if uid:
            log_security_event('AUTH_LOGOUT', f"Operator {uname} safely logged out", user_id=uid)
        session.clear()
        if request.is_json:
            return jsonify({'success': True, 'message': 'Logged out successfully.'})
        flash('You have been safely logged out.', 'info')
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        user = db.session.get(User, session['user_id'])
        saved_passwords = user.saved_passwords.order_by(SavedPassword.id.desc()).all()
        saved_reports = user.strength_reports.order_by(StrengthReport.id.desc()).all()

        total_passwords = len(saved_passwords)
        total_reports = len(saved_reports)
        avg_score = round(sum(r.score for r in saved_reports) / total_reports, 1) if total_reports > 0 else 0

        return render_template(
            'dashboard.html',
            user=user,
            saved_passwords=saved_passwords,
            saved_reports=saved_reports,
            total_passwords=total_passwords,
            total_reports=total_reports,
            avg_score=avg_score
        )

    # -------------------------------------------------------------------------
    # User Profile & Security Management Routes
    # -------------------------------------------------------------------------
    @app.route('/profile')
    @login_required
    def profile():
        user = db.session.get(User, session['user_id'])
        recent_logs = user.audit_logs.order_by(AuditLog.id.desc()).limit(10).all()
        saved_passwords_count = user.saved_passwords.count()
        reports_count = user.strength_reports.count()
        reports = user.strength_reports.all()
        avg_score = round(sum(r.score for r in reports) / reports_count, 1) if reports_count > 0 else 0

        return render_template(
            'profile.html',
            user=user,
            recent_logs=recent_logs,
            saved_passwords_count=saved_passwords_count,
            reports_count=reports_count,
            avg_score=avg_score
        )

    @app.route('/profile/update', methods=['POST'])
    @login_required
    def profile_update():
        user = db.session.get(User, session['user_id'])
        email = (request.form.get('email') or '').strip().lower()

        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('profile'))

        existing = User.query.filter(User.email == email, User.id != user.id).first()
        if existing:
            flash('That email address is already registered by another account.', 'danger')
            return redirect(url_for('profile'))

        old_email = user.email
        user.email = email
        db.session.commit()
        log_security_event('PROFILE_UPDATE', f"Updated email from {old_email} to {email}")
        flash('Profile email updated successfully.', 'success')
        return redirect(url_for('profile'))

    @app.route('/profile/change-password', methods=['POST'])
    @login_required
    def profile_change_password():
        user = db.session.get(User, session['user_id'])
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not user.check_password(current_password):
            flash('Incorrect current master password.', 'danger')
            return redirect(url_for('profile'))

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return redirect(url_for('profile'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('profile'))

        user.set_password(new_password)
        db.session.commit()
        log_security_event('PASSWORD_CHANGED', f"Master password updated successfully for {user.username}")
        flash('Master password successfully updated with bcrypt hashing.', 'success')
        return redirect(url_for('profile'))

    @app.route('/profile/purge-vault', methods=['POST'])
    @login_required
    def profile_purge_vault():
        user = db.session.get(User, session['user_id'])
        count = user.saved_passwords.count()
        user.saved_passwords.delete()
        db.session.commit()
        log_security_event('VAULT_PURGED', f"Purged all {count} saved passwords from vault")
        flash(f'Purged {count} saved passwords from your vault.', 'info')
        return redirect(url_for('profile'))

    @app.route('/profile/purge-reports', methods=['POST'])
    @login_required
    def profile_purge_reports():
        user = db.session.get(User, session['user_id'])
        count = user.strength_reports.count()
        user.strength_reports.delete()
        db.session.commit()
        log_security_event('REPORTS_PURGED', f"Purged all {count} archived strength reports")
        flash(f'Purged {count} archived reports from your vault.', 'info')
        return redirect(url_for('profile'))

    # -------------------------------------------------------------------------
    # Audit Logs Console Routes
    # -------------------------------------------------------------------------
    @app.route('/audit-logs')
    def audit_logs_page():
        filter_type = request.args.get('type')
        query = AuditLog.query.order_by(AuditLog.id.desc())
        if filter_type:
            query = query.filter(AuditLog.event_type == filter_type)
        logs = query.limit(50).all()
        return render_template('audit_logs.html', logs=logs, current_filter=filter_type)

    @app.route('/api/audit-logs', methods=['GET'])
    def api_audit_logs():
        filter_type = request.args.get('type')
        limit = min(int(request.args.get('limit', 50)), 100)
        query = AuditLog.query.order_by(AuditLog.id.desc())
        if filter_type:
            query = query.filter(AuditLog.event_type == filter_type)
        logs = query.limit(limit).all()
        return jsonify({'success': True, 'logs': [l.to_dict() for l in logs]})

    # -------------------------------------------------------------------------
    # Cybersecurity Analytics & Telemetry Dashboard Routes
    # -------------------------------------------------------------------------
    def get_analytics_metrics():
        total_analyzed = AnalysisAudit.query.count()
        if total_analyzed == 0:
            return {
                'total_analyzed': 0,
                'avg_score': 0.0,
                'weak_count': 0,
                'medium_count': 0,
                'strong_count': 0,
                'very_strong_count': 0,
                'total_strong': 0,
                'breached_count': 0,
                'distribution': {'Weak': 0, 'Medium': 0, 'Strong': 0, 'Very Strong': 0},
                'criteria': {'upper': 0, 'lower': 0, 'digit': 0, 'symbol': 0, 'breached': 0},
                'timeline': [],
                'recent_audits': []
            }

        avg_score = round(db.session.query(db.func.avg(AnalysisAudit.score)).scalar() or 0, 1)
        weak_count = AnalysisAudit.query.filter(AnalysisAudit.status == 'Weak').count()
        medium_count = AnalysisAudit.query.filter(AnalysisAudit.status == 'Medium').count()
        strong_count = AnalysisAudit.query.filter(AnalysisAudit.status == 'Strong').count()
        very_strong_count = AnalysisAudit.query.filter(AnalysisAudit.status == 'Very Strong').count()
        total_strong = strong_count + very_strong_count
        breached_count = AnalysisAudit.query.filter(AnalysisAudit.is_breached == True).count()

        upper_count = AnalysisAudit.query.filter(AnalysisAudit.has_upper == True).count()
        lower_count = AnalysisAudit.query.filter(AnalysisAudit.has_lower == True).count()
        digit_count = AnalysisAudit.query.filter(AnalysisAudit.has_digit == True).count()
        symbol_count = AnalysisAudit.query.filter(AnalysisAudit.has_symbol == True).count()

        recent_audits = AnalysisAudit.query.order_by(AnalysisAudit.id.desc()).limit(15).all()
        timeline_audits = AnalysisAudit.query.order_by(AnalysisAudit.id.desc()).limit(20).all()
        timeline_audits.reverse()

        timeline = [{
            'id': a.id,
            'label': a.created_at.strftime('%H:%M:%S'),
            'score': a.score,
            'entropy': round(a.entropy, 1),
            'status': a.status
        } for a in timeline_audits]

        return {
            'total_analyzed': total_analyzed,
            'avg_score': avg_score,
            'weak_count': weak_count,
            'medium_count': medium_count,
            'strong_count': strong_count,
            'very_strong_count': very_strong_count,
            'total_strong': total_strong,
            'breached_count': breached_count,
            'distribution': {
                'Weak': weak_count,
                'Medium': medium_count,
                'Strong': strong_count,
                'Very Strong': very_strong_count
            },
            'criteria': {
                'upper': round((upper_count / total_analyzed) * 100, 1),
                'lower': round((lower_count / total_analyzed) * 100, 1),
                'digit': round((digit_count / total_analyzed) * 100, 1),
                'symbol': round((symbol_count / total_analyzed) * 100, 1),
                'breached': round((breached_count / total_analyzed) * 100, 1)
            },
            'timeline': timeline,
            'recent_audits': [a.to_dict() for a in recent_audits]
        }

    @app.route('/analytics')
    @app.route('/cyber-dashboard')
    def analytics():
        metrics = get_analytics_metrics()
        return render_template('analytics.html', **metrics)

    @app.route('/api/analytics/stats', methods=['GET'])
    def api_analytics_stats():
        return jsonify(get_analytics_metrics())

    @app.route('/api/analytics/seed-demo', methods=['POST'])
    def api_analytics_seed_demo():
        sample_passwords = [
            '123456', 'qwerty99', 'welcome1', 'P@ssw0rd2026', 'Dragon_Fire$88',
            'Xk9#vL2$wP7!zM4@', 'admin', 'football123', 'Quantum#Shield!999',
            'iloveyou', 'CyberSentinel2026!', 'correct-horse-battery-staple',
            'shadow77', 'Kx9#mQ!8_Alpha', 'pass123', 'HyperSec_Key%9872!#&'
        ]
        count_added = 0
        for pwd in sample_passwords:
            breach_res = check_password_breach(pwd, db_session=db.session, compromised_model=CompromisedPassword)
            is_breached = breach_res['is_breached']
            res = analyze_password(pwd, is_known_breached=is_breached)
            audit = AnalysisAudit(
                password_length=res['length'],
                score=res['score'],
                status=res['status'],
                entropy=res['entropy'],
                crack_time_display=res['crack_time']['offline_fast'],
                has_upper=res['criteria']['has_upper'],
                has_lower=res['criteria']['has_lower'],
                has_digit=res['criteria']['has_digit'],
                has_symbol=res['criteria']['has_symbol'],
                is_breached=is_breached
            )
            db.session.add(audit)
            count_added += 1

        db.session.commit()
        log_security_event('DEMO_SEEDED', f"Seeded {count_added} sample cryptographic audit records")
        return jsonify({'success': True, 'added': count_added, 'stats': get_analytics_metrics()})

    # -------------------------------------------------------------------------
    # Authentication & Session Status API
    # -------------------------------------------------------------------------
    @app.route('/api/auth/status', methods=['GET'])
    def api_auth_status():
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'authenticated': False, 'user': None})
        user = db.session.get(User, user_id)
        if not user:
            session.clear()
            return jsonify({'authenticated': False, 'user': None})
        return jsonify({'authenticated': True, 'user': user.to_dict()})

    # -------------------------------------------------------------------------
    # Password Vault Storage API (Saved Passwords in SQLite)
    # -------------------------------------------------------------------------
    @app.route('/api/save-generated', methods=['POST'])
    def api_save_generated():
        data = request.get_json(silent=True) or {}
        password = data.get('password', '').strip()
        label = data.get('label', 'Generated Password').strip() or 'Generated Password'

        if not password:
            return jsonify({'success': False, 'error': 'Password cannot be empty.'}), 400

        user_id = session.get('user_id')

        try:
            saved_pwd = SavedPassword(
                user_id=user_id,
                label=label[:100],
                password=password,
                length=len(password)
            )
            db.session.add(saved_pwd)
            db.session.commit()

            log_security_event('PASSWORD_SAVED', f"Stored password with label: {label[:30]}", user_id=user_id)

            return jsonify({
                'success': True,
                'message': 'Password securely stored in vault.',
                'item': saved_pwd.to_dict()
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/saved-passwords', methods=['GET'])
    @login_required
    def api_get_saved_passwords():
        user = db.session.get(User, session['user_id'])
        items = user.saved_passwords.order_by(SavedPassword.id.desc()).all()
        return jsonify({'success': True, 'passwords': [item.to_dict() for item in items]})

    @app.route('/api/user/saved-passwords/<int:item_id>', methods=['DELETE'])
    @login_required
    def api_delete_saved_password(item_id):
        item = db.session.get(SavedPassword, item_id)
        if not item or item.user_id != session['user_id']:
            return jsonify({'success': False, 'error': 'Password item not found.'}), 404

        try:
            db.session.delete(item)
            db.session.commit()
            log_security_event('PASSWORD_DELETED', f"Deleted saved password ID #{item_id}")
            return jsonify({'success': True, 'message': 'Password removed from vault.'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    # -------------------------------------------------------------------------
    # Strength Reports Storage API (SQLite)
    # -------------------------------------------------------------------------
    @app.route('/api/save-report', methods=['POST'])
    def api_save_report():
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        analysis = data.get('analysis') or {}

        if not analysis and password:
            breach_res = check_password_breach(password, db_session=db.session, compromised_model=CompromisedPassword)
            analysis = analyze_password(password, is_known_breached=breach_res['is_breached'])

        if not analysis:
            return jsonify({'success': False, 'error': 'No report data provided.'}), 400

        user_id = session.get('user_id')
        score = analysis.get('score', 0)
        status = analysis.get('status', 'Weak')
        entropy = float(analysis.get('entropy', 0.0))
        crack_time = (analysis.get('crack_time') or {}).get('offline_fast', 'Instant')
        pool_size = (analysis.get('entropy_metrics') or {}).get('pool_size', 0)
        warnings_count = len(analysis.get('warnings', []))
        is_breached = bool(analysis.get('is_breached', False))

        masked_preview = mask_password(password)

        try:
            report = StrengthReport(
                user_id=user_id,
                password_preview=masked_preview,
                score=score,
                status=status,
                entropy=entropy,
                crack_time=crack_time,
                pool_size=pool_size,
                warnings_count=warnings_count,
                is_breached=is_breached,
                details_json=json.dumps(analysis)
            )
            db.session.add(report)
            db.session.commit()

            log_security_event('REPORT_SAVED', f"Archived strength report ({status}, score: {score}/100)", user_id=user_id)

            return jsonify({
                'success': True,
                'message': 'Strength report archived to vault.',
                'item': report.to_dict()
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/reports', methods=['GET'])
    @login_required
    def api_get_user_reports():
        user = db.session.get(User, session['user_id'])
        items = user.strength_reports.order_by(StrengthReport.id.desc()).all()
        return jsonify({'success': True, 'reports': [item.to_dict() for item in items]})

    @app.route('/api/user/reports/<int:report_id>', methods=['DELETE'])
    @login_required
    def api_delete_report(report_id):
        report = db.session.get(StrengthReport, report_id)
        if not report or report.user_id != session['user_id']:
            return jsonify({'success': False, 'error': 'Report not found.'}), 404

        try:
            db.session.delete(report)
            db.session.commit()
            log_security_event('REPORT_DELETED', f"Deleted strength report ID #{report_id}")
            return jsonify({'success': True, 'message': 'Report removed from vault.'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    # -------------------------------------------------------------------------
    # PDF Audit Report Export API
    # -------------------------------------------------------------------------
    @app.route('/api/export-pdf', methods=['POST'])
    def api_export_pdf():
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        analysis = data.get('analysis')

        if not analysis and password:
            breach_res = check_password_breach(password, db_session=db.session, compromised_model=CompromisedPassword)
            analysis = analyze_password(password, is_known_breached=breach_res['is_breached'])
            analysis['breach_info'] = breach_res

        if not analysis:
            return jsonify({'error': 'No password or analysis provided for export.'}), 400

        user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
        operator_name = user.username if user else "Anonymous Operator"
        preview = mask_password(password)

        # Generate recommendations for PDF
        recs = SecurityRecommendationsEngine.generate_recommendations(
            password=password,
            score=analysis.get('score', 0),
            entropy=analysis.get('entropy', 0.0),
            criteria=analysis.get('criteria', {}),
            warnings=analysis.get('warnings', []),
            is_breached=analysis.get('is_breached', False),
            breach_count=(analysis.get('breach_info') or {}).get('count', 0)
        )

        try:
            pdf_bytes = generate_pdf_report(
                analysis_data=analysis,
                password_preview=preview,
                operator_name=operator_name,
                recommendations=recs
            )

            log_security_event('PDF_EXPORT', f"Exported PDF audit report (Score: {analysis.get('score')})")

            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"CyberGuard_Security_Audit_{int(datetime.now().timestamp())}.pdf"
            )
        except Exception as e:
            app.logger.error(f"PDF generation failed: {e}")
            return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

    @app.route('/api/export-report-pdf/<int:report_id>', methods=['GET'])
    @login_required
    def api_export_saved_report_pdf(report_id):
        report = db.session.get(StrengthReport, report_id)
        if not report or report.user_id != session['user_id']:
            return jsonify({'error': 'Report not found or unauthorized.'}), 404

        analysis = report.to_dict().get('details') or {
            'score': report.score,
            'status': report.status,
            'entropy': report.entropy,
            'crack_time': {'offline_fast': report.crack_time},
            'length': len(report.password_preview),
            'criteria': {},
            'is_breached': report.is_breached
        }

        user = db.session.get(User, session['user_id'])
        recs = SecurityRecommendationsEngine.generate_recommendations(
            password=report.password_preview,
            score=report.score,
            entropy=report.entropy,
            criteria=analysis.get('criteria', {}),
            warnings=analysis.get('warnings', []),
            is_breached=report.is_breached
        )

        pdf_bytes = generate_pdf_report(
            analysis_data=analysis,
            password_preview=report.password_preview,
            operator_name=user.username,
            recommendations=recs
        )

        log_security_event('PDF_EXPORT', f"Exported saved report #{report_id} as PDF")

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"CyberGuard_Report_{report_id}_{int(datetime.now().timestamp())}.pdf"
        )

    # -------------------------------------------------------------------------
    # Breach Checking Dedicated API
    # -------------------------------------------------------------------------
    @app.route('/api/check-breach', methods=['POST'])
    def api_check_breach():
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        if not password:
            return jsonify({'is_breached': False, 'count': 0, 'source': 'None'})

        res = check_password_breach(password, db_session=db.session, compromised_model=CompromisedPassword)
        return jsonify(res)

    # -------------------------------------------------------------------------
    # Core Password Analyzer & Generator APIs (Enhanced with HIBP & Recommendations)
    # -------------------------------------------------------------------------
    @app.route('/api/analyze', methods=['POST'])
    def api_analyze():
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        save_audit = data.get('save_audit', True)

        if not password:
            empty_res = analyze_password('')
            empty_res['breach_info'] = {'is_breached': False, 'count': 0, 'source': 'None'}
            empty_res['recommendations_detailed'] = SecurityRecommendationsEngine.generate_recommendations('', 0, 0, {}, [], False)
            return jsonify(empty_res)

        # 1. Real-time HIBP k-Anonymity API breach detection
        breach_res = check_password_breach(password, db_session=db.session, compromised_model=CompromisedPassword)
        is_breached = breach_res['is_breached']

        # 2. Cryptographic heuristics analysis
        result = analyze_password(password, is_known_breached=is_breached)
        result['breach_info'] = breach_res

        # 3. Security Recommendations Engine
        recommendations = SecurityRecommendationsEngine.generate_recommendations(
            password=password,
            score=result['score'],
            entropy=result['entropy'],
            criteria=result['criteria'],
            warnings=result.get('warnings', []),
            is_breached=is_breached,
            breach_count=breach_res.get('count', 0)
        )
        result['recommendations_detailed'] = recommendations
        result['recommendations'] = [r['message'] for r in recommendations]

        # 4. Log anonymous metadata to SQLite database
        if save_audit and len(password) > 0:
            try:
                audit = AnalysisAudit(
                    password_length=result['length'],
                    score=result['score'],
                    status=result['status'],
                    entropy=result['entropy'],
                    crack_time_display=result['crack_time']['offline_fast'],
                    has_upper=result['criteria']['has_upper'],
                    has_lower=result['criteria']['has_lower'],
                    has_digit=result['criteria']['has_digit'],
                    has_symbol=result['criteria']['has_symbol'],
                    is_breached=is_breached
                )
                db.session.add(audit)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.warning(f"Failed to record audit log: {e}")

        return jsonify(result)

    @app.route('/api/generate', methods=['POST'])
    def api_generate():
        data = request.get_json(silent=True) or {}
        length = int(data.get('length', 16))
        include_upper = bool(data.get('upper', True))
        include_lower = bool(data.get('lower', True))
        include_digits = bool(data.get('digits', True))
        include_symbols = bool(data.get('symbols', True))
        exclude_ambiguous = bool(data.get('exclude_ambiguous', True))

        generated_pwd = generate_secure_password(
            length=length,
            include_upper=include_upper,
            include_lower=include_lower,
            include_digits=include_digits,
            include_symbols=include_symbols,
            exclude_ambiguous=exclude_ambiguous
        )

        analysis = analyze_password(generated_pwd, is_known_breached=False)
        analysis['breach_info'] = {'is_breached': False, 'count': 0, 'source': 'CSPRNG Verified'}
        analysis['recommendations_detailed'] = SecurityRecommendationsEngine.generate_recommendations(
            generated_pwd, analysis['score'], analysis['entropy'], analysis['criteria'], [], False
        )

        return jsonify({
            'password': generated_pwd,
            'analysis': analysis
        })

    @app.route('/api/history', methods=['GET'])
    def api_history():
        audits = AnalysisAudit.query.order_by(AnalysisAudit.id.desc()).limit(8).all()
        total_scans = AnalysisAudit.query.count()
        strong_count = AnalysisAudit.query.filter(AnalysisAudit.status.in_(['Strong', 'Very Strong'])).count()
        safe_ratio = round((strong_count / total_scans * 100), 1) if total_scans > 0 else 0

        return jsonify({
            'history': [a.to_dict() for a in audits],
            'stats': {
                'total_scans': total_scans,
                'safe_ratio': safe_ratio
            }
        })

    @app.route('/api/clear-history', methods=['POST'])
    def api_clear_history():
        try:
            AnalysisAudit.query.delete()
            db.session.commit()
            log_security_event('AUDIT_HISTORY_CLEARED', 'Cleared anonymous scan audit history')
            return jsonify({'success': True, 'message': 'Audit logs cleared.'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    return app


def seed_common_breaches():
    """Populate database with top known breached / weak passwords if empty."""
    if CompromisedPassword.query.first():
        return

    top_breached = [
        "123456", "password", "123456789", "12345", "12345678", "qwerty",
        "1234567", "111111", "1234567890", "123123", "password1", "welcome",
        "admin", "iloveyou", "princess", "football", "monkey", "sunshine",
        "master", "shadow", "superman", "starwars", "secret", "testing",
        "pass123", "admin123", "login", "root", "guest", "charlie"
    ]

    for pwd in top_breached:
        h = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
        db.session.add(CompromisedPassword(
            plain_text=pwd.lower(),
            sha256_hash=h,
            category='Top Leaked Passwords'
        ))

    db.session.commit()


app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
    app.run(host='0.0.0.0', port=port, debug=debug)
