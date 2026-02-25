from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, make_response
from database import mysql, init_db
from datetime import datetime

import re
import io, csv
import datetime as _dt
from flask import send_file

app = Flask(__name__)
app.secret_key = "your_secret_key"

init_db(app)

# ---------------- Password Strength ----------------
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[!@#$%^&*]", password)
    )

# ---------------- Smart Categorize (AI Logic) ----------------
def smart_category(item):
    # improved categorizer: keyword mapping + token matching + fuzzy fallback
    item = (item or '').lower()
    # tokenize words (alphanumeric)
    tokens = re.findall(r"\w+", item)

    # category -> keywords (include common synonyms and local terms)
    category_keywords = {
        'Transportation': ['bus', 'taxi', 'uber', 'ola', 'grab', 'fuel', 'petrol', 'diesel', 'metro', 'train', 'fare', 'cab', 'transport'],
        'Food': ['food', 'rice', 'lunch', 'dinner', 'breakfast', 'momo', 'snack', 'snacks', 'chips', 'pizza', 'burger', 'noodle', 'dal', 'bhat', 'meal', 'chai', 'tea', 'coffee', 'restaurant'],
        'Housing': ['rent', 'mortgage', 'home', 'apartment'],
        'Utilities': ['mobile', 'internet', 'electricity', 'water', 'gas', 'wifi', 'phone', 'bill'],
        'Entertainment': ['movie', 'netflix', 'spotify', 'concert', 'games', 'game', 'theatre'],
        'Health': ['doctor', 'hospital', 'pharmacy', 'medicine', 'clinic'],
        'Shopping': ['shop', 'clothes', 'shopping', 'amazon', 'flipkart', 'mall', 'buy'],
        'Education': ['school', 'tuition', 'course', 'books', 'library'],
        'Others': []
    }

    # direct substring match first (covers multi-word tokens)
    for cat, kws in category_keywords.items():
        for kw in kws:
            if kw in item:
                return cat

    # token match (exact token in keywords)
    token_set = set(tokens)
    for cat, kws in category_keywords.items():
        if token_set.intersection(kws):
            return cat

    # fuzzy match fallback for short typos (use difflib)
    try:
        from difflib import get_close_matches
        all_keywords = [k for kws in category_keywords.values() for k in kws]
        for t in tokens:
            # ignore very short tokens
            if len(t) < 3:
                continue
            m = get_close_matches(t, all_keywords, n=1, cutoff=0.8)
            if m:
                # find category for matched keyword
                for cat, kws in category_keywords.items():
                    if m[0] in kws:
                        return cat
    except Exception:
        pass

    return 'Others'

# ---------------- INDEX ----------------
@app.route('/')
def index():
    return render_template('index.html')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        age = request.form['age']
        password = request.form['password']
        confirm = request.form['confirm_password']

        # 🔹 Password strength check
        if not is_strong_password(password):
            flash("Password too weak!", "error")
            return render_template('register.html')

        # 🔹 Password match check
        if password != confirm:
            flash("Passwords do not match!", "error")
            return render_template('register.html')

        cur = mysql.connection.cursor()

        # 🔹 Check if username already exists
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        existing_user = cur.fetchone()
        if existing_user:
            flash("Username already exists! Try another one.", "error")
            return render_template('register.html')

        # 🔹 Check if email already exists
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        existing_email = cur.fetchone()
        if existing_email:
            flash("Email already registered!", "error")
            return render_template('register.html')

        # 🔹 Ensure role column exists
        cur.execute("SHOW COLUMNS FROM users LIKE 'role'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'")
            mysql.connection.commit()

        # 🔹 Insert new user
        cur.execute(
            "INSERT INTO users (username,email,age,password,role) VALUES (%s,%s,%s,%s,%s)",
            (username,email,age,password,'user')
        )
        mysql.connection.commit()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        requested_role = request.form.get('role', 'user')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        

        role = 'user'
        if user:
            col_names = [d[0] for d in cur.description]
            if 'role' in col_names:
                try:
                    role = user[col_names.index('role')]
                except Exception:
                    role = 'user'

        # enforce requested role: if user requested admin but account is not admin, reject
        if user and user[4] == password:
            if requested_role == 'admin' and role != 'admin':
                flash('Access denied: your account is not an admin', 'error')
                return render_template('login.html')
            # set session role to the actual account role (don't trust client)
            session['user_id'] = user[0]
            session['role'] = role
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid login!", "error")

    return render_template('login.html')

# ---------------- DASHBOARD ----------------
from datetime import datetime
# from flask import redirect, url_for, render_template, session

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    # ---------------- User Info ----------------
    cur.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cur.fetchone()
    # capture the column names for the `users` query immediately
    user_col_names = [d[0] for d in cur.description] if cur.description else []
    role = session.get('role', 'user')

    username = user[1] if user else "User"

    # ---------------- Greeting Logic ----------------
    current_hour = datetime.now().hour

    if 5 <= current_hour < 12:
        greeting = "Good morning"
    elif 12 <= current_hour < 17:
        greeting = "Good afternoon"
    elif 17 <= current_hour < 21:
        greeting = "Good evening"
    else:
        greeting = "Good night"

    message = f"Welcome {username}, {greeting}!"

    # ---------------- Expenses ----------------
    cur.execute("SELECT * FROM expenses WHERE user_id=%s", (session['user_id'],))
    expenses = cur.fetchall()

    total_expense = sum(e[5] for e in expenses)

    # ---------------- Budget / Salary ----------------
    total_budget = 0
    remaining_budget = None
    salary = None

    try:
        if 'budget' in user_col_names:
            # The `users.budget` column stores the current remaining budget.
            # Compute the original total budget as (remaining + total_expense)
            current_remaining = float(user[user_col_names.index('budget')] or 0)
            remaining_budget = current_remaining
            total_budget = current_remaining + float(total_expense or 0)
        if 'salary' in user_col_names:
            salary = float(user[user_col_names.index('salary')] or 0)
        # optional profile fields
        bank_name = None
        account_no = None
        if 'bank_name' in user_col_names:
            try:
                bank_name = user[user_col_names.index('bank_name')]
            except Exception:
                bank_name = None
        if 'account_no' in user_col_names:
            try:
                account_no = user[user_col_names.index('account_no')]
            except Exception:
                account_no = None
    except Exception:
        pass

    # ---------------- AI Message ----------------
    ai_message = ""
    if total_budget > 0:
        try:
            pct = (float(total_expense) / float(total_budget)) * 100 if total_budget else 0
        except Exception:
            pct = 0

        # gather top categories to provide focused advice
        try:
            cur.execute(
                "SELECT category, SUM(cost) as s FROM expenses WHERE user_id=%s GROUP BY category ORDER BY s DESC LIMIT 3",
                (session['user_id'],)
            )
            cat_rows = cur.fetchall()
            top_cats = [r[0] or 'Others' for r in cat_rows]
        except Exception:
            top_cats = []

        # average daily spend estimate (use last 30 days if available)
        try:
            cur.execute(
                "SELECT SUM(cost) FROM expenses WHERE user_id=%s AND DATE(date_time) >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)",
                (session['user_id'],)
            )
            last30 = cur.fetchone()[0] or 0
            avg_daily = float(last30) / 30 if last30 else 0
        except Exception:
            avg_daily = 0

        # craft nuanced, actionable suggestions
        if total_expense > total_budget:
            over = float(total_expense) - float(total_budget)
            ai_message = (
                f"AI Alert: Budget exceeded by Rs {over:,.2f}. "
                f"Top categories: {', '.join(top_cats) if top_cats else 'N/A'}. "
                "Consider cutting non-essential items and moving recurring costs to next month."
            )
        elif pct >= 90:
            ai_message = (
                f"AI Warning: You're at {pct:.0f}% of your budget. "
                f"Top spends: {', '.join(top_cats) if top_cats else 'N/A'}. "
                "Avoid large discretionary purchases and review subscriptions."
            )
        elif pct >= 60:
            ai_message = (
                f"AI Notice: You've used {pct:.0f}% of your budget. "
                f"Watch {top_cats[0] if top_cats else 'major'} spending — try reducing it by 10–20%."
            )
        elif pct >= 40:
            ai_message = (
                f"AI Tip: {pct:.0f}% used of budget. Estimated daily spend: Rs {avg_daily:.2f}. "
                "Plan to keep daily spend lower to stay within budget."
            )
        else:
            ai_message = (
                f"Good job — only {pct:.0f}% of budget used. "
                f"Average daily: Rs {avg_daily:.2f}. Maintain current habits or save the surplus."
            )

    return render_template(
        "dashboard.html",
        message=message,
        expenses=expenses,
        total_budget=total_budget,
        total_expense=total_expense,
        remaining_budget=remaining_budget,
        salary=salary,
        ai_message=ai_message,
        user=user,
        role=role,
        bank_name=bank_name,
        account_no=account_no
    )


# ---------------- ADD EXPENSE ----------------
@app.route('/add-expense', methods=['POST'])
def add_expense():
    item = request.form['item']
    # budget removed from Add Item form; keep stored budget per expense optional
    budget = None
    if 'budget' in request.form and request.form.get('budget'):
        try:
            budget = float(request.form.get('budget'))
        except Exception:
            budget = None
    # robust cost parsing: allow commas and graceful error handling
    cost_raw = request.form.get('cost', '').replace(',', '').strip()
    try:
        cost = float(cost_raw)
    except Exception:
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Invalid cost value'}), 400
        flash('Invalid cost value', 'error')
        return redirect(url_for('dashboard') + '#expenses')
    category = smart_category(item)

    cur = mysql.connection.cursor()
    # ensure user is authenticated
    if 'user_id' not in session:
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'not authenticated'}), 401
        flash('Not authenticated', 'error')
        return redirect(url_for('login'))

    # allow admin to add expense for other users by passing 'user_id'
    target_user = session['user_id']
    if session.get('role') == 'admin' and request.form.get('user_id'):
        try:
            target_user = int(request.form.get('user_id'))
        except Exception:
            pass

    # check if user has a budget column and current budget (for the target user)
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    has_budget_col = bool(cur.fetchone())
    current_budget = None
    if has_budget_col:
        cur.execute("SELECT budget FROM users WHERE id=%s", (target_user,))
        row = cur.fetchone()
        if row:
            try:
                current_budget = float(row[0] or 0)
            except Exception:
                current_budget = 0

    # If budget exists, prevent adding expense that exceeds remaining budget
    if current_budget is not None:
        if cost > current_budget:
            error_msg = (
                f"❌ Your budget is less than your expense! "
                f"Remaining budget: Rs {current_budget:,.2f} | "
                f"Expense cost: Rs {cost:,.2f}"
            )
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': error_msg}), 400
            flash(error_msg, 'error')
            return redirect(url_for('dashboard'))

    # insert expense
    cur.execute(
        "INSERT INTO expenses (user_id,item,category,budget,cost,date_time) VALUES (%s,%s,%s,%s,%s,%s)",
        (target_user, item, category, budget, cost, datetime.now())
    )
    mysql.connection.commit()

    # decrement user's budget if present
    if current_budget is not None:
        cur.execute("UPDATE users SET budget = GREATEST(budget - %s, 0) WHERE id=%s", (cost, target_user))
        mysql.connection.commit()

    # If AJAX/JSON request, return inserted row and totals
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM expenses WHERE user_id=%s ORDER BY id DESC LIMIT 1", (target_user,))
        new_row = cur.fetchone()
        cur.execute("SELECT SUM(cost) FROM expenses WHERE user_id=%s", (target_user,))
        total_exp = cur.fetchone()[0] or 0
        # get updated remaining budget if exists
        cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
        rem = None
        if cur.fetchone():
            cur.execute("SELECT budget FROM users WHERE id=%s", (target_user,))
            r = cur.fetchone()
            rem = float(r[0] or 0) if r else None
        return jsonify({
            'row': new_row,
            'total_expense': total_exp,
            'remaining_budget': rem,
            'message': 'Expense added successfully'
        })

    # non-AJAX: flash message and redirect to expenses view
    flash('Expense added successfully', 'success')
    return redirect(url_for('dashboard') + '#expenses')


def ensure_column_exists(table, column, definition):
    cur = mysql.connection.cursor()
    cur.execute("SHOW COLUMNS FROM %s LIKE %s" % (table, '%s'), (column,))
    exists = cur.fetchone()
    if not exists:
        cur.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, definition))
        mysql.connection.commit()

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    row = cur.fetchone()
    col_names = [d[0] for d in cur.description] if cur.description else []
    user = {}
    if row:
        for i, c in enumerate(col_names):
            user[c] = row[i]
    # render account settings template expecting `user` mapping
    return render_template('account_settings.html', user=user)


@app.route('/account/update-profile', methods=['POST'])
def account_update_profile():
    if 'user_id' not in session:
        return jsonify({'ok': False, 'error': 'not authenticated'}), 401
    # fields we support updating via the account page
    fields = ['first_name', 'middle_name', 'last_name', 'bank_name', 'account_no']
    cur = mysql.connection.cursor()
    # ensure columns exist before updating
    for f in fields:
        cur.execute("SHOW COLUMNS FROM users LIKE %s", (f,))
        if not cur.fetchone():
            # create as VARCHAR(255)
            try:
                cur.execute(f"ALTER TABLE users ADD COLUMN {f} VARCHAR(255)")
                mysql.connection.commit()
            except Exception:
                pass
    # build update set
    updates = []
    params = []
    for f in fields:
        v = request.form.get(f)
        if v is not None:
            updates.append(f + "=%s")
            params.append(v)
    if updates:
        params.append(session['user_id'])
        sql = "UPDATE users SET " + ",".join(updates) + " WHERE id=%s"
        try:
            cur.execute(sql, tuple(params))
            mysql.connection.commit()
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
    return jsonify({'ok': True})


@app.route('/account/update-password', methods=['POST'])
def account_update_password():
    if 'user_id' not in session:
        return jsonify({'ok': False, 'error': 'not authenticated'}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    row = cur.fetchone()
    col_names = [d[0] for d in cur.description] if cur.description else []
    try:
        pwd_idx = col_names.index('password')
    except ValueError:
        pwd_idx = 4
    stored = row[pwd_idx] if row else None
    current = request.form.get('current_password', '')
    newpwd = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    if stored != current:
        return jsonify({'ok': False, 'error': 'Current password is incorrect'}), 400
    if newpwd != confirm:
        return jsonify({'ok': False, 'error': 'Passwords do not match'}), 400
    # optional: enforce strength
    if not is_strong_password(newpwd):
        return jsonify({'ok': False, 'error': 'Password too weak'}), 400
    try:
        cur.execute("UPDATE users SET password=%s WHERE id=%s", (newpwd, session['user_id']))
        mysql.connection.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/set-budget', methods=['POST'])
def set_budget():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    budget_input = request.form.get('budget', '').strip()
    # ensure budget column exists
    cur = mysql.connection.cursor()
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN budget FLOAT DEFAULT 0")
        mysql.connection.commit()
    # get current remaining budget
    cur.execute("SELECT budget FROM users WHERE id=%s", (session['user_id'],))
    row = cur.fetchone()
    current = float(row[0] or 0) if row else 0
    # support relative adjustments: +1000 to add, -500 to subtract, or absolute set
    try:
        if budget_input.startswith('+') or budget_input.startswith('-'):
            delta = float(budget_input)
            new_budget = max(current + delta, 0)
        else:
            new_budget = float(budget_input)
        cur.execute("UPDATE users SET budget=%s WHERE id=%s", (new_budget, session['user_id']))
        mysql.connection.commit()
    except Exception:
        # return JSON for AJAX callers, otherwise flash and redirect
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': False, 'error': 'Invalid budget value'}), 400
        flash('Invalid budget value', 'error')
        return redirect(url_for('dashboard') + '#expenses')

    # If AJAX request, return JSON with updated budget so front-end can update without reload
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'ok': True, 'budget': new_budget})

    # non-AJAX: redirect back to dashboard and show the expenses section
    return redirect(url_for('dashboard') + '#expenses')


@app.route('/clear-budget', methods=['POST'])
def clear_budget():
    if 'user_id' not in session:
        return jsonify({'ok': False, 'error': 'not authenticated'}), 401
    cur = mysql.connection.cursor()
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if not cur.fetchone():
        # nothing to clear
        return jsonify({'ok': True})
    try:
        cur.execute("UPDATE users SET budget=NULL WHERE id=%s", (session['user_id'],))
        mysql.connection.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'not authenticated'}), 401
    username = request.form.get('username')
    email = request.form.get('email')
    # ensure preferences column exists
    cur = mysql.connection.cursor()
    cur.execute("SHOW COLUMNS FROM users LIKE 'preferences'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN preferences TEXT")
        mysql.connection.commit()
    cur.execute("UPDATE users SET username=%s, email=%s, preferences=%s WHERE id=%s", (username, email, '', session['user_id']))
    mysql.connection.commit()
    return jsonify({'ok': True})


@app.route('/download-report')
def download_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT date_time, item, category, cost FROM expenses WHERE user_id=%s ORDER BY date_time", (session['user_id'],))
    rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Item', 'Category', 'Cost', 'Total'])
    running = 0
    for r in rows:
        date, item, category, cost = r[0], r[1], r[2], r[3] if len(r) > 3 else r[3]
        try:
            c = float(cost)
        except Exception:
            c = 0
        running += c
        writer.writerow([date, item, category, c, running])

    # append summary rows
    # attempt to include total budget and remaining budget
    cur.execute("SELECT budget FROM users WHERE id=%s", (session['user_id'],))
    b = None
    if cur.fetchone():
        cur.execute("SELECT budget FROM users WHERE id=%s", (session['user_id'],))
        bval = cur.fetchone()
        if bval:
            try:
                b = float(bval[0])
            except Exception:
                b = None

    writer.writerow([])
    writer.writerow(['Total Budget', b if b is not None else 'N/A'])
    writer.writerow(['Total Expense', running])
    if b is not None:
        writer.writerow(['Remaining', max(b, 0)])

    resp = make_response(output.getvalue())
    resp.headers['Content-Disposition'] = 'attachment; filename=expense_report.csv'
    resp.headers['Content-Type'] = 'text/csv'
    return resp


@app.route('/download-pdf')
def download_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM users WHERE id=%s", (session['user_id'],))
    u = cur.fetchone()
    username = u[0] if u else 'User'

    cur.execute("SELECT date_time, item, category, cost FROM expenses WHERE user_id=%s ORDER BY date_time", (session['user_id'],))
    rows = cur.fetchall()

    # totals and budget
    total_expense = sum((r[3] or 0) for r in rows)
    total_budget = 0
    remaining_budget = None
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if cur.fetchone():
        cur.execute("SELECT budget FROM users WHERE id=%s", (session['user_id'],))
        b = cur.fetchone()
        remaining_budget = float(b[0] or 0) if b else 0
        total_budget = remaining_budget + float(total_expense or 0)

    # AI message: reuse logic from dashboard
    ai_message = ''
    if total_budget > 0:
        try:
            pct = (float(total_expense) / float(total_budget)) * 100 if total_budget else 0
        except Exception:
            pct = 0
        try:
            cur.execute(
                "SELECT category, SUM(cost) as s FROM expenses WHERE user_id=%s GROUP BY category ORDER BY s DESC LIMIT 3",
                (session['user_id'],)
            )
            cat_rows = cur.fetchall()
            top_cats = [r[0] or 'Others' for r in cat_rows]
        except Exception:
            top_cats = []
        if total_expense > total_budget:
            over = float(total_expense) - float(total_budget)
            ai_message = f"Budget exceeded by Rs {over:,.2f}. Top: {', '.join(top_cats) if top_cats else 'N/A'}."
        else:
            ai_message = f"{pct:.0f}% of budget used. Top: {', '.join(top_cats) if top_cats else 'N/A'}."

    # render HTML, convert to PDF
    rendered = render_template('report_pdf.html', username=username, rows=rows, total_budget=total_budget, total_expense=total_expense, remaining_budget=remaining_budget, ai_message=ai_message, generated_at=datetime.now())
    try:
        from weasyprint import HTML
        pdf = HTML(string=rendered).write_pdf()
    except Exception as e:
        # fallback: deliver rendered HTML as attachment
        resp = make_response(rendered)
        resp.headers['Content-Disposition'] = 'attachment; filename=expense_report.html'
        resp.headers['Content-Type'] = 'text/html'
        return resp

    resp = make_response(pdf)
    resp.headers['Content-Disposition'] = 'attachment; filename=expense_report.pdf'
    resp.headers['Content-Type'] = 'application/pdf'
    return resp


@app.route('/expenses-data')
def expenses_data():
    if 'user_id' not in session:
        return jsonify({'labels': [], 'data': []})
    cur = mysql.connection.cursor()
    # last 7 days aggregated by date
    cur.execute(
        "SELECT DATE(date_time) as d, SUM(cost) as s FROM expenses WHERE user_id=%s GROUP BY DATE(date_time) ORDER BY DATE(date_time) DESC LIMIT 7",
        (session['user_id'],)
    )
    rows = cur.fetchall()
    # rows are newest first; reverse to chronological
    rows = rows[::-1]
    labels = []
    data = []
    for r in rows:
        d = r[0]
        # support both date and string
        if isinstance(d, (_dt.date, _dt.datetime)):
            labels.append(d.strftime('%Y-%m-%d'))
        else:
            labels.append(str(d))
        data.append(float(r[1] or 0))
    return jsonify({'labels': labels, 'data': data})


@app.route('/expenses-weeks')
def expenses_weeks():
    if 'user_id' not in session:
        return jsonify([])
    cur = mysql.connection.cursor()
    today = _dt.date.today()
    weeks = []
    for i in range(0, 4):
        # week starts on Monday
        ref = today - _dt.timedelta(weeks=i)
        start = ref - _dt.timedelta(days=ref.weekday())
        end = start + _dt.timedelta(days=6)
        cur.execute(
            "SELECT SUM(cost) FROM expenses WHERE user_id=%s AND DATE(date_time) BETWEEN %s AND %s",
            (session['user_id'], start, end)
        )
        total = cur.fetchone()[0] or 0
        # get items for this week
        cur.execute(
            "SELECT date_time, item, category, cost FROM expenses WHERE user_id=%s AND DATE(date_time) BETWEEN %s AND %s ORDER BY date_time",
            (session['user_id'], start, end)
        )
        items = [dict(date=str(r[0]), item=r[1], category=r[2], cost=float(r[3] or 0)) for r in cur.fetchall()]
        weeks.append({
            'label': f"{start.strftime('%Y-%m-%d')} → {end.strftime('%Y-%m-%d')}",
            'start': start.strftime('%Y-%m-%d'),
            'end': end.strftime('%Y-%m-%d'),
            'total': float(total),
            'items': items
        })
    return jsonify(weeks)


@app.route('/admin/users')
def admin_users():
    # return list of users for admin selector
    if session.get('role') != 'admin':
        return jsonify({'error':'forbidden'}), 403
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username FROM users ORDER BY username")
    rows = cur.fetchall()
    users = [{'id': r[0], 'username': r[1]} for r in rows]
    return jsonify(users)


@app.route('/admin/edit-user', methods=['POST'])
def admin_edit_user():
    if session.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'forbidden'}), 403
    uid = request.form.get('id') or (request.json.get('id') if request.is_json else None)
    if not uid:
        return jsonify({'ok': False, 'error': 'missing id'}), 400
    try:
        uid = int(uid)
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid id'}), 400
    username = request.form.get('username') or (request.json.get('username') if request.is_json else None)
    email = request.form.get('email') or (request.json.get('email') if request.is_json else None)
    role = request.form.get('role') or (request.json.get('role') if request.is_json else None)
    if not any([username, email, role]):
        return jsonify({'ok': False, 'error': 'nothing to update'}), 400
    cur = mysql.connection.cursor()
    updates = []
    params = []
    if username is not None:
        updates.append('username=%s'); params.append(username)
    if email is not None:
        updates.append('email=%s'); params.append(email)
    if role is not None:
        updates.append('role=%s'); params.append(role)
    params.append(uid)
    try:
        cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=%s", tuple(params))
        mysql.connection.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if session.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'forbidden'}), 403
    uid = request.form.get('id') or (request.json.get('id') if request.is_json else None)
    if not uid:
        return jsonify({'ok': False, 'error': 'missing id'}), 400
    try:
        uid = int(uid)
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid id'}), 400
    # Prevent admins from deleting their own account to avoid accidental lockout
    try:
        if 'user_id' in session and int(session['user_id']) == int(uid):
            return jsonify({'ok': False, 'error': "Operation forbidden: cannot delete your own account"}), 400
    except Exception:
        pass
    cur = mysql.connection.cursor()
    try:
        # delete expenses then user to keep DB consistent
        cur.execute("DELETE FROM expenses WHERE user_id=%s", (uid,))
        cur.execute("DELETE FROM users WHERE id=%s", (uid,))
        mysql.connection.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/admin/expenses/<int:uid>')
def admin_expenses_for_user(uid):
    if session.get('role') != 'admin':
        return jsonify({'error':'forbidden'}), 403
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, date_time, item, category, cost FROM expenses WHERE user_id=%s ORDER BY date_time", (uid,))
    rows = cur.fetchall()
    items = []
    for r in rows:
        items.append({'id': r[0], 'date': str(r[1]), 'item': r[2], 'category': r[3], 'cost': float(r[4] or 0)})
    # also return totals and remaining budget for that user
    cur.execute("SELECT SUM(cost) FROM expenses WHERE user_id=%s", (uid,))
    total = cur.fetchone()[0] or 0
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    remaining = None
    if cur.fetchone():
        cur.execute("SELECT budget FROM users WHERE id=%s", (uid,))
        r = cur.fetchone()
        remaining = float(r[0] or 0) if r else None
    return jsonify({'items': items, 'total': float(total), 'remaining': remaining})


@app.route('/edit-expense', methods=['POST'])
def edit_expense():
    if 'user_id' not in session and session.get('role') != 'admin':
        return jsonify({'error':'not authenticated'}), 401
    eid = request.form.get('id') or (request.json.get('id') if request.is_json else None)
    item = request.form.get('item') or (request.json.get('item') if request.is_json else None)
    cost = request.form.get('cost') or (request.json.get('cost') if request.is_json else None)
    if not eid:
        return jsonify({'error':'missing id'}), 400
    try:
        cost = float(cost)
    except Exception:
        return jsonify({'error':'invalid cost'}), 400
    cur = mysql.connection.cursor()
    # fetch old cost to adjust budget. Admins can edit any expense.
    if session.get('role') == 'admin':
        cur.execute("SELECT cost, user_id FROM expenses WHERE id=%s", (eid,))
    else:
        cur.execute("SELECT cost FROM expenses WHERE id=%s AND user_id=%s", (eid, session['user_id']))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'expense not found'}), 404
    if session.get('role') == 'admin':
        old_cost = float(row[0] or 0)
        owner_id = row[1]
        cur.execute("UPDATE expenses SET item=%s, cost=%s WHERE id=%s", (item, cost, eid))
    else:
        old_cost = float(row[0] or 0)
        owner_id = session['user_id']
        cur.execute("UPDATE expenses SET item=%s, cost=%s WHERE id=%s AND user_id=%s", (item, cost, eid, session['user_id']))
    mysql.connection.commit()
    # adjust user's budget if exists: add back old_cost then subtract new cost
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if cur.fetchone():
        cur.execute("UPDATE users SET budget = GREATEST(budget + %s - %s, 0) WHERE id=%s", (old_cost, cost, owner_id))
        mysql.connection.commit()
    # compute totals
    cur.execute("SELECT SUM(cost) FROM expenses WHERE user_id=%s", (session['user_id'],))
    total_exp = cur.fetchone()[0] or 0
    rem = None
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if cur.fetchone():
        cur.execute("SELECT budget FROM users WHERE id=%s", (session['user_id'],))
        r = cur.fetchone()
        rem = float(r[0] or 0) if r else None
    cur.execute("SELECT * FROM expenses WHERE id=%s", (eid,))
    updated = cur.fetchone()
    return jsonify({'row': updated, 'total_expense': total_exp, 'remaining_budget': rem, 'message':'Expense updated successfully'})


@app.route('/delete-expense', methods=['POST'])
def delete_expense():
    if 'user_id' not in session and session.get('role') != 'admin':
        return jsonify({'error':'not authenticated'}), 401
    eid = request.form.get('id') or (request.json.get('id') if request.is_json else None)
    if not eid:
        return jsonify({'error':'missing id'}), 400
    cur = mysql.connection.cursor()
    # fetch cost to restore budget; admins can delete any expense
    if session.get('role') == 'admin':
        cur.execute("SELECT cost, user_id FROM expenses WHERE id=%s", (eid,))
    else:
        cur.execute("SELECT cost FROM expenses WHERE id=%s AND user_id=%s", (eid, session['user_id']))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'expense not found'}), 404
    if session.get('role') == 'admin':
        cost = float(row[0] or 0)
        owner = row[1]
        cur.execute("DELETE FROM expenses WHERE id=%s", (eid,))
    else:
        cost = float(row[0] or 0)
        owner = session['user_id']
        cur.execute("DELETE FROM expenses WHERE id=%s AND user_id=%s", (eid, session['user_id']))
    mysql.connection.commit()
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if cur.fetchone():
        cur.execute("UPDATE users SET budget = budget + %s WHERE id=%s", (cost, owner))
        mysql.connection.commit()
    cur.execute("SELECT SUM(cost) FROM expenses WHERE user_id=%s", (session['user_id'],))
    total_exp = cur.fetchone()[0] or 0
    rem = None
    cur.execute("SHOW COLUMNS FROM users LIKE 'budget'")
    if cur.fetchone():
        cur.execute("SELECT budget FROM users WHERE id=%s", (session['user_id'],))
        r = cur.fetchone()
        rem = float(r[0] or 0) if r else None
    return jsonify({'deleted': eid, 'total_expense': total_exp, 'remaining_budget': rem, 'message':'Expense deleted'})

if __name__ == '__main__':
    app.run(debug=True)