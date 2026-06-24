# ExpensesTs

ExpensesTs is a **Flask-based Expense Tracking Web Application** developed as a **BCA 4th Semester project by Umesh Phuyal**. The system helps users manage their personal finances by allowing them to record daily expenses, organize spending into categories, track budgets, and generate financial reports through a simple and user-friendly interface.

## Project Description

This project is designed to make personal expense management easier and more organized. Users can create accounts, log in securely, add their daily expenses, select categories such as food, transportation, shopping, education, and utilities, and monitor their overall spending.

The application provides a dashboard for financial insights and includes an admin panel that allows administrators to manage users and monitor system activities.

## Features

* User Registration and Login System
* Secure Session-Based Authentication
* Role-Based Access Control (User/Admin)
* Add, Update, and Manage Expenses
* Expense Categorization
* Smart Expense Classification Using Keywords
* Salary and Budget Tracking
* Dashboard with Expense Overview
* Remaining Budget Monitoring
* Admin Dashboard for User Management
* PDF Expense Report Generation
* Responsive User Interface

## Technologies Used

* Python
* Flask Framework
* MySQL Database
* HTML5
* CSS3
* JavaScript
* Jinja2 Templates
* WeasyPrint (PDF Report Generation)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd ExpensesTs
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure the MySQL database settings and ensure the database server is running.

5. Run the application:

```bash
python app.py
```

6. Open your browser:

```bash
http://127.0.0.1:5000/
```

## Usage

* Register a new account or log in.
* Add and manage daily expenses.
* Categorize expenses.
* Track salary, spending, and remaining budget.
* Generate expense reports.
* Admin users can manage users through the admin dashboard.

## Project Structure

```text
ExpensesTs/
│
├── app.py
├── templates/
├── static/
├── database/
├── requirements.txt
└── README.md
```

## Purpose

This project demonstrates practical implementation of:

* Flask Web Development
* Database Management
* Authentication System
* CRUD Operations
* Expense Management
* PDF Report Generation
* Full-Stack Web Application Development

## Developer

**Created by: Umesh Phuyal**

## Note

This project is developed for academic learning and demonstration purposes as part of the **BCA 4th Semester project**.
