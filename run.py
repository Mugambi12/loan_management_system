# Import necessary modules and classes

# Run.py
from datetime import datetime, timezone
from flask_apscheduler import APScheduler
from app import db, create_app
from app.models import Loan


app = create_app()
schedule = APScheduler(app=app)

def process_loans():
    with app.app_context():
        try:
            all_loans = Loan.query.all()

            for loan in all_loans:
                loan.repayment = loan.principal * (1 + (loan.interest_rate / 100))
                loan.profit = loan.principal * (loan.interest_rate / 100) + loan.fines

                if loan.partial_payment > 0:
                    loan.partial_balance = loan.repayment + loan.fines - loan.partial_payment

            db.session.commit()

        except Exception as e:
            print(f"An error occurred while processing loans: {e}")

def process_fines():
    with app.app_context():
        try:
            all_loans = Loan.query.all()
            current_time = datetime.now(timezone.utc)

            for loan in all_loans:
                if current_time > loan.payment_timestamp.replace(tzinfo=timezone.utc):
                    if loan.loan_status == 'fully issued':
                        loan.fines += loan.principal * (loan.interest_rate / 100)
                    elif loan.loan_status == 'partially paid':
                        loan.fines += loan.partial_balance * (loan.interest_rate / 100)

            db.session.commit()

        except Exception as e:
            print(f"An error occurred while processing fines: {e}")

schedule.add_job(id='process_loans', func=process_loans, trigger='interval', seconds=1)
schedule.add_job(id='process_fines', func=process_fines, trigger='interval', hours=1)


if __name__ == '__main__':
    schedule.start()
    app.run(debug=True, host='0.0.0.0')
