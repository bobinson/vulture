import argparse

from app.mail import send_report_email


def main():
    args = argparse.ArgumentParser().parse_args()
    send_report_email(to=args.email)
