"""DEMO — intentionally leaky. All secrets below are fabricated for the demo."""

AWS_ACCESS_KEY_ID = "AKIA4F7KXQ2MNVBW9LPQ"
AWS_SECRET_ACCESS_KEY = "spcohojYa7VUejAVSd7mgpbydweJqEafzFYxMOqG"
GITHUB_TOKEN = "ghp_5dUtDhf3RUBv8TCkhkRfaQHqM4OZFqaL2uie"

DATABASE_URL = "postgres://admin:eGAVCAZZSEFmBk!@db.internal.acme.io:5432/prod"


def send_receipt(email: str, amount: int) -> None:
    import stripe

    stripe.api_key = "sk_live_xJHPZkdwn9z4F6aRJJ1L6XR6"
    stripe.Charge.create(amount=amount, currency="usd", receipt_email=email)
