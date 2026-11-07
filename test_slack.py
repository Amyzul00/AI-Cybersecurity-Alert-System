import requests


def test_slack_webhook():
  webhook_url = (
      "https://hooks.slack.com/services/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"
  )

  payload = {
      "text": (
          "🚨 *Test Security Alert*: Verifying Slack webhook integration"
          " successfully!"
      )
  }

  try:
    response = requests.post(webhook_url, json=payload)
    response.raise_for_status()
    print("Webhook message sent successfully!")
  except requests.exceptions.RequestException as e:
    print(f"Failed to send webhook alert: {e}")


if __name__ == "__main__":
  test_slack_webhook()