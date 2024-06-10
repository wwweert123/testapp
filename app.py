#!/usr/bin/env python3

import datetime
import flask
import hmac
import json
import os
import pprint
import subprocess
import sys
import requests
from flask import Flask
from github import Github


DEBUG = False  # True
SHA1 = 'sha1'

def verify_request(request):
    """
    Verify request by checking webhook secret in request header.
    Webhook secret must also be available in $GITHUB_APP_SECRET_TOKEN environment variable.
    """
    # see https://docs.github.com/en/developers/webhooks-and-events/securing-your-webhooks

    webhook_secret_from_env = os.getenv('GITHUB_APP_SECRET_TOKEN')
    if webhook_secret_from_env is None:
        error("Webhook secret is not available via $GITHUB_APP_SECRET_TOKEN!")

    header_signature = request.headers.get('X-Hub-Signature')
    # if no signature is found, the request is forbidden
    if header_signature is None:
        log("Missing signature in request header => 403")
        flask.abort(403)
    else:
        signature_type, signature = header_signature.split('=')
        if signature_type == SHA1:
            # see https://docs.python.org/3/library/hmac.html
            mac = hmac.new(webhook_secret_from_env.encode(), msg=request.data, digestmod=SHA1)
            if hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                log("Request verified: signature OK!")
            else:
                log("Faulty signature in request header => 403")
                flask.abort(403)
        else:
            # we only know how to verify a SHA1 signature
            log("Uknown type of signature (%s) => 501" % signature_type)
            flask.abort(501)


def handle_pr_event(gh, request):
    """
    Dummy handler for pull request events
    """
    # Log the event details
    log("Handling pull request event")
    log("Request headers: %s" % pprint.pformat(request.headers))
    # log("Request body: %s" % pprint.pformat(request.json))
    
    # Extract some data from the request body for demonstration
    try:
        event_data = request.json
        action = event_data.get('action', 'unknown')
        pr_number = event_data.get('number', 'unknown')
        repo_full_name = request.json['repository']['full_name']
        log("Pull Request action: %s, number: %s" % (action, pr_number))

        # Add a comment to the pull request
        if action == "reopened":
            comment = "Thank you for your pull request! We will review it soon."
        elif action == "closed":
            comment = ":("
        else:
            comment = "Unrecognized action"

        add_comment_to_pr(gh, repo_full_name, pr_number, comment)
    except Exception as e:
        log("Error parsing request body: %s" % str(e))
    
    # Return a success response
    response_data = {'status': 'success', 'message': 'Pull request event handled'}
    response_object = json.dumps(response_data)
    return flask.Response(response_object, status=200, mimetype='application/json')


def add_comment_to_pr(gh, repo_full_name, pr_number, comment):
    """
    Add a comment to the pull request
    """
    gh_token = os.getenv('GITHUB_TOKEN')
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        'Authorization': f'token {gh_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    payload = {
        'body': comment
    }

    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 201:
        log("Successfully added comment to pull request")
    else:
        log(f"Failed to add comment to pull request: {response.status_code}, {response.text}")


# Dummy log function for demonstration
def log(message):
    print(message)


def handle_event(gh, request):
    """
    Handle event
    """
    event_handlers = {
        # 'check_run': handle_check_run_event,
        # 'check_suite': handle_check_suite_event,
        # 'ping': handle_ping_event,
        'pull_request': handle_pr_event,
        # 'workflow_run': handle_workflow_run_event,
    }
    event_type = request.headers["X-GitHub-Event"]

    event_handler = event_handlers.get(event_type)
    if event_handler:
        log("Event type: %s" % event_type)
        # log("Request headers: %s" % pprint.pformat(request.headers))
        # log("Request body: %s" % pprint.pformat(request.json))
        event_handler(gh, request)
    else:
        log("Unsupported event type: %s" % event_type)
        response_data = {'Unsupported event type': event_type}
        response_object = json.dumps(response_data, default=lambda obj: obj.__dict__)
        return flask.Response(response_object, status=400, mimetype='application/json')


def create_app(gh):
    """
    Create Flask app.
    """

    app = Flask(__name__)

    @app.route('/', methods=['POST'])
    def main():
        log("%s request received!" % flask.request.method)
        verify_request(flask.request)
        handle_event(gh, flask.request)
        return ''

    return app


def main():
    """Main function."""

    gh = Github(os.getenv('GITHUB_TOKEN'))
    return create_app(gh)


if __name__ == '__main__':
    app = main()
    app.run()