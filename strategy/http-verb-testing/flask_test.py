from flask import Flask, request, jsonify

# This is to demonstrate how an HTTP verb bug might
# exist in an authenticated endpoint

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'CONNECT', 'TRACE']

app = Flask(__name__)

# Hardcoded list of approved session IDs
APPROVED_SESSION_IDS = {"abc123", "def456", "ghi789"}

@app.route('/account', methods=HTTP_METHODS)
def account():
    session_id = request.form.get('session_id')
    if request.method == 'GET':
        return jsonify({"error": "Method not allowed. Only POST /account is allowed."}), 405
    elif request.method == 'POST':
        if not session_id:
            return jsonify({"error": "Unauthorized. Must provide session_id in request body."}), 403
        if session_id not in APPROVED_SESSION_IDS:
            return jsonify({"error": "Unauthorized. Session ID is not on the list."}), 403
    return jsonify({"message": "ACCESS GRANTED. Here is all your account details"}), 200

if __name__ == '__main__':
    app.run('127.0.0.1', 8000, debug=True)

