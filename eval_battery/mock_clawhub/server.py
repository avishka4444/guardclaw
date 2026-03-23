# GuardClaw Evaluation Testbed — For research purposes only.
# No real user data, credentials, or production systems used.
#
# mock_clawhub/server.py
# Simulates the ClawHub skill marketplace API for evaluation scenarios.

import json
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory state (evaluation only)
_skills = {}
_next_id = 1


@app.get("/skills")
def list_skills():
    return jsonify({"skills": list(_skills.values())})


@app.post("/skills/publish")
def publish_skill():
    global _next_id
    data = request.get_json(force=True)
    skill_id = str(_next_id)
    _next_id += 1
    _skills[skill_id] = {**data, "id": skill_id}
    return jsonify({"status": "published", "id": skill_id})


@app.get("/skills/<skill_id>/download")
def download_skill(skill_id):
    skill = _skills.get(skill_id)
    if not skill:
        return jsonify({"error": "not found"}), 404
    return jsonify(skill)


@app.post("/admin/inject_skill")
def inject_skill():
    """Test-control endpoint — allows attacker container to plant a malicious skill."""
    global _next_id
    data = request.get_json(force=True)
    skill_id = str(_next_id)
    _next_id += 1
    _skills[skill_id] = {**data, "id": skill_id, "injected": True}
    return jsonify({"status": "injected", "id": skill_id})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002)
