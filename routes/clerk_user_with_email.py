from flask import Blueprint, jsonify
from clerk_backend_api import Clerk
import os

clerk_users_with_email_bp = Blueprint("clerk_users_with_email_bp", __name__)

def get_clerk_client() -> Clerk:
    """
    Create and return a Clerk client using the secret key
    loaded from environment (.env).
    """
    secret_key = os.getenv("CLERK_SECRET_KEY")
    if not secret_key:
        raise RuntimeError("CLERK_SECRET_KEY environment variable is not set")
    return Clerk(bearer_auth=secret_key)


@clerk_users_with_email_bp.route("/backend/api/user-info", methods=["GET"])
def list_clerk_users():
    """
    Return all Clerk users (as a list) with their metadata.
    """
    try:
        with get_clerk_client() as clerk:
            # This returns a Python list of user objects
            users = clerk.users.list()

            # Safely convert each user to a plain dict
            serialized_users = []
            for u in users:
                if hasattr(u, "to_dict"):
                    serialized_users.append(u.to_dict())
                elif isinstance(u, dict):
                    serialized_users.append(u)
                else:
                    # Fallback: convert to string (shouldn't normally be needed)
                    serialized_users.append({"raw": str(u)})

            return jsonify({
                "total": len(serialized_users),
                "users": serialized_users,
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@clerk_users_with_email_bp.route("/api/user-email/<path:email>", methods=["GET"])
def get_user_by_email(email: str):
    """
    Return a single Clerk user whose email matches the :email in the URL.
    Example: GET /api/user-email/ballaraja77@gmail.com
    """
    try:
        with get_clerk_client() as clerk:
            users = clerk.users.list()

            found_user = None

            for u in users:
                # u.email_addresses is a list of EmailAddress objects
                for ea in getattr(u, "email_addresses", []):
                    if getattr(ea, "email_address", None) == email:
                        found_user = u
                        break
                if found_user:
                    break

            if not found_user:
                return jsonify({
                    "error": "User not found",
                    "email": email,
                }), 404

            # Serialize the found user
            if hasattr(found_user, "to_dict"):
                data = found_user.to_dict()
            elif isinstance(found_user, dict):
                data = found_user
            else:
                data = {"raw": str(found_user)}

            return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
