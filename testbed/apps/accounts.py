"""Accounts: a customer's own accounts and balances. Requires an access token with scope accounts:read."""
import bank

ROLE = "accounts"


class Accounts(bank.Handler):
    routes = {("GET", "/api/accounts"): "list"}

    def list(self):
        ok, claims, code = bank.verify_access_token(self.headers.get("Authorization", ""),
                                                    bank.state(ROLE)["jwt_accept"], "accounts:read")
        if not ok:
            return self.reply(code, {"error": claims})
        with bank.db() as conn:
            rows = conn.execute("SELECT id, balance, currency FROM accounts WHERE customer_id=%s ORDER BY id",
                                (claims["sub"],)).fetchall()
        self.reply(200, {"customer": claims["sub"],
                         "accounts": [{"id": r[0], "balance": r[1], "currency": r[2]} for r in rows]})


if __name__ == "__main__":
    bank.serve(Accounts)
