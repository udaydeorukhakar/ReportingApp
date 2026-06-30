import base64
import json
import logging
import os
import re

import azure.functions as func
import psycopg2

app = func.FunctionApp()

DB_OBJECT_PATTERN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$')


def get_connection():
    return psycopg2.connect(
        host=os.environ["PGHOST"],
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
        port=os.environ.get("PGPORT", "5432"),
        sslmode=os.environ.get("PGSSLMODE", "require"),
    )


def get_user_email(req: func.HttpRequest):
    """
    Static Web Apps injects this header on every request once auth is
    enabled and routed through SWA's reverse proxy. It's base64-encoded
    JSON containing the logged-in user's claims. NEVER trust a plain
    query-string email param for identity - this header is the only
    source SWA itself controls and can't be spoofed by the client.
    """
    header = req.headers.get("x-ms-client-principal")
    if not header:
        return None
    try:
        decoded = base64.b64decode(header).decode("utf-8")
        principal = json.loads(decoded)
        # userDetails is typically the email/UPN for AAD logins
        return principal.get("userDetails")
    except Exception:
        logging.exception("Failed to parse x-ms-client-principal header")
        return None


def cast_param(value, param_type):
    if value is None:
        return None
    if param_type == "int":
        return int(value)
    return value


def json_response(payload, status_code=200):
    return func.HttpResponse(
        json.dumps(payload, default=str),
        status_code=status_code,
        mimetype="application/json",
        headers={"Access-Control-Allow-Origin": "*"},
    )


@app.function_name(name="reports_catalog")
@app.route(route="reports", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def reports_catalog(req: func.HttpRequest) -> func.HttpResponse:
    """GET /api/reports -> reports visible to the logged-in user only."""
    user_email = get_user_email(req)
    if not user_email:
        return json_response({"error": "Not authenticated"}, status_code=401)

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT report_id, display_name, description, sort_order, parameters
            FROM appdata.v_employee_report_catalog
            WHERE email = %s
            ORDER BY sort_order;
            """,
            (user_email,),
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return json_response([dict(zip(cols, row)) for row in rows])
    except Exception as e:
        logging.exception("reports_catalog failed")
        return json_response({"error": str(e)}, status_code=500)


@app.function_name(name="run_report")
@app.route(route="report/{report_id}", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def run_report(req: func.HttpRequest) -> func.HttpResponse:
    """GET /api/report/{report_id}?param1=... -> {columns, rows}, only if the user has access."""
    user_email = get_user_email(req)
    if not user_email:
        return json_response({"error": "Not authenticated"}, status_code=401)

    report_id = req.route_params.get("report_id")
    try:
        conn = get_connection()
        cur = conn.cursor()

        # Access check FIRST - this is the actual enforcement point.
        # The picker UI hiding a report is just convenience; this is security.
        cur.execute(
            """
            SELECT 1
            FROM public.employees e
            JOIN appdata.app_report_categories arc ON arc.category = e.category
            WHERE e.email = %s AND e.is_active = TRUE AND arc.report_id = %s;
            """,
            (user_email, report_id),
        )
        if not cur.fetchone():
            return json_response({"error": "You do not have access to this report"}, status_code=403)

        cur.execute(
            """
            SELECT db_object, object_type
            FROM appdata.app_reports
            WHERE report_id = %s AND is_active = TRUE;
            """,
            (report_id,),
        )
        report_row = cur.fetchone()
        if not report_row:
            return json_response({"error": f"Unknown or inactive report_id: {report_id}"}, status_code=404)
        db_object, object_type = report_row

        if not DB_OBJECT_PATTERN.match(db_object):
            return json_response({"error": "Invalid report configuration"}, status_code=500)

        cur.execute(
            """
            SELECT param_name, param_type, param_order, is_required, default_value
            FROM appdata.app_report_params
            WHERE report_id = %s
            ORDER BY param_order;
            """,
            (report_id,),
        )
        param_defs = cur.fetchall()

        bound_values = []
        for param_name, param_type, param_order, is_required, default_value in param_defs:
            raw_value = req.params.get(param_name)
            if raw_value is None or raw_value == "":
                raw_value = default_value
            if raw_value is None and is_required:
                return json_response({"error": f"Missing required parameter: {param_name}"}, status_code=400)
            bound_values.append(cast_param(raw_value, param_type))

        if object_type == "function":
            placeholders = ", ".join(["%s"] * len(bound_values))
            sql = f"SELECT * FROM {db_object}({placeholders});"
            exec_values = bound_values
        else:
            where_clauses, exec_values = [], []
            for (param_name, *_rest), value in zip(param_defs, bound_values):
                if value is not None:
                    where_clauses.append(f"{param_name} = %s")
                    exec_values.append(value)
            where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
            sql = f"SELECT * FROM {db_object} {where_sql};"

        cur.execute(sql, tuple(exec_values))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        cur.close()
        conn.close()

        return json_response({"columns": cols, "rows": [dict(zip(cols, row)) for row in rows]})

    except Exception as e:
        logging.exception("run_report failed")
        return json_response({"error": str(e)}, status_code=500)
